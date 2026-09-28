require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'school.sqlite');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
  CREATE TABLE IF NOT EXISTS student_information (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    gender TEXT NOT NULL CHECK (gender IN ('Male','Female','Other')),
    guardian_name TEXT NOT NULL,
    guardian_phone TEXT NOT NULL,
    address TEXT NOT NULL,
    emergency_contact TEXT NOT NULL,
    notes TEXT DEFAULT '',
    house TEXT NOT NULL DEFAULT '',
    class_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','transferred','left')),
    date_added TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_students_class ON student_information(class_name, status);

  CREATE TABLE IF NOT EXISTS daily_registration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_date TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    class_name TEXT NOT NULL,
    teacher_id TEXT NOT NULL,
    total_students INTEGER NOT NULL,
    present INTEGER NOT NULL,
    absent INTEGER NOT NULL,
    male_present INTEGER NOT NULL,
    female_present INTEGER NOT NULL,
    male_absent INTEGER NOT NULL,
    female_absent INTEGER NOT NULL,
    absent_students_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(registration_date, class_name)
  );
  CREATE INDEX IF NOT EXISTS idx_registration_date ON daily_registration(registration_date);

  CREATE TABLE IF NOT EXISTS staff_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    assigned_class TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login TEXT
  );
  CREATE TABLE IF NOT EXISTS staff_registration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_date TEXT NOT NULL,
    staff_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Teacher','Assistant principal','Vice principal','Principal','Non academic staff')),
    reported_time TEXT NOT NULL,
    departure_time TEXT,
    registered_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_staff_registration_date ON staff_registration(registration_date);
  CREATE INDEX IF NOT EXISTS idx_staff_registration_staff ON staff_registration(staff_id, registration_date);

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    record_ref TEXT,
    class_name TEXT,
    details TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS system_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const studentColumns = db.prepare('PRAGMA table_info(student_information)').all();
if (!studentColumns.some(column => column.name === 'house')) db.exec("ALTER TABLE student_information ADD COLUMN house TEXT NOT NULL DEFAULT ''");
db.prepare("UPDATE student_information SET house = CASE house WHEN 'Yellow' THEN 'ගැමුණු' WHEN 'Blue' THEN 'පැරකුම්' WHEN 'Red' THEN 'මහසෙන්' ELSE house END WHERE house IN ('Blue','Yellow','Red')").run();

const GRADES = {
  6: ['A', 'B', 'C'], 7: ['A', 'B', 'C'], 8: ['A', 'B', 'C'],
  9: ['A', 'B', 'C'], 10: ['A', 'B', 'C'], 11: ['A', 'B', 'C'],
  12: ['A', 'C', 'T', 'S'], 13: ['A', 'C', 'T', 'S']
};
const CLASSES = Object.entries(GRADES).flatMap(([grade, sections]) => sections.map(section => `${grade}${section}`));
const ADMIN_ROLES = ['Principal', 'Vice Principal', 'Assistant Principal', 'administrator'];
const TEACHER_ROLES = ['Class Teacher', 'Assistant Class Teacher'];
const DEFAULT_DB_PASSWORDS = {
  1: process.env.DB1_PASSWORD || 'DB1@123',
  2: process.env.DB2_PASSWORD || 'DB2@123',
  3: process.env.DB3_PASSWORD || 'DB3@123',
  4: process.env.DB4_PASSWORD || 'DB4@123',
  5: process.env.DB5_PASSWORD || 'DB5@123',
  6: process.env.DB6_PASSWORD || 'DB6@123'
};
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin2026@';
const ADMINISTRATOR_ROLE = 'administrator';
const HOUSE_OPTIONS = ['ගැමුණු', 'පැරකුම්', 'මහසෙන්'];
const SENSITIVE_STUDENT_FIELDS = ['guardian_name', 'guardian_phone', 'address', 'emergency_contact', 'notes'];
const sessions = new Map();
const dbAccessSessions = new Map();
const COOKIE_MAX_AGE = 8 * 60 * 60 * 1000;
const nowIso = () => new Date().toISOString();
const SCHOOL_TIME_OFFSET_MS = (5 * 60 + 30) * 60 * 1000;
const schoolClock = (date = new Date()) => new Date(date.getTime() + SCHOOL_TIME_OFFSET_MS);
const schoolDateKey = (date = new Date()) => { const clock = schoolClock(date); const pad = value => String(value).padStart(2, '0'); return `${clock.getUTCFullYear()}-${pad(clock.getUTCMonth() + 1)}-${pad(clock.getUTCDate())}`; };
const schoolTimeKey = (date = new Date()) => { const clock = schoolClock(date); return `${String(clock.getUTCHours()).padStart(2, '0')}:${String(clock.getUTCMinutes()).padStart(2, '0')}`; };
const todayKey = () => schoolDateKey();
const localDateKey = schoolDateKey;
const localTimeKey = schoolTimeKey;
const CURRENT_SCHOOL_YEAR = Number(process.env.SCHOOL_YEAR || new Date().getFullYear());
const SESSION_SECRET = process.env.SESSION_SECRET || 'development-session-secret-change-before-deployment';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || 'development-encryption-key-change-before-deployment').digest();

for (const number of Object.keys(DEFAULT_DB_PASSWORDS)) {
  const key = `db_password_${number}`;
  if (!db.prepare('SELECT 1 FROM system_metadata WHERE key = ?').get(key)) {
    db.prepare('INSERT INTO system_metadata (key,value) VALUES (?,?)').run(key, bcrypt.hashSync(DEFAULT_DB_PASSWORDS[number], 12));
  }
}

function databasePasswordMatches(number, password) {
  const row = db.prepare('SELECT value FROM system_metadata WHERE key = ?').get(`db_password_${number}`);
  return Boolean(row && bcrypt.compareSync(String(password || ''), row.value));
}

function normalizeClass(value) {
  if (!value) return '';
  const clean = String(value).trim().toUpperCase().replace(/^GRADE\s*/i, '').replace(/[\s_-]+/g, '');
  const match = clean.match(/^(\d{1,2})([ABCST])$/);
  if (!match) return '';
  const grade = Number(match[1]);
  const section = match[2];
  if (grade < 6 || grade > 13) return '';
  if (grade >= 6 && grade <= 11 && !['A', 'B', 'C'].includes(section)) return '';
  if ((grade === 12 || grade === 13) && !['A', 'C', 'T', 'S'].includes(section)) return '';
  return `${grade}${section}`;
}

function classFromParts(grade, section) {
  return normalizeClass(`${grade}${section}`);
}

function isValidClass(className) {
  return CLASSES.includes(normalizeClass(className));
}

function buildTeacherUserId(role, className, year = CURRENT_SCHOOL_YEAR) {
  const normalizedClass = normalizeClass(className);
  if (!normalizedClass) return null;
  const prefix = role === 'Assistant Class Teacher' ? 'ACT' : 'CT';
  return `${prefix}-${normalizedClass}-${year}`;
}

function cleanText(value, max = 200) {
  return String(value ?? '').trim().slice(0, max);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return Object.fromEntries(header.split(';').filter(Boolean).map(item => {
    const index = item.indexOf('=');
    return [item.slice(0, index).trim(), decodeURIComponent(item.slice(index + 1).trim())];
  }));
}

function setCookie(res, name, value, maxAge = COOKIE_MAX_AGE) {
  res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; Max-Age=${Math.floor(maxAge / 1000)}; Path=/; HttpOnly; SameSite=Lax`);
}

function clearCookie(res, name) {
  res.append('Set-Cookie', `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
}

function safeUser(user) {
  if (!user) return null;
  return { id: user.user_id, name: user.name, role: user.role, assignedClass: user.assigned_class || null, active: Boolean(user.active) };
}

function issueSession(user) {
  const nonce = crypto.randomBytes(32).toString('hex');
  const token = crypto.createHmac('sha256', SESSION_SECRET).update(nonce).digest('hex');
  sessions.set(token, { userId: user.user_id, createdAt: Date.now() });
  return token;
}

function getCurrentUser(req) {
  const token = parseCookies(req).school_session;
  const session = token && sessions.get(token);
  if (!session || Date.now() - session.createdAt > COOKIE_MAX_AGE) return null;
  return db.prepare('SELECT * FROM staff_users WHERE user_id = ? AND active = 1').get(session.userId) || null;
}

function audit(userId, action, recordRef = '', className = '', details = '') {
  db.prepare('INSERT INTO audit_log (timestamp,user_id,action,record_ref,class_name,details) VALUES (?,?,?,?,?,?)')
    .run(nowIso(), userId || null, action, recordRef, className || null, details);
}

function publicError(res, status, message) {
  return res.status(status).json({ error: message });
}

function requireAuth(req, res, next) {
  const user = getCurrentUser(req);
  if (!user) return publicError(res, 401, 'Please log in to continue.');
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!ADMIN_ROLES.includes(req.user.role)) return publicError(res, 403, 'You do not have permission to perform this action.');
  next();
}

function ownsClass(user, className) {
  const normalized = normalizeClass(className);
  return ADMIN_ROLES.includes(user.role) || (TEACHER_ROLES.includes(user.role) && user.assigned_class === normalized);
}

function canReadClass(user, className) {
  const normalized = normalizeClass(className);
  return ADMIN_ROLES.includes(user.role) || (TEACHER_ROLES.includes(user.role) && isValidClass(normalized));
}

function ageFromDob(dob) {
  const date = new Date(`${dob}T00:00:00Z`);
  if (Number.isNaN(date.getTime()) || date > new Date()) return null;
  const today = new Date();
  let age = today.getUTCFullYear() - date.getUTCFullYear();
  const month = today.getUTCMonth() - date.getUTCMonth();
  if (month < 0 || (month === 0 && today.getUTCDate() < date.getUTCDate())) age--;
  return age >= 0 ? age : null;
}

function encryptValue(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(value ?? ''), 'utf8'), cipher.final()]);
  return `enc:v1:${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptValue(value) {
  if (!value || !String(value).startsWith('enc:v1:')) return value || '';
  try {
    const [, , ivHex, tagHex, dataHex] = String(value).split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch (error) {
    return '[protected data unavailable]';
  }
}

function protectStudentFields(values) {
  const result = { ...values };
  SENSITIVE_STUDENT_FIELDS.forEach(field => {
    if (field in result) result[field] = encryptValue(result[field]);
  });
  return result;
}

function revealStudent(student) {
  if (!student) return student;
  const result = { ...student };
  SENSITIVE_STUDENT_FIELDS.forEach(field => {
    result[field] = decryptValue(result[field]);
  });
  return result;
}

function studentView(student) {
  return { ...revealStudent(student), age: ageFromDob(student.date_of_birth) };
}

function registrationView(row) {
  if (!row) return null;
  return { ...row, absent_students: JSON.parse(row.absent_students_json || '[]') };
}

function validateStudent(body, partial = false) {
  const fields = ['student_id', 'full_name', 'date_of_birth', 'gender', 'guardian_name', 'guardian_phone', 'address', 'emergency_contact', 'class_name'];
  if (!partial && fields.some(field => !cleanText(body[field]))) return 'Please complete all required student fields.';
  if (body.gender && !['Male', 'Female', 'Other'].includes(body.gender)) return 'Please select a valid gender.';
  if (body.house && !HOUSE_OPTIONS.includes(body.house)) return 'Please select ගැමුණු, පැරකුම්, or මහසෙන් house.';
  if (body.date_of_birth && ageFromDob(body.date_of_birth) === null) return 'Please enter a valid date of birth.';
  if (body.class_name && !isValidClass(body.class_name)) return 'Please select a valid school class.';
  if (body.student_id && !/^[A-Za-z0-9-]{2,30}$/.test(cleanText(body.student_id))) return 'Student ID may contain letters, numbers, and hyphens only.';
  return null;
}

function cleanup() {
  const cutoff365 = new Date();
  cutoff365.setUTCDate(cutoff365.getUTCDate() - 365);
  const cutoff24 = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const oldStudents = db.prepare("DELETE FROM student_information WHERE status IN ('inactive','transferred','left') AND date_added < ?").run(cutoff365.toISOString());
  const oldRegistrations = db.prepare('DELETE FROM daily_registration WHERE submitted_at < ?').run(cutoff24.toISOString());
  const oldStaffRegistrations = db.prepare('DELETE FROM staff_registration WHERE created_at < ?').run(cutoff365.toISOString());

  if (oldStudents.changes) audit('SYSTEM', 'Cleanup expired student records', `${oldStudents.changes} records`, '', 'Retention policy: 365 days');
  if (oldRegistrations.changes) audit('SYSTEM', 'Cleanup expired daily registrations', `${oldRegistrations.changes} records`, '', 'Retention policy: 24 hours');
  if (oldStaffRegistrations.changes) audit('SYSTEM', 'Cleanup expired staff registration records', `${oldStaffRegistrations.changes} records`, '', 'Retention policy: 365 days');

  return { students: oldStudents.changes, registrations: oldRegistrations.changes, staffRegistrations: oldStaffRegistrations.changes };
}

function createAdminUserRecord(userId, name, role, password = DEFAULT_ADMIN_PASSWORD) {
  const rawId = cleanText(userId, 50).replace(/\s+/g, '');
  const normalizedId = rawId.toLowerCase() === 'admin' ? 'admin' : rawId.toUpperCase();
  const adminRole = role === ADMINISTRATOR_ROLE ? ADMINISTRATOR_ROLE : (ADMIN_ROLES.includes(role) ? role : 'Principal');
  if (!normalizedId || !name || (!ADMIN_ROLES.includes(adminRole) && adminRole !== ADMINISTRATOR_ROLE)) return null;

  const hash = bcrypt.hashSync(String(password || DEFAULT_ADMIN_PASSWORD), 12);
  const existing = db.prepare('SELECT * FROM staff_users WHERE user_id = ?').get(normalizedId);

  if (existing) {
    db.prepare('UPDATE staff_users SET name=?,role=?,assigned_class=?,active=?,password_hash=? WHERE user_id=?')
      .run(name, adminRole, null, 1, hash, normalizedId);
    return { user_id: normalizedId, name, role: adminRole, assigned_class: null };
  }

  db.prepare('INSERT INTO staff_users (user_id,name,role,assigned_class,active,password_hash,created_at) VALUES (?,?,?,?,1,?,?)')
    .run(normalizedId, name, adminRole, null, hash, nowIso());

  return { user_id: normalizedId, name, role: adminRole, assigned_class: null };
}

function seedIfEmpty() {
  const initialized = db.prepare("SELECT value FROM system_metadata WHERE key = 'clean_slate_v3'").get();
  if (initialized) return;

  // One-time migration: remove all sample/legacy records and establish the two requested primary accounts.
  db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM daily_registration').run();
    db.prepare('DELETE FROM student_information').run();
    db.prepare('DELETE FROM staff_users').run();
    db.prepare('DELETE FROM audit_log').run();

    createAdminUserRecord('PRI0102', 'Principal Account', 'Principal', '12345678');
    createAdminUserRecord('admin', 'Administrator Account', ADMINISTRATOR_ROLE, DEFAULT_ADMIN_PASSWORD);
    db.prepare("INSERT INTO system_metadata (key,value) VALUES ('clean_slate_v3',?)").run(nowIso());
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

seedIfEmpty();
const administratorAccount = db.prepare('SELECT * FROM staff_users WHERE role = ? ORDER BY CASE WHEN user_id = ? THEN 0 ELSE 1 END LIMIT 1').get(ADMINISTRATOR_ROLE, 'admin');
if (administratorAccount) {
  db.prepare('UPDATE staff_users SET user_id=?,name=?,password_hash=?,active=1 WHERE user_id=?').run('Admin-2026', 'Administrator Account', bcrypt.hashSync(DEFAULT_ADMIN_PASSWORD, 12), administratorAccount.user_id);
} else {
  createAdminUserRecord('Admin-2026', 'Administrator Account', ADMINISTRATOR_ROLE, DEFAULT_ADMIN_PASSWORD);
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000).unref();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(ROOT, 'public')));

app.get('/api/session', (req, res) => res.json({ user: safeUser(getCurrentUser(req)), classes: CLASSES, grades: GRADES }));
app.get('/api/overview', (req, res) => {
  const students = db.prepare("SELECT class_name, gender FROM student_information WHERE status = 'active'").all();
  const registrations = db.prepare('SELECT * FROM daily_registration WHERE registration_date = ?').all(todayKey());
  const totalStudents = students.length;
  const present = registrations.reduce((n, r) => n + Number(r.present || 0), 0);
  const registeredStudents = registrations.reduce((n, r) => n + Number(r.total_students || 0), 0);
  const attendancePercent = registeredStudents ? Math.round((present / registeredStudents) * 1000) / 10 : 0;
  res.json({ registeredClasses: registrations.length, totalClasses: CLASSES.length, present, totalStudents, registeredStudents, attendancePercent });
});

app.get('/api/classes', (req, res) => res.json({ classes: CLASSES, grades: GRADES }));

app.post('/api/login', (req, res) => {
  const id = cleanText(req.body.staffId, 50);
  const password = String(req.body.password || '');
  const currentUser = getCurrentUser(req);
  const administratorBypass = Boolean(currentUser && currentUser.role === ADMINISTRATOR_ROLE);
  const user = administratorBypass ? currentUser : db.prepare('SELECT * FROM staff_users WHERE user_id = ?').get(id);

  if (!administratorBypass && (!user || !user.active || !bcrypt.compareSync(password, user.password_hash))) {
    audit(id || 'UNKNOWN', 'Failed login', id, '', 'Invalid ID or password');
    return publicError(res, 401, 'Incorrect ID or password.');
  }

  const mode = req.body.mode || 'admin';
  if (!administratorBypass && mode === 'class') {
    const selectedClass = classFromParts(req.body.grade, req.body.section);
    if (!TEACHER_ROLES.includes(user.role)) return publicError(res, 403, 'Only class teachers and assistant class teachers can use class login.');
    if (!selectedClass || user.assigned_class !== selectedClass) return publicError(res, 403, 'This account is not assigned to this class.');
  } else if (!administratorBypass && !ADMIN_ROLES.includes(user.role)) {
    return publicError(res, 403, 'This account does not have school administration access.');
  }

  db.prepare('UPDATE staff_users SET last_login = ? WHERE user_id = ?').run(nowIso(), user.user_id);
  audit(user.user_id, 'Login', user.user_id, user.assigned_class || '', `Role: ${user.role}`);
  setCookie(res, 'school_session', issueSession(user));
  res.json({ user: safeUser(user) });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.school_session) sessions.delete(cookies.school_session);
  if (cookies.db_access) dbAccessSessions.delete(cookies.db_access);
  clearCookie(res, 'school_session');
  clearCookie(res, 'db_access');
  res.json({ ok: true });
});

app.post('/api/students', requireAuth, (req, res) => {
  const className = normalizeClass(req.body.class_name || req.user.assigned_class);
  if (!ownsClass(req.user, className)) return publicError(res, 403, 'You do not have permission to perform this action.');

  const error = validateStudent({ ...req.body, class_name: className });
  if (error) return publicError(res, 400, error);

  const studentId = cleanText(req.body.student_id, 30);
  if (db.prepare('SELECT 1 FROM student_information WHERE student_id = ?').get(studentId)) return publicError(res, 409, 'This student ID already exists.');

  const timestamp = nowIso();
  db.prepare(`INSERT INTO student_information
    (student_id,full_name,date_of_birth,gender,guardian_name,guardian_phone,address,emergency_contact,notes,house,class_name,status,date_added,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    studentId,
    cleanText(req.body.full_name),
    cleanText(req.body.date_of_birth, 10),
    req.body.gender,
    ...Object.values(protectStudentFields({
      guardian_name: cleanText(req.body.guardian_name),
      guardian_phone: cleanText(req.body.guardian_phone, 40),
      address: cleanText(req.body.address),
      emergency_contact: cleanText(req.body.emergency_contact, 100),
      notes: cleanText(req.body.notes, 500)
    })),
    cleanText(req.body.house, 80),
    className,
    'active',
    timestamp,
    timestamp
  );

  audit(req.user.user_id, 'Student created', studentId, className);
  res.status(201).json({ student: studentView(db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(studentId)) });
});

app.get('/api/students', requireAuth, (req, res) => {
  const className = normalizeClass(req.query.class || req.user.assigned_class);
  if (!className || (!ownsClass(req.user, className) && !ADMIN_ROLES.includes(req.user.role))) return publicError(res, 403, 'You do not have permission to view this class.');
  const rows = db.prepare("SELECT * FROM student_information WHERE class_name = ? AND status = 'active' ORDER BY full_name COLLATE NOCASE").all(className).map(studentView);
  res.json({ className, students: rows });
});

app.get('/api/students/:studentId', requireAuth, (req, res) => {
  const student = db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(cleanText(req.params.studentId, 30));
  if (!student || (!ownsClass(req.user, student.class_name) && !ADMIN_ROLES.includes(req.user.role))) return publicError(res, 404, 'Student record not found.');
  res.json({ student: studentView(student) });
});

app.put('/api/students/:studentId', requireAuth, (req, res) => {
  const student = db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(cleanText(req.params.studentId, 30));
  if (!student || !ownsClass(req.user, student.class_name)) return publicError(res, 403, 'You do not have permission to perform this action.');

  const merged = { ...student, ...req.body, class_name: student.class_name };
  const error = validateStudent(merged, true);
  if (error) return publicError(res, 400, error);

  const timestamp = nowIso();
  db.prepare(`UPDATE student_information SET full_name=?,date_of_birth=?,gender=?,guardian_name=?,guardian_phone=?,address=?,emergency_contact=?,notes=?,house=?,updated_at=? WHERE student_id=?`)
    .run(
      cleanText(merged.full_name),
      cleanText(merged.date_of_birth, 10),
      merged.gender,
      ...Object.values(protectStudentFields({
        guardian_name: cleanText(merged.guardian_name),
        guardian_phone: cleanText(merged.guardian_phone, 40),
        address: cleanText(merged.address),
        emergency_contact: cleanText(merged.emergency_contact, 100),
        notes: cleanText(merged.notes, 500)
      })),
      cleanText(merged.house, 80),
      timestamp,
      student.student_id
    );

  audit(req.user.user_id, 'Student edited', student.student_id, student.class_name);
  res.json({ student: studentView(db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(student.student_id)) });
});

app.delete('/api/students/:studentId', requireAuth, requireAdmin, (req, res) => {
  const studentId = cleanText(req.params.studentId, 30);
  const student = db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(studentId);
  if (!student) return publicError(res, 404, 'Student record not found.');
  db.prepare('DELETE FROM student_information WHERE student_id = ?').run(studentId);
  audit(req.user.user_id, 'Student deleted', studentId, student.class_name, 'School-wide administrator action');
  res.json({ ok: true, message: 'Student record deleted.' });
});

app.post('/api/students/:studentId/transfer', requireAuth, (req, res) => {
  const student = db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(cleanText(req.params.studentId, 30));
  if (!student || !ownsClass(req.user, student.class_name)) return publicError(res, 403, 'You do not have permission to perform this action.');

  const action = cleanText(req.body.action, 20);
  const newClass = req.body.newClass ? normalizeClass(req.body.newClass) : null;
  if (!['transfer', 'leave', 'inactive'].includes(action)) return publicError(res, 400, 'Please choose a valid student status action.');
  if (action === 'transfer' && !isValidClass(newClass)) return publicError(res, 400, 'Please select a valid destination class.');

  const status = action === 'transfer' ? 'transferred' : action === 'leave' ? 'left' : 'inactive';
  const destination = action === 'transfer' ? newClass : student.class_name;
  const timestamp = nowIso();
  db.prepare('UPDATE student_information SET class_name=?,status=?,updated_at=? WHERE student_id=?').run(destination, status, timestamp, student.student_id);
  audit(req.user.user_id, 'Student transferred', student.student_id, student.class_name, `Action=${action}; New class=${newClass || 'none'}; Reason=${cleanText(req.body.reason, 300)}`);
  res.json({ ok: true, message: action === 'transfer' ? `Student transferred to ${newClass}.` : 'Student status updated.' });
});

app.get('/api/attendance/today', requireAuth, (req, res) => {
  const className = normalizeClass(req.query.class || req.user.assigned_class);
  if (!canReadClass(req.user, className)) return publicError(res, 403, 'You do not have permission to view this class.');

  const students = db.prepare("SELECT * FROM student_information WHERE class_name = ? AND status = 'active' ORDER BY full_name COLLATE NOCASE").all(className).map(studentView);
  const registration = registrationView(db.prepare('SELECT * FROM daily_registration WHERE registration_date = ? AND class_name = ?').get(todayKey(), className));
  const readOnly = !ownsClass(req.user, className);
  res.json({ className, date: todayKey(), students, registration, readOnly });
});

app.post('/api/attendance', requireAuth, (req, res) => {
  const className = normalizeClass(req.body.class_name || req.user.assigned_class);
  if (!TEACHER_ROLES.includes(req.user.role) || !ownsClass(req.user, className)) return publicError(res, 403, 'You do not have permission to submit attendance for this class.');
  if (db.prepare('SELECT 1 FROM daily_registration WHERE registration_date = ? AND class_name = ?').get(todayKey(), className)) return publicError(res, 409, "This class has already submitted today's registration.");

  const activeStudents = db.prepare("SELECT student_id,full_name,gender FROM student_information WHERE class_name = ? AND status = 'active'").all(className);
  const statuses = Array.isArray(req.body.statuses) ? req.body.statuses : [];
  const byId = new Map(statuses.map(item => [cleanText(item.studentId, 30), item.status]));

  if (!activeStudents.length) return publicError(res, 400, 'There are no active students in this class.');
  if (activeStudents.some(student => !['present', 'absent'].includes(byId.get(student.student_id)))) return publicError(res, 400, 'Please mark every student as present or absent.');

  const absentStudents = activeStudents.filter(student => byId.get(student.student_id) === 'absent').map(student => ({ studentId: student.student_id, name: student.full_name }));
  const presentStudents = activeStudents.filter(student => byId.get(student.student_id) === 'present');
  const absent = absentStudents.length;
  const present = presentStudents.length;
  const malePresent = presentStudents.filter(s => s.gender === 'Male').length;
  const femalePresent = presentStudents.filter(s => s.gender === 'Female').length;
  const maleAbsent = absentStudents.filter(s => activeStudents.find(a => a.student_id === s.studentId)?.gender === 'Male').length;
  const femaleAbsent = absentStudents.filter(s => activeStudents.find(a => a.student_id === s.studentId)?.gender === 'Female').length;
  const total = activeStudents.length;

  if (total !== present + absent || present !== malePresent + femalePresent || absent !== maleAbsent + femaleAbsent) return publicError(res, 400, 'Attendance totals are inconsistent. Please review the entries.');

  const timestamp = nowIso();
  db.prepare(`INSERT INTO daily_registration
    (registration_date,submitted_at,class_name,teacher_id,total_students,present,absent,male_present,female_present,male_absent,female_absent,absent_students_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    todayKey(), timestamp, className, req.user.user_id, total, present, absent, malePresent, femalePresent, maleAbsent, femaleAbsent, JSON.stringify(absentStudents)
  );

  audit(req.user.user_id, 'Attendance submitted', todayKey(), className, `Present=${present}; Absent=${absent}`);
  res.status(201).json({ registration: registrationView(db.prepare('SELECT * FROM daily_registration WHERE registration_date = ? AND class_name = ?').get(todayKey(), className)) });
});

app.get('/api/attendance/history', requireAuth, (req, res) => {
  const className = normalizeClass(req.query.class || req.user.assigned_class);
  if (!canReadClass(req.user, className)) return publicError(res, 403, 'You do not have permission to view this class.');
  const rows = db.prepare('SELECT * FROM daily_registration WHERE class_name = ? ORDER BY registration_date DESC LIMIT 90').all(className).map(registrationView);
  res.json({ className, registrations: rows });
});

app.get('/api/admin/dashboard', requireAuth, requireAdmin, (req, res) => {
  const requestedDate = cleanText(req.query.date, 10);
  const selectedDate = /^\d{4}-\d{2}-\d{2}$/.test(requestedDate) ? requestedDate : todayKey();
  const students = db.prepare("SELECT * FROM student_information WHERE status = 'active'").all();
  const registrations = db.prepare('SELECT * FROM daily_registration WHERE registration_date = ?').all(selectedDate);
  const stats = {
    total: students.length,
    male: students.filter(s => s.gender === 'Male').length,
    female: students.filter(s => s.gender === 'Female').length,
    present: registrations.reduce((n, r) => n + r.present, 0),
    absent: registrations.reduce((n, r) => n + r.absent, 0),
    malePresent: registrations.reduce((n, r) => n + r.male_present, 0),
    femalePresent: registrations.reduce((n, r) => n + r.female_present, 0),
    maleAbsent: registrations.reduce((n, r) => n + r.male_absent, 0),
    femaleAbsent: registrations.reduce((n, r) => n + r.female_absent, 0)
  };
  stats.attendancePercent = stats.total ? Math.round((stats.present / stats.total) * 1000) / 10 : 0;

  const registrationMap = new Map(registrations.map(r => [r.class_name, registrationView(r)]));
  const sections = CLASSES.map(className => {
    const classStudents = students.filter(s => s.class_name === className);
    const registration = registrationMap.get(className) || null;
    return {
      className,
      grade: String(className).match(/^\d+/)?.[0] || '',
      section: className.replace(/^\d+/, ''),
      registration,
      studentCount: classStudents.length,
      attendancePercent: registration && registration.total_students ? Math.round((registration.present / registration.total_students) * 1000) / 10 : null
    };
  });

  res.json({ date: selectedDate, isToday: selectedDate === todayKey(), stats, registeredClasses: registrations.length, totalClasses: CLASSES.length, sections });
});


app.get('/api/staff-registration', requireAuth, requireAdmin, (req, res) => {
  const requestedDate = cleanText(req.query.date, 10);
  const selectedDate = /^\d{4}-\d{2}-\d{2}$/.test(requestedDate) ? requestedDate : todayKey();
  const rows = db.prepare(`
    SELECT id,registration_date,staff_id,name,role,reported_time,departure_time,registered_by,created_at,updated_at
    FROM staff_registration
    WHERE registration_date = ?
    ORDER BY reported_time, name COLLATE NOCASE
  `).all(selectedDate);
  res.json({ date: selectedDate, registrations: rows });
});

app.post('/api/staff-registration', requireAuth, requireAdmin, (req, res) => {
  const staffId = cleanText(req.body.staffId, 50);
  const name = cleanText(req.body.name, 120);
  const role = cleanText(req.body.role, 40);
  const reportedTime = cleanText(req.body.reportedTime, 5);
  const departureTime = cleanText(req.body.departureTime, 5);
  const registrationDate = cleanText(req.body.registrationDate, 10) || todayKey();
  const roles = ['Teacher','Assistant principal','Vice principal','Principal','Non academic staff'];

  if (!staffId || !name || !roles.includes(role) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(reportedTime)) {
    return publicError(res, 400, 'Please complete Staff ID, name, role, and a valid reported time.');
  }
  if (departureTime && !/^([01]\d|2[0-3]):[0-5]\d$/.test(departureTime)) {
    return publicError(res, 400, 'Please enter a valid departure time.');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(registrationDate)) {
    return publicError(res, 400, 'Please select a valid registration date.');
  }
  if (departureTime && departureTime < reportedTime) {
    return publicError(res, 400, 'Departure time cannot be earlier than the reported time.');
  }

  const timestamp = nowIso();
  const result = db.prepare(`
    INSERT INTO staff_registration
      (registration_date,staff_id,name,role,reported_time,departure_time,registered_by,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(registrationDate, staffId, name, role, reportedTime, departureTime || null, req.user.user_id, timestamp, timestamp);

  audit(req.user.user_id, 'Staff registration created', String(result.lastInsertRowid), '', `Staff ID=${staffId}; Role=${role}; Date=${registrationDate}`);
  res.status(201).json({ message: 'Staff registration saved.', id: result.lastInsertRowid });
});

app.put('/api/staff-registration/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM staff_registration WHERE id = ?').get(id);
  if (!existing) return publicError(res, 404, 'Staff registration record not found.');

  const departureTime = cleanText(req.body.departureTime, 5);
  if (departureTime && !/^([01]\d|2[0-3]):[0-5]\d$/.test(departureTime)) {
    return publicError(res, 400, 'Please enter a valid departure time.');
  }
  if (departureTime && departureTime < existing.reported_time) {
    return publicError(res, 400, 'Departure time cannot be earlier than the reported time.');
  }

  db.prepare('UPDATE staff_registration SET departure_time=?,updated_at=? WHERE id=?').run(departureTime || null, nowIso(), id);
  audit(req.user.user_id, 'Staff departure updated', String(id), '', `Departure=${departureTime || 'not recorded'}`);
  res.json({ message: 'Departure time updated.' });
});

function requireDbAccess(number) {
  return (req, res, next) => {
    const token = parseCookies(req).db_access;
    const access = token && dbAccessSessions.get(token);
    if (!access || access.number !== number || access.expiresAt < Date.now()) return publicError(res, 401, 'Database authentication is required.');
    const user = access.userId === 'REGID' && number === 5 ? { user_id: 'REGID', role: 'REGID', active: 1 } : db.prepare('SELECT * FROM staff_users WHERE user_id = ? AND active = 1').get(access.userId);
    if (!user || (number === 4 || number === 6 ? user.role !== ADMINISTRATOR_ROLE : !ADMIN_ROLES.includes(user.role) && !(number === 5 && user.role === 'REGID'))) return publicError(res, 403, 'Access Denied.');
    req.dbAccess = access;
    req.dbUser = user;
    next();
  };
}

app.post('/api/db/:number/unlock', (req, res) => {
  const number = Number(req.params.number);
  if (![1, 2, 3, 4, 5, 6].includes(number)) return publicError(res, 404, 'Database not found.');

  let user;
  const requestedId = cleanText(req.body.staffId, 50);
  const regidBypass = number === 5 && requestedId.toUpperCase() === 'REGID';
  if (regidBypass) {
    user = { user_id: 'REGID', role: 'REGID' };
  } else {
    const id = requestedId;
    user = db.prepare('SELECT * FROM staff_users WHERE user_id = ? AND active = 1').get(id);
    const permitted = user && user.active && ((number === 4 || number === 6) ? user.role === ADMINISTRATOR_ROLE : ADMIN_ROLES.includes(user.role));
    if (!permitted) {
      audit(id || 'UNKNOWN', 'Failed database login', `DB/${number}`, '', 'Role is not permitted');
      return publicError(res, 403, 'Access Denied.');
    }
    if (!bcrypt.compareSync(String(req.body.password || ''), user.password_hash)) {
      audit(user.user_id, 'Failed database login', `DB/${number}`, '', 'Invalid staff credentials');
      return publicError(res, 401, 'Incorrect ID or password.');
    }
  }

  const staffPasswordOnly = user && (user.role === ADMINISTRATOR_ROLE || user.role === 'Principal');
  if (!regidBypass && !staffPasswordOnly && !databasePasswordMatches(number, req.body.databasePassword)) {
    audit(user.user_id, 'Failed database login', `DB/${number}`, '', 'Invalid database password');
    return publicError(res, 401, 'Incorrect database password.');
  }

  const token = crypto.randomBytes(32).toString('hex');
  dbAccessSessions.set(token, { number, userId: user.user_id, expiresAt: Date.now() + COOKIE_MAX_AGE });
  setCookie(res, 'db_access', token);
  audit(user.user_id, 'Database login', `DB/${number}`, '', regidBypass ? 'REGID password-free access' : staffPasswordOnly ? 'Staff password accepted' : 'Database password accepted');
  res.json({ ok: true, database: number, bypass: regidBypass || Boolean(staffPasswordOnly) });
});

app.get('/api/db/6/passwords', requireDbAccess(6), (req, res) => {
  if (req.dbAccess.userId !== 'admin') return publicError(res, 403, 'Only the Administrator account can manage database passwords.');
  res.json({ databases: Object.keys(DEFAULT_DB_PASSWORDS).map(number => ({ number: Number(number), name: `Database ${number}` })) });
});

app.post('/api/db/6/passwords', requireDbAccess(6), (req, res) => {
  if (req.dbAccess.userId !== 'admin') return publicError(res, 403, 'Only the Administrator account can manage database passwords.');
  const number = Number(req.body.number);
  const password = String(req.body.password || '').trim();
  if (!Object.prototype.hasOwnProperty.call(DEFAULT_DB_PASSWORDS, number)) return publicError(res, 400, 'Select a valid database number.');
  if (password.length < 8) return publicError(res, 400, 'Database passwords must be at least 8 characters long.');
  db.prepare('INSERT INTO system_metadata (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    .run(`db_password_${number}`, bcrypt.hashSync(password, 12));
  audit(req.dbAccess.userId, 'Database password changed', `DB/${number}`);
  res.json({ message: `Database ${number} password updated.` });
});

app.get('/api/db/1/students', requireDbAccess(1), (req, res) => {
  const q = cleanText(req.query.q, 100).toLowerCase();
  const rows = db.prepare(`SELECT student_id,full_name,date_of_birth,gender,guardian_name,guardian_phone,address,emergency_contact,notes,house,class_name,status,date_added,updated_at FROM student_information ${q ? 'WHERE lower(student_id) LIKE ? OR lower(full_name) LIKE ?' : ''} ORDER BY class_name,full_name COLLATE NOCASE`).all(...(q ? [`%${q}%`, `%${q}%`] : [])).map(studentView);
  res.json({ students: rows });
});

app.delete('/api/db/1/students/:studentId', requireDbAccess(1), (req, res) => {
  const studentId = cleanText(req.params.studentId, 30);
  const student = db.prepare('SELECT * FROM student_information WHERE student_id = ?').get(studentId);
  if (!student) return publicError(res, 404, 'Student record not found.');
  db.prepare('DELETE FROM student_information WHERE student_id = ?').run(studentId);
  audit(req.dbAccess.userId, 'Student deleted', studentId, student.class_name, 'Database 1 administrator action');
  res.json({ ok: true, message: 'Student record deleted.' });
});

app.get('/api/db/2/registrations', requireDbAccess(2), (req, res) => {
  const rows = db.prepare('SELECT * FROM daily_registration ORDER BY registration_date DESC,class_name LIMIT 500').all().map(registrationView);
  res.json({ registrations: rows });
});

app.get('/api/db/4/credentials', requireDbAccess(4), (req, res) => {
  const credentials = db.prepare('SELECT user_id,name,role,assigned_class,active,created_at,last_login FROM staff_users ORDER BY user_id').all().map(user => ({ ...user, active: Boolean(user.active) }));
  res.json({ credentials });
});

app.get('/api/db/5/staff-registration', requireDbAccess(5), (req, res) => {
  const requestedDate = cleanText(req.query.date, 10);
  const selectedDate = /^\d{4}-\d{2}-\d{2}$/.test(requestedDate) ? requestedDate : localDateKey();
  const registrations = db.prepare(`
    SELECT id,registration_date,staff_id,name,role,reported_time,departure_time,registered_by,created_at,updated_at
    FROM staff_registration WHERE registration_date = ?
    ORDER BY reported_time, name COLLATE NOCASE
  `).all(selectedDate);
  res.json({ date: selectedDate, registrations });
});

app.post('/api/db/5/staff-registration', requireDbAccess(5), (req, res) => {
  const staffId = cleanText(req.body.staffId, 50);
  const name = cleanText(req.body.name, 120);
  const role = cleanText(req.body.role, 40);
  const reportedTime = localTimeKey();
  const departureTime = cleanText(req.body.departureTime, 5);
  const registrationDate = localDateKey();
  const roles = ['Teacher','Assistant principal','Vice principal','Principal','Non academic staff'];

  if (!staffId || !name || !roles.includes(role)) {
    return publicError(res, 400, 'Please complete Staff ID, name, and role.');
  }
  if (departureTime && !/^([01]\d|2[0-3]):[0-5]\d$/.test(departureTime)) {
    return publicError(res, 400, 'Please enter a valid departure time.');
  }
  if (departureTime && departureTime < reportedTime) {
    return publicError(res, 400, 'Departure time cannot be earlier than the reported time.');
  }
  const timestamp = nowIso();
  const result = db.prepare(`
    INSERT INTO staff_registration
      (registration_date,staff_id,name,role,reported_time,departure_time,registered_by,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(registrationDate, staffId, name, role, reportedTime, departureTime || null, req.dbAccess.userId, timestamp, timestamp);

  audit(req.dbAccess.userId, 'Staff registration created', String(result.lastInsertRowid), '', `Staff ID=${staffId}; Role=${role}; Date=${registrationDate}; Source=DB5`);
  res.status(201).json({ message: 'Staff registration saved.', id: result.lastInsertRowid });
});

app.get('/api/db/3/users', requireDbAccess(3), (req, res) => {
  const users = db.prepare('SELECT user_id,name,role,assigned_class,active,created_at,last_login FROM staff_users ORDER BY CASE role WHEN \'Principal\' THEN 1 WHEN \'Vice Principal\' THEN 2 WHEN \'Assistant Principal\' THEN 3 WHEN \'Class Teacher\' THEN 4 ELSE 5 END,name').all().map(user => ({ ...user, active: Boolean(user.active) }));
  res.json({ users });
});

app.post('/api/db/3/users', requireDbAccess(3), (req, res) => {
  const actingUser = db.prepare('SELECT * FROM staff_users WHERE user_id = ? AND active = 1').get(req.dbAccess.userId);
  if (!actingUser || !ADMIN_ROLES.includes(actingUser.role)) return publicError(res, 403, 'You do not have permission to perform this action.');

  const role = cleanText(req.body.role, 40);
  const assignedClass = TEACHER_ROLES.includes(role) ? normalizeClass(req.body.assignedClass) : null;
  const requestedUserId = cleanText(req.body.userId, 50);
  const userId = TEACHER_ROLES.includes(role) && !requestedUserId && assignedClass ? buildTeacherUserId(role, assignedClass, CURRENT_SCHOOL_YEAR) : requestedUserId;
  const name = cleanText(req.body.name, 120);
  const active = req.body.active === false || req.body.active === 'false' ? 0 : 1;
  const password = String(req.body.password || '');

  if (!/^[A-Za-z0-9-]{3,50}$/.test(userId) || !name || ![...ADMIN_ROLES, ...TEACHER_ROLES].includes(role)) return publicError(res, 400, 'Enter a valid ID, name, and role.');
  if (TEACHER_ROLES.includes(role) && !isValidClass(assignedClass)) return publicError(res, 400, 'Teacher accounts require a valid assigned class.');

  const existing = db.prepare('SELECT * FROM staff_users WHERE user_id = ?').get(userId);
  if (!existing && password.length < 8) return publicError(res, 400, 'New staff users need a password of at least 8 characters.');

  if (existing) {
    db.prepare('UPDATE staff_users SET name=?,role=?,assigned_class=?,active=?' + (password ? ',password_hash=?' : '') + ' WHERE user_id=?')
      .run(...(password ? [name, role, assignedClass, active, bcrypt.hashSync(password, 12), userId] : [name, role, assignedClass, active, userId]));
    audit(actingUser.user_id, 'Administrative action', userId, assignedClass || '', 'Staff user updated');
  } else {
    db.prepare('INSERT INTO staff_users (user_id,name,role,assigned_class,active,password_hash,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(userId, name, role, assignedClass, active, bcrypt.hashSync(password, 12), nowIso());
    audit(actingUser.user_id, 'Administrative action', userId, assignedClass || '', 'Staff user created');
  }

  res.json({ ok: true, message: existing ? 'Staff user updated.' : 'Staff user created.' });
});

app.post('/api/db/3/users/delete', requireDbAccess(3), (req, res) => {
  const actingUser = db.prepare('SELECT * FROM staff_users WHERE user_id = ? AND active = 1').get(req.dbAccess.userId);
  if (!actingUser || !ADMIN_ROLES.includes(actingUser.role)) return publicError(res, 403, 'Only a school administrator can delete staff accounts.');

  const userId = cleanText(req.body.userId, 50);
  if (!userId) return publicError(res, 400, 'Enter a valid staff ID to delete.');
  if (userId === actingUser.user_id) return publicError(res, 400, 'The Principal cannot delete their own account.');

  const target = db.prepare('SELECT * FROM staff_users WHERE user_id = ?').get(userId);
  if (!target) return publicError(res, 404, 'Staff user not found.');

  db.prepare('DELETE FROM staff_users WHERE user_id = ?').run(userId);
  audit(actingUser.user_id, 'Administrative action', userId, target.assigned_class || '', 'Staff user deleted');
  res.json({ ok: true, message: 'Staff user deleted.' });
});

app.get('/api/audit', requireAuth, requireAdmin, (req, res) => res.json({ audit: db.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 250').all() }));

app.get('/api/export/students.csv', requireDbAccess(1), (req, res) => {
  const rows = db.prepare('SELECT student_id,full_name,date_of_birth,gender,class_name,status,guardian_name,guardian_phone FROM student_information ORDER BY class_name,full_name').all();
  const csv = [['Student ID','Name','DOB','Gender','Class','Status','Guardian','Guardian Phone'], ...rows.map(r => [r.student_id,r.full_name,r.date_of_birth,r.gender,r.class_name,r.status,r.guardian_name,r.guardian_phone])]
    .map(row => row.map(value => `"${String(value ?? '').replaceAll('"','""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="student-information.csv"');
  res.send(csv);
});

app.get('/api/export/registrations.csv', requireDbAccess(2), (req, res) => {
  const rows = db.prepare('SELECT registration_date,class_name,teacher_id,total_students,present,absent,male_present,female_present,male_absent,female_absent,submitted_at FROM daily_registration ORDER BY registration_date DESC,class_name').all();
  const csv = [['Date','Class','Submitted by','Total','Present','Absent','Male Present','Female Present','Male Absent','Female Absent','Submitted at'], ...rows.map(r => [r.registration_date,r.class_name,r.teacher_id,r.total_students,r.present,r.absent,r.male_present,r.female_present,r.male_absent,r.female_absent,r.submitted_at])]
    .map(row => row.map(value => `"${String(value ?? '').replaceAll('"','""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="daily-registration.csv"');
  res.send(csv);
});

app.get('/DB/1', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/DB/2', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/DB/3', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/DB/4', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/DB/5', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/DB/6', (req, res) => res.sendFile(path.join(ROOT, 'public', 'db.html')));
app.get('/login', (req, res) => res.sendFile(path.join(ROOT, 'public', 'login.html')));
app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'public', 'index.html')));

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  publicError(res, 500, 'The request could not be completed.');
});

function start(port = PORT) {
  const preferredPort = Number(port) || 3000;
  const candidatePorts = Array.from(new Set([
    preferredPort,
    ...Array.from({ length: 20 }, (_, index) => preferredPort + index + 1)
  ]));

  let currentIndex = 0;

  function attemptListen() {
    const candidatePort = candidatePorts[currentIndex];
    const server = app.listen(candidatePort, () => {
      console.log('========================================');
      console.log('DIGITAL SCHOOL REGISTRATION SYSTEM');
      console.log('========================================');
      console.log(`Main UI:   http://localhost:${candidatePort}/`);
      console.log(`Database 1: http://localhost:${candidatePort}/DB/1`);
      console.log(`Database 2: http://localhost:${candidatePort}/DB/2`);
      console.log(`Database 3: http://localhost:${candidatePort}/DB/3`);
      console.log(`Database 4: http://localhost:${candidatePort}/DB/4`);
      console.log(`Database 5: http://localhost:${candidatePort}/DB/5`);
      console.log(`Database 6: http://localhost:${candidatePort}/DB/6`);
      console.log(`Classes:   ${CLASSES.length}`);
      console.log('Server:    RUNNING');
      console.log('========================================');
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        if (currentIndex < candidatePorts.length - 1) {
          console.warn(`Port ${candidatePort} is already in use. Trying ${candidatePorts[currentIndex + 1]}...`);
          currentIndex += 1;
          server.close(() => attemptListen());
          return;
        }

        console.error(`Unable to start server. Ports ${candidatePorts.join(', ')} are all in use.`);
        process.exitCode = 1;
        return;
      }

      console.error(`Server startup failed on port ${candidatePort}:`, error.message);
      process.exitCode = 1;
    });
  }

  attemptListen();
}

if (require.main === module) start();
module.exports = { app, db, CLASSES, cleanup, normalizeClass, buildTeacherUserId, start };
