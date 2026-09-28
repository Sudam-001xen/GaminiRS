# Railway deployment

## Deploy

1. Create a Railway project and deploy this repository or ZIP contents.
2. Railway will use `railway.toml` and run `npm start`.
3. Add a Railway Volume mounted at `/data`.
4. Add the environment variable `DATA_DIR=/data`.
5. DB/5 uses a fixed UTC+5:30 school clock, so no Railway timezone setting is required.
6. Set the following variables before the first start:

```text
ADMIN_PASSWORD=Admin2026@
SESSION_SECRET=<long random value>
ENCRYPTION_KEY=<long random value>
DB1_PASSWORD=<strong database 1 password>
DB2_PASSWORD=<strong database 2 password>
DB3_PASSWORD=<strong database 3 password>
DB4_PASSWORD=<strong database 4 password>
DB5_PASSWORD=<strong database 5 password>
DB6_PASSWORD=<strong database 6 password>
```

7. Generate a public Railway domain and open `/`.
8. The protected database pages are `/DB/1` through `/DB/6`.

**Important:** The volume is required because the application uses SQLite. Without it, student records, staff IDs, audit logs, and changed DB passwords can be lost when Railway redeploys or restarts the service.
