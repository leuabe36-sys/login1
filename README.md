# Login page with Cloudflare D1

A login/signup page backed by a Cloudflare Worker and a D1 (SQLite) database.
Passwords are salted and hashed with PBKDF2 before being stored — never in plain text.

## Project layout

```
login-page/
├── public/index.html   # front end (sign in / create account)
├── src/worker.js        # API: /api/signup, /api/login
├── schema.sql            # users table
├── wrangler.toml          # Cloudflare config
└── README.md
```

## 1. Push to GitHub

```bash
cd login-page
git init
git add .
git commit -m "Login page with D1-backed auth"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
git push -u origin main
```

## 2. Deploy to Cloudflare

You'll need Node.js and the Wrangler CLI:

```bash
npm install -g wrangler
wrangler login
```

Create the D1 database:

```bash
wrangler d1 create login_page_db
```

This prints a `database_id` — copy it into `wrangler.toml`, replacing
`REPLACE_WITH_YOUR_DATABASE_ID`.

Create the `users` table:

```bash
wrangler d1 execute login_page_db --file=./schema.sql --remote
```

Deploy the Worker (this also publishes the `public/` front end as static assets):

```bash
wrangler deploy
```

Wrangler will print your live URL, something like
`https://login-page.YOUR-SUBDOMAIN.workers.dev`.

## Notes

- To connect this to GitHub for auto-deploys on push, go to the Cloudflare
  dashboard → Workers & Pages → your project → Settings → Builds, and link
  the GitHub repo.
- `schema.sql` drops and recreates the `users` table — don't re-run it against
  a database you care about without removing the `DROP TABLE` line first.
- This is a minimal auth setup (no sessions/cookies yet) — good for a demo,
  but for production you'd want to add session tokens or a proper auth
  provider on top.
