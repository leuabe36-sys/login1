# Login page with Cloudflare D1

A login/signup page backed by a Cloudflare Worker and a D1 (SQLite) database.
Passwords are salted and hashed with PBKDF2 before being stored — never in plain text.

## Project layout

```
login-page/
├── public/index.html   # front end (sign in / create account / verify email)
├── src/worker.js        # API: /api/signup, /api/login, /api/verify-email, /api/resend-code, /api/me, /api/logout
├── schema.sql            # users, sessions, login_attempts, verification_codes tables
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

## 2. Set up email sending (Resend, free tier)

Signups now require verifying a 6-digit code sent by email before the account can log in.

1. Create a free account at https://resend.com (no credit card needed, 3,000 emails/month free).
2. Get an API key from the Resend dashboard.
3. For **testing**, you can send from `onboarding@resend.dev` without any domain setup — but Resend
   will only deliver those to the email address you signed up with.
4. For **real users**, add and verify your own domain in Resend (Domains → Add Domain, then add the
   DNS records they give you), then send from an address on that domain, e.g. `noreply@yourdomain.com`.
5. Set the two Worker secrets/vars (see step 3 below for the `wrangler secret` commands):
   - `RESEND_API_KEY` — your Resend API key (secret)
   - `EMAIL_FROM` — the from-address, e.g. `onboarding@resend.dev` while testing, or `noreply@yourdomain.com` once your domain is verified

## 3. Deploy to Cloudflare

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

Create the tables:

```bash
wrangler d1 execute login_page_db --file=./schema.sql --remote
```

Set the email secrets:

```bash
wrangler secret put RESEND_API_KEY
# paste your Resend API key when prompted

wrangler secret put EMAIL_FROM
# e.g. onboarding@resend.dev, or noreply@yourdomain.com
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
- `schema.sql` drops and recreates all tables — don't re-run it against a
  database you care about without removing the `DROP TABLE` lines first.
- Verification codes are 6 digits, expire after 15 minutes, and are hashed
  (SHA-256) before being stored — the plaintext code only ever exists in the
  email itself.
- Unverified accounts can't log in. Signing up sends a code; entering it
  correctly verifies the account and signs the user in.
- Resending a code is rate-limited to 3 requests per 15 minutes per email.
