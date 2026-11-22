# Setup (one time)

1. Cloudflare dashboard > Storage & Databases > D1 > Create database, name it `login-log`.
2. Open that database > Console tab > paste everything from `schema.sql` > Run.
3. Copy the database ID into `wrangler.jsonc` (`database_id`).
4. In `wrangler.jsonc`, set `name` to your existing Worker name, `GOOGLE_CLIENT_ID`, and `OWNER_EMAIL` (your Gmail).
5. Dashboard > your Worker > Settings > Variables and Secrets > Add a **Secret** named `SESSION_SECRET` with a long random text (40+ characters).
6. Google Cloud Console > your OAuth client > Authorised JavaScript origins > add your site address, e.g. https://yourname.jv7.workers.dev
7. Replace your GitHub repo files with this folder's contents (index.html now lives in `public/`). Cloudflare redeploys automatically.

Approve people: open https://yoursite/admin while signed in as the owner.
