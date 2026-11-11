# AgentGrow AI — Cloudflare SaaS

A multi-user Indian real-estate marketing workspace built on Cloudflare Workers and D1. It preserves the original OpenAI marketing generation workflow and adds account registration/login, per-user property storage, campaign history, usage limits and an admin console.

## Included features

- Email/password login and verified registration; signup collects full name, email and contact number, then requires a six-digit email OTP before creating the account. Password hashes use PBKDF2-SHA-256.
- Secure, HttpOnly, Secure, SameSite=Lax session cookie.
- Separate properties, transactions, campaigns and usage records per user.
- Agent transaction ledger: sale/resale/rental/lease, property type and full address, buyer/seller contacts, deal value, commission rate/earned/received, payment reference/status, transaction status, lead source, co-broker share and notes. **All financial amounts use Indian rupees (INR / ₹); no USD or foreign-exchange conversion is used.**
- Transaction totals for closed deal value and commission earned/received.
- CSV export of the agent transaction register for bookkeeping and accountant hand-off.
- OpenAI Chat Completions integration using `gpt-4o-mini` and JSON response mode.
- WhatsApp copy, Instagram/Facebook caption and Hinglish Reel script.
- No Cloudflare R2 subscription or payment card is required. Property photos can still be selected locally in Creative Studio when designing a poster; persistent property-library photo uploads are disabled in this version.
- 1080×1080 property poster generator and PNG download.
- Free tier: 10 AI generations per calendar month.
- Pro tier: unlimited generations; administrator assigns Pro manually.
- Admin user/role/plan management.
- Responsive frontend; no frontend build step or external JavaScript framework dependency.

## Important limitations in this first production package

1. Payments are **not** integrated. The admin manually assigns Free/Pro plans. Do not advertise paid checkout until a payment provider and webhook flow have been implemented and tested.
2. Email OTP verification is included for new registrations and requires a Resend account, API key and verified sender domain. Password reset emails and automated subscription billing are not included.
3. Persistent property-library image uploads are disabled to avoid requiring an R2 subscription. The Creative Studio can still use a photo selected locally in your browser for the current poster.
4. RERA numbers and property claims are user-entered and are not independently verified. Review generated content before publishing.
5. The first account whose email exactly matches `ADMIN_EMAIL` becomes an administrator. Configure that value before creating your first account.
6. The included free tier is a basic usage counter, not a payment or accounting system.

## Currency handling (India)

- The application currency is fixed to **INR (₹)** throughout.
- Property listing prices are entered as a number of **Lakhs** or **Crores** (for example, `85` + `Lakhs` means ₹85,00,000).
- Transaction deal value, commission earned/received, GST, TDS and co-broker share are entered as full rupee amounts (for example, `8500000` means ₹85,00,000).
- Commission percentage calculations use the deal value in rupees and produce a rupee commission amount.
- The transaction CSV export names its financial columns with `_inr` to make the currency explicit.

## What you need

- A Cloudflare account.
- An OpenAI API key with API billing enabled.
- Node.js LTS installed on your computer.
- A terminal/command prompt. If you do not want to use commands yourself, ask a developer to perform the deployment steps below once.

## 1. Install Wrangler

Open Terminal (Mac) or PowerShell (Windows), then run:

```bash
npm install
npx wrangler login
```

A browser window opens. Sign in to Cloudflare and authorize Wrangler.

## 2. Create the D1 database

```bash
npx wrangler d1 create agentgrow-db
```

Cloudflare returns a database ID. Open `wrangler.toml` and replace:

```toml
database_id = "REPLACE_WITH_D1_DATABASE_ID"
```

with the ID Cloudflare provided.

Create the database tables:

```bash
npx wrangler d1 execute agentgrow-db --remote --file=migrations/0001_init.sql
npx wrangler d1 execute agentgrow-db --remote --file=migrations/0002_transactions.sql\nnpx wrangler d1 execute agentgrow-db --remote --file=migrations/0003_email_verification.sql
```

## 3. Image storage

This deployment does not use R2. No R2 bucket or payment card is required. Property photos can be selected locally inside Creative Studio when creating a poster.

## 4. Set administrator email and app origin

Open `wrangler.toml`:

- Change `ADMIN_EMAIL` to the email address you will use for your first account.
- Change `APP_ORIGIN` to your final HTTPS domain, or use the `workers.dev` origin after your first deployment.

Do this before registering your account. The matching first account is granted administrator access.

## 5. Add secrets

Run these commands, entering the actual values when prompted:

```bash
npx wrangler secret put OPENAI_API_KEY
npx wrangler secret put SESSION_SECRET\nnpx wrangler secret put RESEND_API_KEY\nnpx wrangler secret put EMAIL_FROM
```

Use your OpenAI API key for the first secret. For `SESSION_SECRET`, use a long, random value (at least 32 characters). For `RESEND_API_KEY`, use an API key from Resend (https://resend.com). For `EMAIL_FROM`, enter a sender such as `AgentGrow AI <verify@your-verified-domain.in>` after verifying that domain with Resend. Do not use an address on a domain you do not control. The current session implementation stores random opaque session tokens hashed in D1; the secret is retained for future signed-token extensions.

Never put API keys in `public/app.js`, `index.html`, or any other browser file. Do not share the `.dev.vars` file.

## 6. Test locally (optional)

Create a local secrets file by copying `.dev.vars.example` to `.dev.vars` and entering your local OpenAI key and a long random session secret.

```bash
npx wrangler dev
```

Open the local URL Wrangler prints. Local D1 bindings may require local setup; deploy to a staging Worker to test the complete flow.

## 7. Deploy

```bash
npx wrangler deploy
```

Cloudflare prints your Worker URL, usually:

`https://agentgrow-ai.<your-subdomain>.workers.dev`

Open that address and create the administrator account using the email configured as `ADMIN_EMAIL`.

## 8. Connect your domain (optional)

In Cloudflare Dashboard:

1. Open Workers & Pages.
2. Select `agentgrow-ai`.
3. Open Settings → Domains & Routes.
4. Add your domain or subdomain.
5. Make sure it uses HTTPS.
6. Update `APP_ORIGIN` in `wrangler.toml` to the exact HTTPS origin and deploy again.

## Everyday use

- Register a agent account.
- Add a property in **My Properties**.
- Generate WhatsApp, social and Reel content in **AI Marketing Studio**.
- Create a square poster in **Creative Studio**.
- Revisit generated content in **Campaign History**.
- Record every completed or pending deal in **Transactions** and monitor commission earned versus received.
- Review monthly AI usage in **Usage & Analytics**.
- Administrator can assign Pro access in **Admin Console**.

## Security and operational checklist before inviting customers

- Use a unique administrator email and strong password.
- Keep OpenAI key only in Worker secrets.
- Add a Cloudflare rate-limiting rule for `/api/auth/login`, `/api/auth/register` and `/api/generate`.
- Set a spending limit/usage alert in your OpenAI account.
- Configure backups/exports for D1 data.
- Add privacy policy, terms, support contact and data-retention policy.
- Test email verification delivery, expiry, resend throttling and incorrect-code limits before inviting customers. Add password reset before broad public launch.
- Test registration, login, logout, user isolation, generation failures and quota boundaries.
- Have the deployment and security configuration reviewed before handling paying customers.

## Updating the application

After changing files, run:

```bash
npx wrangler deploy
```

## Troubleshooting

**"OpenAI API key is not configured"**  
Run `npx wrangler secret put OPENAI_API_KEY`, then deploy again.\n\n**Email verification is not configured**\nAdd `RESEND_API_KEY` and `EMAIL_FROM` as Worker secrets, and verify the sender domain in Resend. Registration intentionally remains blocked until these are configured.

**"Please sign in" after refresh**  
Check that the app is opened over HTTPS and that browser cookies are enabled.

**Database/table error**  
Confirm the D1 database ID in `wrangler.toml` and run the remote SQL migration command.

**Property photos**  
Persistent property-library photo uploads are disabled in this no-R2 version. Creative Studio can use a photo selected locally in the browser.

**AI generation fails**  
Check OpenAI API billing, key validity and usage limits. The application does not guarantee AI service availability.

## Architecture

- `src/index.js` — Cloudflare Worker API, auth, data access and OpenAI integration.
- `public/index.html` — application shell.
- `public/styles.css` — responsive visual system.
- `public/app.js` — frontend application.
- `migrations/0001_init.sql`, `0002_transactions.sql` and `0003_email_verification.sql` — D1 schema, transaction ledger and email-verified signup.
- `wrangler.toml` — Cloudflare configuration.
