# checkmate web

Marketing site and future auth surface for checkmate.

## Stack

- Next.js App Router (`web/`)
- `next-intl` — French default, English secondary (`/fr`, `/en`)
- Design tokens mirrored from the Chrome extension (`src/styles/tokens.css`)
- Plan catalog: `src/config/plans.ts` (single source of truth for pricing UI)

## Develop

```bash
cd web
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) — you will be redirected to `/fr`.

## Key routes

| Path | Purpose |
|------|---------|
| `/fr`, `/en` | Landing page |
| `/fr/signup`, `/en/signup` | Sign-up stub (auth next) |
| `/fr/signin`, `/en/signin` | Sign-in stub |
| `/fr/terms`, `/fr/privacy` | Legal placeholders |

## Security headers

See [HOSTING.md](./HOSTING.md) for CSP / HSTS / XFO requirements so the deployed site can pass checkmate’s own `header-checks` rules.
