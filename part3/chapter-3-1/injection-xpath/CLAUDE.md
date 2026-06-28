# Chapter 3-1: Base Project

Security book teaching target (`secbook-examples/part3/chapter-3-1`). A minimal Node.js/Express app used as the starting point for injection vulnerability examples.

## Stack

- Node.js + Express
- `express-session` + `bcryptjs` for auth
- PostgreSQL (via `db/setup.sql`) — not yet wired into the app
- No `package.json` — install deps manually: `npm install express express-session bcryptjs`

## Structure

- `app.js` — single-file server with in-memory auth, session management, RBAC middleware, and inline HTML templates
- `db/setup.sql` — PostgreSQL schema (`mysecuritydb` database, `users` table with `name` and `favorite_ice_cream` columns)

## Seed Users

| Username | Password | Role |
|---|---|---|
| alice | password123 | admin |
| bob | password123 | user |

## Routes

| Route | Auth | Notes |
|---|---|---|
| `GET /` | None | Home page |
| `GET/POST /login` | None | Form-based login |
| `POST /logout` | None | Destroys session |
| `GET /dashboard` | Any logged-in user | |
| `GET /admin` | Admin role only | |
| `GET /api/me` | Any logged-in user | Returns session JSON |

## Intentional Vulnerabilities (Teaching Targets)

The database schema (`favorite_ice_cream` column) is not yet connected to `app.js`. The chapter likely wires in a DB-backed user lookup without parameterized queries to create a **SQL injection** surface.

Additional weaknesses present in the base:

- `user.username` / `user.role` rendered into HTML without escaping — **reflected XSS** risk once user input reaches those fields
- Session secret falls back to hardcoded `'change-this-session-secret'` if `SESSION_SECRET` env var is absent
- No CSRF protection on `POST /login` or `POST /logout`
- No rate limiting on the login endpoint

## What's Correct

- Passwords hashed with bcrypt (cost 10)
- Sessions use `httpOnly` and `sameSite: lax`
- RBAC enforced via `requireAuth` / `requireRole` middleware chain
