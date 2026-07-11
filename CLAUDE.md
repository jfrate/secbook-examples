# Applied Software Security — secbook-examples

## What this repo is

Companion code examples for *Applied Software Security* by Joseph Frate, Jr.
Each subdirectory is a standalone Node.js/Express app demonstrating a specific vulnerability and its mitigation.

The book HTML source is in the sibling repo `../secbook`.

---

## Tech stack

- Node.js + Express
- `express-session` + `bcryptjs` for auth
- `better-sqlite3` for in-memory SQLite (injection-orm example)
- `graphql` npm package v16 (injection-graphql example)
- PostgreSQL for examples that need a persistent database (injection-sql)

Install all dependencies from the repo root:

```sh
npm install
```

---

## Structure

```
secbook-examples/
  package.json           — shared dependencies for all examples
  part3/
    chapter-3-2/
      base-project/      — minimal Express app used as starting point
      injection-sql/     — SQL injection example (requires PostgreSQL)
      injection-nosql/   — NoSQL injection
      injection-ldap/    — LDAP injection
      injection-xpath/   — XPath injection
      injection-command/ — Command injection
      injection-code/    — Code injection
      injection-expressionlang/ — Expression Language injection
      injection-ssti/    — Server-Side Template Injection
      injection-orm/     — ORM/HQL injection (better-sqlite3, in-memory)
      injection-smtp/    — SMTP injection
      injection-log/     — Log injection
      injection-csv/     — CSV / Formula injection
```

---

## Base project seed users

| Username | Password    | Role  |
|----------|-------------|-------|
| alice    | password123 | admin |
| bob      | password123 | user  |

---

## Example conventions

Every example app follows this pattern:

- A **vulnerable route** that demonstrates the attack
- A **safe route** that shows the correct mitigation
- Visual indicators (red text) for injected or unexpected content
- curl commands for attacks that browsers prevent (e.g. CRLF injection)

Each example is self-contained. Start any example with:

```sh
node part3/chapter-3-2/<example-name>/app.js
```

---

## Relationship to the book

Each example corresponds to a section in `chapter-3-2.html` in the secbook repo.
The chapter follows the same order as the directories above:
SQL → NoSQL → ORM/HQL → LDAP → XPath → Command → Code → EL → Extension → SSTI → XML → SMTP → CRLF/HTTP Header → Log → CSV/Formula.
