// app.js - ORM / HQL Injection demonstration
// Dependencies: express, express-session, bcryptjs, better-sqlite3
// Install: npm install express express-session bcryptjs better-sqlite3
//
// ORM injection occurs when a developer bypasses the ORM's parameterised API
// and interpolates user input directly into a raw query string. Most ORMs
// expose an escape hatch — sequelize.query(), TypeORM's createQueryBuilder()
// with a raw WHERE clause, Prisma's $queryRaw, Hibernate HQL strings — that
// reintroduces SQL injection even though the rest of the codebase uses the ORM
// safely. The fix is to use the ORM's parameterised API for every query.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const app = express();

// ---------- Database setup ----------
// SQLite in-memory database. In a real application this would be PostgreSQL,
// MySQL, or another server-side database reached through an ORM like Sequelize,
// TypeORM, or Prisma. The injection pattern is identical regardless of the
// underlying database; only the SQL dialect differs.
const db = new Database(':memory:');

db.exec(`
  CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    role        TEXT    NOT NULL DEFAULT 'user',
    email       TEXT    NOT NULL,
    recovery_token TEXT NOT NULL
  );
`);

// Seed data — recovery_token is a sensitive column that should never appear
// in search results but is present in the table and reachable via injection.
const insertUser = db.prepare(
  'INSERT INTO users (username, role, email, recovery_token) VALUES (?, ?, ?, ?)'
);
insertUser.run('alice', 'admin', 'alice@internal.corp', 'tok-alice-8f3a2c9d1b4e');
insertUser.run('bob',   'user',  'bob@example.com',     'tok-bob-5e7f1a0c2d9b');
insertUser.run('carol', 'user',  'carol@example.com',   'tok-carol-3b6d4e8f0a2c');

// ---------- ORM-style wrapper ----------
// Simulates the two APIs that every ORM exposes:
//
//   UserModel.search(term)    — the ORM's built-in parameterised method.
//                               Equivalent to Sequelize's Model.findAll({ where: ... })
//                               or TypeORM's repo.find({ where: ... }).
//                               User input is bound as a typed parameter; it
//                               cannot alter the query structure.
//
//   UserModel.rawSearch(sql)  — the ORM's raw-query escape hatch.
//                               Equivalent to sequelize.query(sql),
//                               TypeORM's entityManager.query(sql), or
//                               Prisma's $queryRawUnsafe(sql).
//                               If the SQL string was built by concatenation,
//                               all of the ORM's protection is bypassed.
//
const UserModel = {
  // Safe: only username, role, and email are projected; input is a bound parameter.
  search(term) {
    return db
      .prepare('SELECT id, username, role, email FROM users WHERE username LIKE ?')
      .all(`%${term}%`);
  },

  // Unsafe: executes any SQL string passed to it, including one built by concatenation.
  rawSearch(sql) {
    try {
      return db.prepare(sql).all();
    } catch (e) {
      return { error: e.message };
    }
  },
};

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ---------- Sessions ----------
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'change-this-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      // secure: true, // enable when serving over HTTPS
      maxAge: 1000 * 60 * 60
    }
  })
);

// ---------- In-memory users for session auth ----------
const seedUsers = [
  { username: 'alice', password: 'password1', role: 'admin' },
  { username: 'bob',   password: 'password2', role: 'user'  }
];
const SESSION_USERS = Object.fromEntries(
  seedUsers.map(u => [
    u.username,
    { username: u.username, role: u.role, passwordHash: bcrypt.hashSync(u.password, 10) }
  ])
);

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).send(`
    <h1>401 Unauthorized</h1>
    <p>You must <a href="/login">log in</a> to access this page.</p>
  `);
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session?.user?.role === role) return next();
    return res.status(403).send('<h1>403 Forbidden</h1><p>Insufficient permissions.</p>');
  };
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return '<p><em>No results.</em></p>';
  }
  const cols = Object.keys(rows[0]);
  const header = cols.map(c => `<th>${escapeHtml(c)}</th>`).join('');
  const body = rows.map(r =>
    `<tr>${cols.map(c => {
      const val = escapeHtml(String(r[c] ?? ''));
      const isLeak = c !== 'id' && c !== 'username' && c !== 'role' && c !== 'email';
      return `<td${isLeak ? ' style="color:red;font-weight:bold"' : ''}>${val}</td>`;
    }).join('')}</tr>`
  ).join('');
  return `
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr>${header}</tr></thead>
      <tbody>${body}</tbody>
    </table>`;
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/search">User Search</a> |
    <a href="/search-safe">User Search (Safe)</a> |
    <a href="/login">${user ? 'Switch user' : 'Login'}</a>
    ${user ? ' | <form style="display:inline" method="post" action="/logout"><button>Logout</button></form>' : ''}
  </nav>
  <hr>
`;

const page = (title, body, user) => `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  ${nav(user)}
  ${body}
</body>
</html>
`;

// ---------- Routes ----------
app.get('/', (req, res) => {
  const user = req.session.user;
  res.send(page('ORM / HQL Injection', `
    <h1>ORM / HQL Injection</h1>
    <p>ORM injection occurs when a developer bypasses the ORM's parameterised API and interpolates user input directly into a raw query string. Modern ORMs — Sequelize, TypeORM, Prisma, Hibernate — protect against SQL injection by default: when you use their built-in query methods, user input is passed as a bound parameter that the database engine treats as a literal value, never as SQL syntax. But every ORM also provides an escape hatch for queries too complex for the safe API: <code>sequelize.query()</code>, <code>entityManager.query()</code>, <code>$queryRawUnsafe()</code>, Hibernate's <code>session.createQuery()</code> with a raw HQL string. If the string passed to that escape hatch was built by concatenation, all of the ORM's protection evaporates.</p>
    <p>This example demonstrates the pattern with a user search feature. The <code>users</code> table has columns <code>id</code>, <code>username</code>, <code>role</code>, <code>email</code>, and <code>recovery_token</code>. The intended query — built by the safe ORM method — returns only <code>id</code>, <code>username</code>, <code>role</code>, and <code>email</code>. The vulnerable route passes a raw SQL string to <code>UserModel.rawSearch()</code>, constructed by interpolating the search term. A UNION-based payload reaches <code>recovery_token</code> — a sensitive column that no legitimate query exposes.</p>

    <h2>How This App Works</h2>
    <p><code>UserModel</code> is a thin wrapper over a SQLite in-memory database that exposes two methods. <code>UserModel.search(term)</code> simulates the ORM's built-in parameterised API — input is bound as a <code>?</code> placeholder. <code>UserModel.rawSearch(sql)</code> simulates the raw escape hatch — it executes any SQL string it receives. The <a href="/search">/search</a> route builds that string by interpolation; the <a href="/search-safe">/search-safe</a> route calls the safe method instead. Any columns beyond the intended four appear in red in the results table.</p>

    <h2>The Attack</h2>
    <p>On the <a href="/search">/search</a> page, enter the following as the search term:</p>
    <pre>' UNION SELECT recovery_token, email, role, id FROM users --</pre>
    <p>The constructed SQL becomes:</p>
    <pre>SELECT id, username, role, email FROM users WHERE username LIKE '%' UNION SELECT recovery_token, email, role, id FROM users --%'</pre>
    <p>The UNION replaces the <code>id</code> column with <code>recovery_token</code> in the result set. All three users' recovery tokens are returned — credentials the application never exposes through the search interface.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/search">/search</a> — enter <code>alice</code> — see a normal result with id, username, role, email</li>
      <li>Enter <code>' UNION SELECT recovery_token, email, role, id FROM users --</code> — recovery tokens appear in red in the first column</li>
      <li>Visit <a href="/search-safe">/search-safe</a> and enter the same payload — the single-quote is treated as a literal character; no results or only a literal-match result</li>
    </ul>

    ${user ? `<p>Currently logged in as <strong>${user.username}</strong> (${user.role}).</p>` : '<p>You are not logged in.</p>'}
  `, user));
});

// ---------- Login / logout ----------
app.get('/login', (req, res) => {
  const user = req.session.user;
  res.send(page('Login', `
    <h1>Login</h1>
    <form method="post" action="/login">
      <label for="username">Username</label><br>
      <input id="username" name="username" autocomplete="username" required><br><br>
      <label for="password">Password</label><br>
      <input id="password" name="password" type="password" autocomplete="current-password" required><br><br>
      <button type="submit">Sign in</button>
    </form>
    ${user ? `<p>Already logged in as <strong>${user.username}</strong>. <a href="/">Go home</a>.</p>` : ''}
  `, user));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const record = SESSION_USERS[username];
  if (!record || !bcrypt.compareSync(password, record.passwordHash)) {
    return res.status(401).send(page('Login failed', '<p>Invalid credentials.</p><p><a href="/login">Try again</a></p>'));
  }
  req.session.user = { username: record.username, role: record.role };
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  res.send(page('Dashboard', `
    <h1>Dashboard</h1>
    <p>Welcome, <strong>${user.username}</strong>. Your role is <strong>${user.role}</strong>.</p>
    <p><a href="/search">User Search (vulnerable)</a> | <a href="/search-safe">User Search (safe)</a></p>
  `, user));
});

app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  const user = req.session.user;
  res.send(page('Admin', `
    <h1>Admin</h1>
    <p>Only admins can see this. Hello, <strong>${user.username}</strong>.</p>
  `, user));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user, ok: true });
});

// ---------- User search (vulnerable) ----------
const searchForm = (q, sql, rows, user) => page('User Search', `
  <h1>User Search (Vulnerable)</h1>
  <p>Searches by passing a raw SQL string to the ORM's query escape hatch.
     The search term is interpolated directly into the SQL — injection is possible.</p>
  <form method="post" action="/search">
    <label for="q">Search username</label><br>
    <input id="q" name="q" value="${escapeHtml(q)}"
      placeholder="e.g. alice — or try a UNION payload"
      style="width:600px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${sql !== null ? `
    <h2>SQL sent to the database</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(sql)}</pre>
    <h2>Results</h2>
    ${Array.isArray(rows) && rows.length > 0 && Object.keys(rows[0]).some(k => k !== 'id' && k !== 'username' && k !== 'role' && k !== 'email')
      ? '<p style="color:red;font-weight:bold">&#9888; Columns beyond the intended projection returned — sensitive data leaked via UNION injection.</p>'
      : ''}
    ${rows?.error
      ? `<p style="color:red">SQL error: ${escapeHtml(rows.error)}</p>`
      : renderRows(rows)}
  ` : ''}
`, user);

app.get('/search', requireAuth, (req, res) => {
  res.send(searchForm('', null, null, req.session.user));
});

app.post('/search', requireAuth, (req, res) => {
  const { q = '' } = req.body;
  // VULNERABLE: the search term is interpolated directly into the SQL string.
  // This is equivalent to: sequelize.query(`SELECT ... WHERE username LIKE '%${q}%'`)
  // or TypeORM's: createQueryBuilder().where("username LIKE '%" + q + "%'")
  // The ORM's parameterisation is bypassed entirely; standard SQL injection applies.
  const sql = `SELECT id, username, role, email FROM users WHERE username LIKE '%${q}%'`;
  const rows = UserModel.rawSearch(sql);
  res.send(searchForm(q, sql, rows, req.session.user));
});

// ---------- User search (safe) ----------
const searchSafeForm = (q, rows, user) => page('User Search (Safe)', `
  <h1>User Search (Safe)</h1>
  <p>Searches via the ORM's built-in parameterised method.
     The search term is a bound parameter — it cannot alter the query structure.</p>
  <form method="post" action="/search-safe">
    <label for="q">Search username</label><br>
    <input id="q" name="q" value="${escapeHtml(q)}"
      placeholder="e.g. alice — try the same UNION payload"
      style="width:600px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${rows !== null ? `
    <h2>Results</h2>
    ${renderRows(rows)}
  ` : ''}
`, user);

app.get('/search-safe', requireAuth, (req, res) => {
  res.send(searchSafeForm('', null, req.session.user));
});

app.post('/search-safe', requireAuth, (req, res) => {
  const { q = '' } = req.body;
  // Safe: the ORM's built-in method binds the search term as a typed parameter.
  // Equivalent to: User.findAll({ where: { username: { [Op.like]: `%${q}%` } } })
  // or TypeORM's: repo.find({ where: { username: Like(`%${q}%`) } })
  // No matter what q contains, it is treated as a literal string value by the DB engine.
  const rows = UserModel.search(q);
  res.send(searchSafeForm(q, rows, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
