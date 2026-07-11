// app.js - SQL injection demonstration
// Dependencies: express, express-session, bcryptjs, pg
// Install: npm install express express-session bcryptjs pg
// Database: psql -U postgres -f db/setup.sql

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();

// ---------- Database ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://localhost/mysecuritydb'
});

// ---------- Basic middleware ----------
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
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

// ---------- In-memory users (demo only) ----------
const seedUsers = [
  { username: 'alice', password: 'password1', role: 'admin' },
  { username: 'bob',   password: 'password2', role: 'user'  }
];
const USERS = Object.fromEntries(
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

function resultsTable(rows) {
  if (!rows.length) return '<p>No results found.</p>';
  return `
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>ID</th><th>Name</th><th>Favourite Ice Cream</th></tr></thead>
      <tbody>
        ${rows.map(r => `<tr><td>${r.id}</td><td>${r.name}</td><td>${r.favorite_ice_cream}</td></tr>`).join('')}
      </tbody>
    </table>`;
}

// ---------- Minimal HTML templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/search">Search</a> |
    <a href="/search-safe">Search (Safe)</a> |
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
  res.send(page('SQL Injection', `
    <h1>SQL Injection</h1>
    <p>SQL injection occurs when user-supplied input is concatenated directly into a SQL query string without sanitization or parameterization. The database receives the modified query and executes it as written, allowing an attacker to change the query's logic, bypass filters, retrieve unauthorized data, or in the worst case destroy data.</p>
    <p>It is one of the oldest and most prevalent web vulnerabilities, and remains highly impactful because databases typically hold an application's most sensitive data.</p>

    <h2>How This App Works</h2>
    <p>This app adds a User Search page at <a href="/search">/search</a> that queries a PostgreSQL <code>users</code> table by name. The vulnerable version builds the query by concatenating the search term directly into the SQL string:</p>
    <pre>SELECT * FROM users WHERE name = '${`'`}${`\${name}`}${`'`}'</pre>
    <p>A safe version is available at <a href="/search-safe">/search-safe</a>, which uses a parameterized query so the input is always treated as data, never as SQL.</p>

    <h2>The Attack</h2>
    <p>Searching for <code>Alice</code> returns her row normally. Entering the following as the search term:</p>
    <pre>' OR '1'='1</pre>
    <p>transforms the query into:</p>
    <pre>SELECT * FROM users WHERE name = '' OR '1'='1'</pre>
    <p>Because <code>'1'='1'</code> is always true, every row in the table is returned — the WHERE clause is completely bypassed. Other payloads can order, limit, or extract data from other tables using UNION. The most destructive payload:</p>
    <pre>'; DROP TABLE users; --</pre>
    <p>would permanently delete the table. <strong>Do not run this payload</strong> — it is shown here to illustrate the potential impact.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/search">/search</a> and enter <code>Alice</code> — returns Alice's row</li>
      <li>Enter <code>' OR '1'='1</code> — returns all rows</li>
      <li>Enter <code>' OR '1'='1' ORDER BY name --</code> — all rows, alphabetically ordered</li>
      <li>Visit <a href="/search-safe">/search-safe</a> and enter the same payloads — no results returned</li>
    </ul>

    ${user ? `<p>Currently logged in as <strong>${user.username}</strong> (${user.role}).</p>` : '<p>You are not logged in.</p>'}
  `, user));
});

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
    ${user ? `<p>Already logged in as <strong>${user.username}</strong>. You can <a href="/">go home</a> or log out below.</p>` : ''}
  `, user));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const record = USERS[username];
  if (!record) {
    return res.status(401).send(page('Login failed', '<p>Invalid credentials.</p><p><a href="/login">Try again</a></p>'));
  }
  const ok = bcrypt.compareSync(password, record.passwordHash);
  if (!ok) {
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
    <p>This page is visible to any authenticated user.</p>
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

// ---------- Search (vulnerable) ----------
const searchForm = (term, rows, error, action, user) => page('User Search', `
  <h1>User Search</h1>
  <p>Search for a user by name.</p>
  <form method="post" action="${action}">
    <label for="name">Name</label><br>
    <input id="name" name="name" value="${term}" placeholder="e.g. Alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search', requireAuth, (req, res) => {
  res.send(searchForm('', null, '', '/search', req.session.user));
});

app.post('/search', requireAuth, async (req, res) => {
  const { name } = req.body || {};
  try {
    // VULNERABLE: user input concatenated directly into the SQL query
    const sql = `SELECT * FROM users WHERE name = '${name}'`;
    const result = await pool.query(sql);
    res.send(searchForm(name, result.rows, '', '/search', req.session.user));
  } catch (err) {
    res.send(searchForm(name, null, err.message, '/search', req.session.user));
  }
});

// ---------- Search (safe) ----------
const searchSafeForm = (term, rows, user) => page('User Search (Safe)', `
  <h1>User Search (Safe)</h1>
  <p>Search for a user by name.</p>
  <form method="post" action="/search-safe">
    <label for="name">Name</label><br>
    <input id="name" name="name" value="${term}" placeholder="e.g. Alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search-safe', requireAuth, (req, res) => {
  res.send(searchSafeForm('', null, req.session.user));
});

app.post('/search-safe', requireAuth, async (req, res) => {
  const { name } = req.body || {};
  // Safe: user input passed as a parameter, never interpolated into the query string
  const result = await pool.query('SELECT * FROM users WHERE name = $1', [name]);
  res.send(searchSafeForm(name, result.rows, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
