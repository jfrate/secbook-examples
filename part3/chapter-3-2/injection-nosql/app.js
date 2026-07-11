// app.js - NoSQL (MongoDB operator) injection demonstration
// Dependencies: express, express-session, bcryptjs, mongodb
// Install: npm install express express-session bcryptjs mongodb
// Requires: MongoDB running locally (default: mongodb://localhost:27017)
// On first run the app auto-seeds the mysecuritydb.users collection.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

const app = express();

// ---------- Database ----------
const mongoClient = new MongoClient(process.env.MONGO_URL || 'mongodb://localhost:27017');
let db;

(async () => {
  await mongoClient.connect();
  db = mongoClient.db('mysecuritydb');
  const count = await db.collection('users').countDocuments();
  if (count === 0) {
    await db.collection('users').insertMany([
      { username: 'alice', password: 'password1', role: 'admin', favorite_ice_cream: 'Vanilla'    },
      { username: 'bob',   password: 'password2', role: 'user',  favorite_ice_cream: 'Chocolate'  },
      { username: 'carol', password: 'password3', role: 'user',  favorite_ice_cream: 'Strawberry' },
      { username: 'dan',   password: 'password4', role: 'user',  favorite_ice_cream: 'Peach'      },
    ]);
    console.log('MongoDB: seeded mysecuritydb.users');
  }
})().catch(err => {
  console.error('MongoDB connection failed:', err.message);
  process.exit(1);
});

// ---------- Middleware ----------
// extended: true uses the qs library, which parses bracket-notation form fields
// (e.g. username[$gt]) into JavaScript objects ({ username: { $gt: '' } }).
// This is what makes form-based MongoDB operator injection possible.
app.use(express.urlencoded({ extended: true }));
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

// ---------- In-memory users for session auth (bcrypt-hashed) ----------
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
      <thead><tr><th>Username</th><th>Role</th><th>Favourite Ice Cream</th></tr></thead>
      <tbody>
        ${rows.map(r => `<tr><td>${r.username}</td><td>${r.role}</td><td>${r.favorite_ice_cream}</td></tr>`).join('')}
      </tbody>
    </table>`;
}

// ---------- Templates ----------
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
  res.send(page('NoSQL Injection', `
    <h1>NoSQL Injection</h1>
    <p>NoSQL injection occurs when user-supplied input is passed directly into a NoSQL database query without validation, allowing an attacker to inject query operators that change the query's logic. Unlike SQL injection — which exploits string concatenation to break out of a literal — NoSQL injection typically exploits structured query parameters. MongoDB queries are JavaScript objects; when user input is placed directly into a query object, the attacker can supply operator keys like <code>$gt</code>, <code>$ne</code>, or <code>$regex</code> that the database treats as query logic, not data.</p>
    <p>This example uses <strong>MongoDB</strong> and the Node.js <code>mongodb</code> driver. Express is configured with <code>urlencoded({ extended: true })</code>, which uses the <code>qs</code> library to parse bracket-notation form fields: a field named <code>username[$gt]</code> is parsed into the object <code>{ username: { $gt: '' } }</code>. When that object is passed directly to MongoDB's <code>find()</code>, MongoDB executes it as a range query — returning every user whose username is greater than an empty string, which is all of them.</p>

    <h2>How This App Works</h2>
    <p>MongoDB stores four users in a <code>mysecuritydb.users</code> collection: Alice, Bob, Carol, and Dan (passwords stored in plaintext to keep the query straightforward). The vulnerable <a href="/search">/search</a> route passes <code>req.body.username</code> directly into the query:</p>
    <pre>db.collection('users').find({ username: req.body.username }).toArray()</pre>
    <p>The <a href="/search">/search</a> page provides both a normal search form and an Injection Demo form. The injection form has its input field named <code>username[$gt]</code> — when submitted with an empty value, <code>qs</code> parses this into <code>{ username: { $gt: '' } }</code>, and MongoDB receives that as the query filter, returning all users.</p>
    <p>The safe version at <a href="/search-safe">/search-safe</a> checks <code>typeof username === 'string'</code> before using the value. An injected operator object fails this check and is rejected with an error.</p>

    <h2>The Attack</h2>
    <p>On the <a href="/search">/search</a> page, use the Injection Demo form with an empty comparison value. This submits <code>username[$gt]=</code>, which the <code>qs</code> parser converts to the query filter:</p>
    <pre>{ username: { $gt: '' } }</pre>
    <p>MongoDB interprets <code>$gt: ''</code> as "username greater than empty string" and returns all four users — the filter is bypassed without needing to know any username. Other operator payloads work by the same mechanism:</p>
    <ul>
      <li><code>username[$ne]=nonexistent</code> — returns all users whose username is not "nonexistent"</li>
      <li><code>username[$regex]=.*</code> — regex match against all usernames</li>
      <li><code>username[$exists]=true</code> — returns all documents that have a username field</li>
    </ul>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/search">/search</a> — Normal Search form, enter <code>alice</code> — returns only Alice's row</li>
      <li>Use the Injection Demo form with an empty value — all four users are returned</li>
      <li>Visit <a href="/search-safe">/search-safe</a> — same injection form — rejected with a validation error</li>
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
    ${user ? `<p>Already logged in as <strong>${user.username}</strong>. <a href="/">Go home</a> or log out below.</p>` : ''}
  `, user));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const record = USERS[username];
  if (!record || !bcrypt.compareSync(String(password), record.passwordHash)) {
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
const searchForm = (term, rows, error, user) => page('User Search', `
  <h1>User Search</h1>

  <h2>Normal Search</h2>
  <p>Search for a user by username.</p>
  <form method="post" action="/search">
    <label for="username">Username</label><br>
    <input id="username" name="username" value="${typeof term === 'string' ? term : ''}" placeholder="e.g. alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>

  <hr>

  <h2>Injection Demo</h2>
  <p>This form sends <code>username[$gt]=</code> as the POST body. The <code>qs</code> parser converts <code>username[$gt]</code> into <code>{ username: { $gt: '' } }</code>, which MongoDB executes as a range query returning all users.</p>
  <form method="post" action="/search">
    <label>Comparison value (leave empty to match all usernames):</label><br>
    <input name="username[$gt]" placeholder="(leave empty)" style="width:300px"><br><br>
    <button type="submit">Search (Injected)</button>
  </form>

  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search', requireAuth, (req, res) => {
  res.send(searchForm('', null, '', req.session.user));
});

app.post('/search', requireAuth, async (req, res) => {
  const { username } = req.body || {};
  try {
    // VULNERABLE: req.body.username may be a MongoDB operator object, not a string.
    // With extended: true, the form field "username[$gt]" is parsed by qs into
    // { username: { $gt: '' } }, which MongoDB treats as a range query.
    const users = await db.collection('users').find({ username }).toArray();
    res.send(searchForm(username, users, '', req.session.user));
  } catch (err) {
    res.send(searchForm(username, null, err.message, req.session.user));
  }
});

// ---------- Search (safe) ----------
const searchSafeForm = (term, rows, error, user) => page('User Search (Safe)', `
  <h1>User Search (Safe)</h1>

  <h2>Normal Search</h2>
  <p>Search for a user by username.</p>
  <form method="post" action="/search-safe">
    <label for="username">Username</label><br>
    <input id="username" name="username" value="${typeof term === 'string' ? term : ''}" placeholder="e.g. alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>

  <hr>

  <h2>Injection Demo</h2>
  <p>This form sends the same <code>username[$gt]=</code> payload. The safe route rejects it because the parsed value is not a plain string.</p>
  <form method="post" action="/search-safe">
    <input name="username[$gt]" placeholder="(leave empty)" style="width:300px"><br><br>
    <button type="submit">Search (Injected)</button>
  </form>

  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search-safe', requireAuth, (req, res) => {
  res.send(searchSafeForm('', null, '', req.session.user));
});

app.post('/search-safe', requireAuth, async (req, res) => {
  const { username } = req.body || {};
  // Safe: operator injection produces an object, not a string. Reject anything
  // that is not a plain string before it reaches the database query.
  if (typeof username !== 'string') {
    return res.send(searchSafeForm(
      username,
      null,
      'Invalid input: username must be a plain string, not a query operator object.',
      req.session.user
    ));
  }
  const users = await db.collection('users').find({ username }).toArray();
  res.send(searchSafeForm(username, users, '', req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
