// app.js - Extension Language (vm) injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
// Uses Node.js built-in vm module — no additional packages required.
//
// The vm module is intended for running isolated JavaScript scripts (extension
// language scripting). It is NOT a security sandbox. User scripts can escape
// the vm context by traversing the prototype chain to reach the outer process.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const vm = require('vm');

const app = express();

// ---------- Report data ----------
// This object is the "sandbox context" made available to user scripts.
// The developer intends scripts to only see users and orders, but not process/require.
const reportData = {
  users: [
    { id: 1, name: 'alice', role: 'admin', region: 'us-east' },
    { id: 2, name: 'bob',   role: 'user',  region: 'us-west' },
    { id: 3, name: 'carol', role: 'user',  region: 'eu-west' },
    { id: 4, name: 'dan',   role: 'user',  region: 'ap-east' },
  ],
  orders: [
    { id: 101, userId: 1, amount: 49.99,  status: 'shipped'   },
    { id: 102, userId: 2, amount: 149.99, status: 'pending'   },
    { id: 103, userId: 1, amount: 9.99,   status: 'delivered' },
    { id: 104, userId: 3, amount: 299.99, status: 'shipped'   },
  ],
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

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/report">Report</a> |
    <a href="/report-safe">Report (Safe)</a> |
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
  res.send(page('Extension Language Injection', `
    <h1>Extension Language Injection</h1>
    <p>Extension language injection occurs when an application executes user-supplied input as code within an embedded scripting engine. Many applications embed a scripting engine to support plugins, custom reports, automation workflows, or configuration hooks. When user input is accepted as the script itself, the attacker can use the scripting engine's capabilities to access data or functionality outside the intended scope.</p>
    <p>This example uses Node.js's built-in <strong>vm module</strong> — the JavaScript runtime's own extension scripting facility. The vm module is widely used to run user-provided scripts in an isolated context. It is not a security sandbox: the Node.js documentation explicitly states "The vm module is not a security mechanism. Do not use it to run untrusted code." An attacker can escape the vm context by traversing the JavaScript prototype chain to reach the outer <code>process</code> object, which exposes environment variables, loaded modules, and the ability to spawn child processes.</p>

    <h2>How This App Works</h2>
    <p>A Report Script Runner at <a href="/report">/report</a> lets authenticated users write custom scripts against a report dataset containing <code>users</code> and <code>orders</code> arrays. The script runs in a vm context that exposes only those two arrays — <code>process</code> and <code>require</code> are deliberately not included. The vulnerable version passes the script directly to <code>vm.runInContext()</code>. The safe version at <a href="/report-safe">/report-safe</a> accepts only a predefined report type and runs server-side logic — no user script is ever executed.</p>

    <h2>The Attack</h2>
    <p>Enter the following script in the <a href="/report">/report</a> form:</p>
    <pre>this.constructor.constructor('return process')().env</pre>
    <p>Step by step:</p>
    <ol>
      <li><code>this</code> — the sandbox context object (a plain JS object)</li>
      <li><code>this.constructor</code> — <code>Object</code>, from the outer V8 context</li>
      <li><code>this.constructor.constructor</code> — <code>Function</code>, also from the outer V8 context</li>
      <li><code>Function('return process')()</code> — creates and calls a function in the outer context, returning the real <code>process</code> object</li>
      <li><code>.env</code> — dumps all server environment variables</li>
    </ol>
    <p>From <code>process</code> the attacker can also call <code>process.mainModule</code> (older Node.js), access <code>process.binding()</code>, or use <code>require('child_process').execSync()</code> to run arbitrary OS commands.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/report">/report</a> and enter <code>users.length</code> — returns 4 (safe, in-context access)</li>
      <li>Enter <code>orders.filter(o => o.status === 'shipped').length</code> — 2 shipped orders</li>
      <li>Enter <code>this.constructor.constructor('return process')().version</code> — returns the Node.js version from outside the sandbox</li>
      <li>Enter <code>this.constructor.constructor('return process')().env</code> — dumps all environment variables</li>
      <li>Visit <a href="/report-safe">/report-safe</a> — select any report type — no script executed</li>
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
    <p>This page is visible to any authenticated user.</p>
    <p><a href="/report">Report (vulnerable)</a> | <a href="/report-safe">Report (safe)</a></p>
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

// ---------- Report (vulnerable) ----------
const reportForm = (script, result, error, user) => page('Report', `
  <h1>Report Script Runner</h1>
  <p>Enter a JavaScript script to query the report data. The script runs in a vm sandbox with access to <code>users</code> and <code>orders</code> arrays only.</p>
  <form method="post" action="/report">
    <label for="script">Script</label><br>
    <textarea id="script" name="script" rows="4" style="width:600px;font-family:monospace">${escapeHtml(script)}</textarea><br><br>
    <button type="submit">Run</button>
  </form>
  <p>Try these scripts:</p>
  <ul>
    <li><code>users.length</code></li>
    <li><code>orders.filter(o =&gt; o.status === 'shipped').length</code></li>
    <li><code>this.constructor.constructor('return process')().env</code></li>
  </ul>
  ${error  ? `<p style="color:red"><strong>Error:</strong> ${escapeHtml(error)}</p>` : ''}
  ${result !== null ? `<h2>Result</h2><pre>${escapeHtml(result)}</pre>` : ''}
`, user);

app.get('/report', requireAuth, (req, res) => {
  res.send(reportForm('', null, '', req.session.user));
});

app.post('/report', requireAuth, (req, res) => {
  const { script } = req.body || {};
  try {
    // VULNERABLE: user script runs inside a vm context that is not a true security sandbox.
    // The vm module explicitly states it must not be used for untrusted code.
    // An attacker can escape by using this.constructor.constructor (which resolves to the
    // outer Function constructor) to create a function in the outer context and return process.
    const context = vm.createContext({ ...reportData });
    const raw = vm.runInContext(script, context, { timeout: 1000 });
    res.send(reportForm(script, JSON.stringify(raw, null, 2), '', req.session.user));
  } catch (err) {
    res.send(reportForm(script, null, err.message, req.session.user));
  }
});

// ---------- Report (safe) ----------
const REPORT_TYPES = {
  summary: (data) => ({
    userCount:    data.users.length,
    orderCount:   data.orders.length,
    totalRevenue: data.orders.reduce((sum, o) => sum + o.amount, 0).toFixed(2),
  }),
  users:   (data) => data.users.map(u => ({ id: u.id, name: u.name, role: u.role, region: u.region })),
  shipped: (data) => data.orders.filter(o => o.status === 'shipped'),
};

const reportSafeForm = (type, result, error, user) => page('Report (Safe)', `
  <h1>Report Script Runner (Safe)</h1>
  <p>Select a predefined report type. No user script is executed — the server runs hardcoded logic for each allowed type.</p>
  <form method="post" action="/report-safe">
    <label for="type">Report type</label><br>
    <select id="type" name="type" style="width:300px">
      <option value="summary"${type === 'summary' ? ' selected' : ''}>Summary</option>
      <option value="users"${type === 'users'   ? ' selected' : ''}>User List</option>
      <option value="shipped"${type === 'shipped' ? ' selected' : ''}>Shipped Orders</option>
    </select><br><br>
    <button type="submit">Run</button>
  </form>
  ${error  ? `<p style="color:red"><strong>Error:</strong> ${escapeHtml(error)}</p>` : ''}
  ${result !== null ? `<h2>Result</h2><pre>${escapeHtml(result)}</pre>` : ''}
`, user);

app.get('/report-safe', requireAuth, (req, res) => {
  res.send(reportSafeForm('', null, '', req.session.user));
});

app.post('/report-safe', requireAuth, (req, res) => {
  const { type } = req.body || {};
  // Safe: no user script is executed. Accept only a predefined report type key,
  // look it up in an allowlist, and run server-side logic.
  const handler = REPORT_TYPES[type];
  if (!handler) {
    return res.send(reportSafeForm(type, null, `Unknown report type: ${escapeHtml(type)}`, req.session.user));
  }
  const result = handler(reportData);
  res.send(reportSafeForm(type, JSON.stringify(result, null, 2), '', req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
