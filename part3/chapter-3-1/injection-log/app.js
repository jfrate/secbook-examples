// app.js - Log Injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
//
// Log injection occurs when user-supplied input is written to log entries without
// sanitizing newline characters. Because log entries are line-delimited, an attacker
// who controls a logged value can inject additional lines that are structurally
// indistinguishable from legitimate entries — forging an audit trail, hiding attacks,
// or corrupting log-based metrics.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();

// ---------- In-memory log stores ----------
// Two separate stores so the vulnerable and safe demos are independent.
const vulnLog = [];
const safeLog  = [];

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

// Encode CR and LF as visible two-character escape sequences before writing to a log.
// Backslashes are doubled first so existing \r / \n strings are not misread.
// This keeps every log event on a single line while preserving the original content.
function sanitizeForLog(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/logs">Logs (Vulnerable)</a> |
    <a href="/logs-safe">Logs (Safe)</a> |
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
  res.send(page('Log Injection', `
    <h1>Log Injection</h1>
    <p>Log injection occurs when user-supplied values are written to application logs without sanitizing newline characters (<code>\n</code>, <code>\r</code>). Application logs are line-delimited: each log event occupies one line, and log viewers, SIEMs, and analysts treat each line as a separate event. An attacker who controls a logged value can inject additional lines that are structurally identical to legitimate entries — indistinguishable to any system or person reading the log.</p>
    <p>The most impactful attack is <strong>audit trail forgery</strong>: by including a newline and a forged log line in a login username, the attacker creates a fake "successful admin login" record that never actually occurred. In a post-incident review, an analyst sees what appears to be a legitimate event and cannot distinguish it from real entries. This example logs every login attempt to a separate in-memory store for each route so you can compare the vulnerable and safe outputs side by side.</p>

    <h2>How This App Works</h2>
    <p>Login attempts are logged in the format <code>[timestamp] LOGIN ip=... status=... username=...</code>. The username is placed <em>last</em> so that injected content after a newline forms a complete, clean forged line — no real suffix is appended after the injected text. The vulnerable <a href="/login">/login</a> endpoint writes the username directly to <code>vulnLog</code>; the safe <a href="/login-safe">/login-safe</a> endpoint encodes newlines as <code>\\n</code> before writing to <code>safeLog</code>. Admins can compare both at <a href="/logs">/logs</a> and <a href="/logs-safe">/logs-safe</a>.</p>

    <h2>The Attack</h2>
    <p>Browsers strip newlines from <code>&lt;input type="text"&gt;</code> before submitting. Use <code>curl</code> with <code>%0a</code> (URL-encoded LF) to inject a forged entry:</p>
    <pre>curl -s -X POST \\
  -d "username=alice%0a[2026-07-11T10%3A00%3A01.000Z]+LOGIN+ip%3D127.0.0.1+status%3DSUCCESS+username%3Dadmin" \\
  -d "password=wrongpassword" \\
  http://localhost:3000/login</pre>
    <p>This adds two lines to <code>vulnLog</code>: a real <code>FAIL</code> for the injection attempt, and a forged <code>SUCCESS</code> for <code>admin</code> with a fabricated timestamp. Both lines are structurally identical — an analyst cannot tell which is genuine.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Make one normal failed login attempt via <code>/login</code> to establish a baseline</li>
      <li>Run the curl command above while logged in as alice — then visit <a href="/logs">/logs</a></li>
      <li>The log shows 3 lines for 2 attempts: the baseline FAIL, the real FAIL from the injection attempt, and the forged SUCCESS for admin</li>
      <li>Run the same curl against <code>/login-safe</code> and visit <a href="/logs-safe">/logs-safe</a> — the forged content is visible as a single long line with <code>\\n</code> encoded</li>
    </ul>

    ${user ? `<p>Currently logged in as <strong>${user.username}</strong> (${user.role}).</p>` : '<p>You are not logged in.</p>'}
  `, user));
});

// ---------- Login (vulnerable) ----------
const loginVulnForm = (error, user) => page('Login (Vulnerable)', `
  <h1>Login</h1>
  <p>Login attempts are logged with the username written directly into the log entry.</p>
  <form method="post" action="/login">
    <label for="username">Username</label><br>
    <input id="username" name="username" autocomplete="username" required><br><br>
    <label for="password">Password</label><br>
    <input id="password" name="password" type="password" autocomplete="current-password" required><br><br>
    <button type="submit">Sign in</button>
  </form>
  ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
  ${user ? `<p>Already logged in as <strong>${user.username}</strong>. <a href="/">Go home</a>.</p>` : ''}
`, user);

app.get('/login', (req, res) => {
  res.send(loginVulnForm('', req.session.user || null));
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const timestamp = new Date().toISOString();
  const record = USERS[username];
  const success = record && bcrypt.compareSync(password, record.passwordHash);

  // VULNERABLE: username is written directly into the log entry.
  // A \n in the username starts a new log line that looks identical to a real entry.
  // Injecting \n[timestamp] LOGIN ip=... status=SUCCESS username=admin creates a
  // forged successful admin login that never actually occurred.
  const status = success ? 'SUCCESS' : 'FAIL';
  vulnLog.push(`[${timestamp}] LOGIN ip=${ip} status=${status} username=${username}`);

  if (success) {
    req.session.user = { username: record.username, role: record.role };
    return res.redirect('/dashboard');
  }
  res.status(401).send(loginVulnForm('Invalid credentials.', req.session.user || null));
});

// ---------- Login (safe) ----------
const loginSafeForm = (error, user) => page('Login (Safe)', `
  <h1>Login (Safe)</h1>
  <p>Newlines in the username are encoded as <code>\\n</code> before logging — each attempt occupies exactly one line.</p>
  <form method="post" action="/login-safe">
    <label for="username">Username</label><br>
    <input id="username" name="username" autocomplete="username" required><br><br>
    <label for="password">Password</label><br>
    <input id="password" name="password" type="password" autocomplete="current-password" required><br><br>
    <button type="submit">Sign in</button>
  </form>
  ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
  ${user ? `<p>Already logged in as <strong>${user.username}</strong>. <a href="/">Go home</a>.</p>` : ''}
`, user);

app.get('/login-safe', (req, res) => {
  res.send(loginSafeForm('', req.session.user || null));
});

app.post('/login-safe', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const timestamp = new Date().toISOString();
  const record = USERS[username];
  const success = record && bcrypt.compareSync(password, record.passwordHash);

  // Safe: newlines in the username are encoded as \r and \n escape sequences.
  // Every login attempt occupies exactly one log line regardless of what the username contains.
  const status = success ? 'SUCCESS' : 'FAIL';
  safeLog.push(`[${timestamp}] LOGIN ip=${ip} status=${status} username=${sanitizeForLog(username)}`);

  if (success) {
    req.session.user = { username: record.username, role: record.role };
    return res.redirect('/dashboard');
  }
  res.status(401).send(loginSafeForm('Invalid credentials.', req.session.user || null));
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
    ${user.role === 'admin'
      ? '<p><a href="/logs">View vulnerable log</a> | <a href="/logs-safe">View safe log</a></p>'
      : ''}
  `, user));
});

app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  const user = req.session.user;
  res.send(page('Admin', `
    <h1>Admin</h1>
    <p>Only admins can see this. Hello, <strong>${user.username}</strong>.</p>
    <p><a href="/logs">View vulnerable log</a> | <a href="/logs-safe">View safe log</a></p>
  `, user));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user, ok: true });
});

// ---------- Log viewers (admin only) ----------
app.get('/logs', requireAuth, requireRole('admin'), (req, res) => {
  const lines = vulnLog.length;
  const content = vulnLog.join('\n') || '(no entries yet)';
  res.send(page('Login Logs (Vulnerable)', `
    <h1>Login Logs (Vulnerable)</h1>
    <p>Recorded by <a href="/login">/login</a>. Usernames are written directly into each entry — a newline anywhere in the username creates additional log lines that look identical to real entries.</p>
    <p><strong>${lines} log line${lines !== 1 ? 's' : ''}</strong> — each login attempt should produce exactly one line; extra lines indicate injection.</p>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(content)}</pre>
    <p><a href="/logs-safe">Compare with safe log &rarr;</a></p>
  `, req.session.user));
});

app.get('/logs-safe', requireAuth, requireRole('admin'), (req, res) => {
  const lines = safeLog.length;
  const content = safeLog.join('\n') || '(no entries yet)';
  res.send(page('Login Logs (Safe)', `
    <h1>Login Logs (Safe)</h1>
    <p>Recorded by <a href="/login-safe">/login-safe</a>. Newlines are encoded as <code>\\n</code> — each login attempt occupies exactly one line regardless of what the username contains.</p>
    <p><strong>${lines} log line${lines !== 1 ? 's' : ''}</strong></p>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(content)}</pre>
    <p><a href="/logs">Compare with vulnerable log &rarr;</a></p>
  `, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
