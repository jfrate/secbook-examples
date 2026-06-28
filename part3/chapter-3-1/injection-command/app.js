// app.js - Command injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { exec, execFile } = require('child_process');

const app = express();

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

// ---------- Minimal HTML templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/diagnostics">Diagnostics</a> |
    <a href="/diagnostics-safe">Diagnostics (Safe)</a> |
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
  res.send(page('Command Injection', `
    <h1>Command Injection</h1>
    <p>Command injection is a vulnerability that occurs when an application constructs and executes operating system commands using untrusted user input without proper validation or sanitization. An attacker can inject shell metacharacters — such as <code>;</code>, <code>&&</code>, or <code>|</code> — to append or chain additional commands, causing the host system to execute arbitrary code in the context of the application's process.</p>
    <p>Unlike code injection, which targets the application's runtime, command injection abuses the underlying operating system shell. The impact can range from reading sensitive files to full remote code execution, depending on the privileges of the running process.</p>

    <h2>How This App Works</h2>
    <p>This app adds a Network Diagnostics feature available to logged-in users at <a href="/diagnostics">/diagnostics</a>. It accepts a hostname and runs <code>ping</code> against it, returning the output. The vulnerable version passes the hostname directly into a shell command string:</p>
    <pre>exec(\`ping -c 1 \${host}\`, ...)</pre>
    <p>A safe version is available at <a href="/diagnostics-safe">/diagnostics-safe</a>, which uses <code>execFile</code> and strict input validation.</p>

    <h2>The Attack</h2>
    <p>Enter the following as the hostname in <a href="/diagnostics">/diagnostics</a>:</p>
    <pre>google.com; whoami</pre>
    <p>This causes the app to execute:</p>
    <pre>ping -c 1 google.com; whoami</pre>
    <p>The shell runs both commands. The output of <code>whoami</code> — the OS user the app is running as — is returned in the response alongside the ping output. Other payloads such as <code>google.com && ls -la</code> or <code>google.com | cat /etc/passwd</code> work the same way.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/diagnostics">/diagnostics</a> and enter <code>google.com</code> — normal output</li>
      <li>Enter <code>google.com; whoami</code> — injected command runs alongside ping</li>
      <li>Visit <a href="/diagnostics-safe">/diagnostics-safe</a> — same input is rejected</li>
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
    <p><a href="/diagnostics">Network Diagnostics (vulnerable)</a> | <a href="/diagnostics-safe">Network Diagnostics (safe)</a></p>
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

// ---------- Diagnostics (vulnerable) ----------
const diagnosticsForm = (output, user) => page('Network Diagnostics', `
  <h1>Network Diagnostics</h1>
  <p>Enter a hostname or IP address to ping.</p>
  <form method="post" action="/diagnostics">
    <label for="host">Hostname</label><br>
    <input id="host" name="host" placeholder="e.g. google.com" required style="width:300px"><br><br>
    <button type="submit">Ping</button>
  </form>
  ${output ? `<h2>Output</h2><pre>${output}</pre>` : ''}
`, user);

app.get('/diagnostics', requireAuth, (req, res) => {
  res.send(diagnosticsForm('', req.session.user));
});

app.post('/diagnostics', requireAuth, (req, res) => {
  const { host } = req.body || {};

  // VULNERABLE: user input concatenated directly into shell command
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    const output = stdout || stderr || err?.message || '';
    res.send(diagnosticsForm(output, req.session.user));
  });
});

// ---------- Diagnostics (safe) ----------
const HOSTNAME_PATTERN = /^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$|^(?:\d{1,3}\.){3}\d{1,3}$/;

const diagnosticsSafeForm = (output, error, user) => page('Network Diagnostics (Safe)', `
  <h1>Network Diagnostics (Safe)</h1>
  <p>Enter a hostname or IP address to ping.</p>
  <form method="post" action="/diagnostics-safe">
    <label for="host">Hostname</label><br>
    <input id="host" name="host" placeholder="e.g. google.com" required style="width:300px"><br><br>
    <button type="submit">Ping</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${output ? `<h2>Output</h2><pre>${output}</pre>` : ''}
`, user);

app.get('/diagnostics-safe', requireAuth, (req, res) => {
  res.send(diagnosticsSafeForm('', '', req.session.user));
});

app.post('/diagnostics-safe', requireAuth, (req, res) => {
  const { host } = req.body || {};

  if (!HOSTNAME_PATTERN.test(host)) {
    return res.send(diagnosticsSafeForm('', 'Invalid hostname. Only hostnames and IPv4 addresses are allowed.', req.session.user));
  }

  // Safe: execFile does not invoke a shell; arguments are passed directly to the binary
  execFile('ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout, stderr) => {
    const output = stdout || stderr || err?.message || '';
    res.send(diagnosticsSafeForm(output, '', req.session.user));
  });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
