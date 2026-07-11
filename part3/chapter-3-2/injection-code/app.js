// app.js - Code injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

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
    <a href="/evaluator">Evaluator</a> |
    <a href="/evaluator-safe">Evaluator (Safe)</a> |
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
  res.send(page('Code Injection', `
    <h1>Code Injection</h1>
    <p>Code injection occurs when user-supplied input is executed directly by the application's runtime as program code. Unlike command injection — which abuses the operating system shell — code injection targets the language runtime itself. In Node.js, the classic vector is <code>eval()</code>, which accepts a string and executes it as live JavaScript with full access to the server's runtime, modules, environment variables, and file system.</p>
    <p>The impact is severe: an attacker can read secrets, exfiltrate data, spawn processes, or take full control of the server — all without ever touching the OS shell directly.</p>

    <h2>How This App Works</h2>
    <p>This app adds a Math Expression Evaluator available to logged-in users at <a href="/evaluator">/evaluator</a>. It accepts an expression such as <code>2 * (3 + 4)</code> and returns the result. The vulnerable version passes the input directly to <code>eval()</code>:</p>
    <pre>eval(expression)</pre>
    <p>A safe version is available at <a href="/evaluator-safe">/evaluator-safe</a>, which validates input against a strict allowlist before evaluating.</p>

    <h2>The Attack</h2>
    <p>Enter the following as the expression in <a href="/evaluator">/evaluator</a>:</p>
    <pre>require('child_process').execSync('whoami').toString()</pre>
    <p>Node.js executes this as live JavaScript. The <code>require</code> call loads the <code>child_process</code> module, <code>execSync</code> runs an OS command, and the result is returned in the response. Other payloads include:</p>
    <ul>
      <li><code>JSON.stringify(process.env)</code> — dumps all server environment variables</li>
      <li><code>require('fs').readdirSync('.').toString()</code> — lists files in the working directory</li>
    </ul>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/evaluator">/evaluator</a> and enter <code>2 * (3 + 4)</code> — returns <code>14</code></li>
      <li>Enter <code>require('child_process').execSync('whoami').toString()</code> — executes an OS command via the JS runtime</li>
      <li>Visit <a href="/evaluator-safe">/evaluator-safe</a> — the same payloads are rejected by input validation</li>
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
    <p><a href="/evaluator">Math Evaluator (vulnerable)</a> | <a href="/evaluator-safe">Math Evaluator (safe)</a></p>
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

// ---------- Evaluator (vulnerable) ----------
const evaluatorForm = (expression, result, user) => page('Math Evaluator', `
  <h1>Math Evaluator</h1>
  <p>Enter a math expression to evaluate.</p>
  <form method="post" action="/evaluator">
    <label for="expression">Expression</label><br>
    <input id="expression" name="expression" placeholder="e.g. 2 * (3 + 4)" value="${expression}" required style="width:400px"><br><br>
    <button type="submit">Evaluate</button>
  </form>
  ${result !== null ? `<h2>Result</h2><pre>${result}</pre>` : ''}
`, user);

app.get('/evaluator', requireAuth, (req, res) => {
  res.send(evaluatorForm('', null, req.session.user));
});

app.post('/evaluator', requireAuth, (req, res) => {
  const { expression } = req.body || {};
  let result;
  try {
    // VULNERABLE: user input passed directly to eval()
    result = eval(expression);
  } catch (err) {
    result = `Error: ${err.message}`;
  }
  res.send(evaluatorForm(expression, String(result), req.session.user));
});

// ---------- Evaluator (safe) ----------
const MATH_PATTERN = /^[\d\s\+\-\*\/\(\)\.]+$/;

const evaluatorSafeForm = (expression, result, error, user) => page('Math Evaluator (Safe)', `
  <h1>Math Evaluator (Safe)</h1>
  <p>Enter a math expression to evaluate.</p>
  <form method="post" action="/evaluator-safe">
    <label for="expression">Expression</label><br>
    <input id="expression" name="expression" placeholder="e.g. 2 * (3 + 4)" value="${expression}" required style="width:400px"><br><br>
    <button type="submit">Evaluate</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${result !== null ? `<h2>Result</h2><pre>${result}</pre>` : ''}
`, user);

app.get('/evaluator-safe', requireAuth, (req, res) => {
  res.send(evaluatorSafeForm('', null, '', req.session.user));
});

app.post('/evaluator-safe', requireAuth, (req, res) => {
  const { expression } = req.body || {};

  if (!MATH_PATTERN.test(expression)) {
    return res.send(evaluatorSafeForm(expression, null, 'Invalid expression. Only numbers and operators ( + - * / ( ) . ) are allowed.', req.session.user));
  }

  let result;
  try {
    result = eval(expression);
  } catch (err) {
    result = `Error: ${err.message}`;
  }
  res.send(evaluatorSafeForm(expression, String(result), '', req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
