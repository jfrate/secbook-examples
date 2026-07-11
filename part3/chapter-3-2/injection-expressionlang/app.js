// app.js - Expression language injection demonstration
// Dependencies: express, express-session, bcryptjs, ejs
// Install: npm install express express-session bcryptjs ejs

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const ejs = require('ejs');

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
    <a href="/greeting">Greeting</a> |
    <a href="/greeting-safe">Greeting (Safe)</a> |
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
  res.send(page('Expression Language Injection', `
    <h1>Expression Language Injection</h1>
    <p>Expression Language (EL) injection occurs when user-supplied input is embedded into a template or expression string that is then evaluated by a templating or expression engine. The engine interprets the injected content as live expressions rather than plain text, allowing an attacker to execute arbitrary code within the engine's context.</p>
    <p>This is distinct from code injection (where the developer calls <code>eval()</code> explicitly) — here the developer is using a template engine as intended, but places user input in the wrong location: inside the template string itself rather than in the template data. The vulnerability is subtle and easy to introduce by accident.</p>

    <h2>How This App Works</h2>
    <p>This app uses <strong>EJS</strong>, a widely-used Node.js templating library that evaluates <code>&lt;%= expression %&gt;</code> tags embedded in template strings. A Greeting page at <a href="/greeting">/greeting</a> asks for the user's name and renders a personalised message. The vulnerable version constructs the EJS template by concatenating the user's name directly into the template string:</p>
    <pre>ejs.render(&#96;&lt;p&gt;Hello, \${name}!&lt;/p&gt;&#96;, {})</pre>
    <p>If the name contains EJS expression tags, the engine evaluates them. A safe version is available at <a href="/greeting-safe">/greeting-safe</a>, which keeps the template fixed and passes the name only as template data.</p>

    <h2>The Attack</h2>
    <p>Enter the following as your name in <a href="/greeting">/greeting</a>:</p>
    <pre>&lt;%= process.env.HOME %&gt;</pre>
    <p>EJS evaluates the tag and renders the server's home directory path into the page. To dump all environment variables:</p>
    <pre>&lt;%= JSON.stringify(process.env) %&gt;</pre>
    <p>Because the vulnerable route passes <code>require</code> as template data, full OS command execution is also possible:</p>
    <pre>&lt;%= require('child_process').execSync('whoami').toString() %&gt;</pre>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/greeting">/greeting</a> and enter <code>Alice</code> — renders <em>Hello, Alice!</em></li>
      <li>Enter <code>&lt;%= process.env.HOME %&gt;</code> — renders the server's home directory</li>
      <li>Enter <code>&lt;%= JSON.stringify(process.env) %&gt;</code> — dumps all server environment variables</li>
      <li>Enter <code>&lt;%= require('child_process').execSync('whoami').toString() %&gt;</code> — executes an OS command</li>
      <li>Visit <a href="/greeting-safe">/greeting-safe</a> — all payloads render as plain text, not evaluated</li>
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
    <p><a href="/greeting">Greeting (vulnerable)</a> | <a href="/greeting-safe">Greeting (safe)</a></p>
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

// ---------- Greeting (vulnerable) ----------
const greetingForm = (name, result, error, user) => page('Greeting', `
  <h1>Greeting</h1>
  <p>Enter your name to receive a personalised greeting.</p>
  <form method="post" action="/greeting">
    <label for="name">Name</label><br>
    <input id="name" name="name" placeholder="e.g. Alice" value="${name}" required style="width:300px"><br><br>
    <button type="submit">Greet me</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${result ? `<h2>Result</h2><p>${result}</p>` : ''}
`, user);

app.get('/greeting', requireAuth, (req, res) => {
  res.send(greetingForm('', '', '', req.session.user));
});

app.post('/greeting', requireAuth, (req, res) => {
  const { name } = req.body || {};
  let result = '';
  let error = '';
  try {
    // VULNERABLE: user input embedded directly into the EJS template string;
    // require is passed as template data, making it available to injected expressions
    result = ejs.render(`<p>Hello, ${name}!</p>`, { require });
  } catch (err) {
    error = err.message;
  }
  res.send(greetingForm(name, result, error, req.session.user));
});

// ---------- Greeting (safe) ----------
const greetingSafeForm = (name, result, user) => page('Greeting (Safe)', `
  <h1>Greeting (Safe)</h1>
  <p>Enter your name to receive a personalised greeting.</p>
  <form method="post" action="/greeting-safe">
    <label for="name">Name</label><br>
    <input id="name" name="name" placeholder="e.g. Alice" value="${name}" required style="width:300px"><br><br>
    <button type="submit">Greet me</button>
  </form>
  ${result ? `<h2>Result</h2><p>${result}</p>` : ''}
`, user);

app.get('/greeting-safe', requireAuth, (req, res) => {
  res.send(greetingSafeForm('', '', req.session.user));
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.post('/greeting-safe', requireAuth, (req, res) => {
  const { name } = req.body || {};
  // Safe: name is HTML-escaped before insertion — EJS tags become inert plain text
  const result = `<p>Hello, ${escapeHtml(name)}!</p>`;
  res.send(greetingSafeForm(name, result, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
