// app.js - Server-Side Template Injection (SSTI) demonstration
// Dependencies: express, express-session, bcryptjs, pug
// Install: npm install express express-session bcryptjs pug

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const pug = require('pug');

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
    <a href="/profile">Profile</a> |
    <a href="/profile-safe">Profile (Safe)</a> |
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
  res.send(page('Server-Side Template Injection', `
    <h1>Server-Side Template Injection (SSTI)</h1>
    <p>Server-Side Template Injection occurs when user-supplied input is passed directly to a template engine as the template itself, rather than as data to be rendered into a fixed template. The engine compiles and executes the input, giving the attacker full access to the engine's capabilities — and through it, the underlying runtime.</p>
    <p>This is distinct from Expression Language injection, where the developer accidentally embedded user input inside a template string using JavaScript string interpolation. In SSTI the mistake is more direct: the developer calls <code>pug.render(userInput)</code>, making the user's input the template itself.</p>

    <h2>How This App Works</h2>
    <p>This app uses <strong>Pug</strong>, a widely-used Node.js template engine with an indentation-based syntax. A Profile page at <a href="/profile">/profile</a> lets logged-in users enter a greeting template. The vulnerable version compiles and renders the input directly:</p>
    <pre>pug.render(template)</pre>
    <p>Pug's <code>-</code> prefix executes arbitrary JavaScript, and <code>p=</code> renders a JavaScript expression as a paragraph. A safe version is available at <a href="/profile-safe">/profile-safe</a>, which keeps the template fixed and passes the name only as data.</p>

    <h2>The Attack</h2>
    <p>Enter the following in the template textarea at <a href="/profile">/profile</a>:</p>
    <pre>p= process.env.HOME</pre>
    <p>Pug evaluates <code>process.env.HOME</code> as a JavaScript expression and renders the server's home directory. To dump all environment variables:</p>
    <pre>p= JSON.stringify(process.env)</pre>
    <p>For OS command execution using Pug's arbitrary JavaScript execution:</p>
    <pre>- var x = process.mainModule.require('child_process').execSync('whoami').toString()
p= x</pre>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/profile">/profile</a> and enter <code>p Hello, World!</code> — normal Pug output</li>
      <li>Enter <code>p= process.env.HOME</code> — renders the server's home directory</li>
      <li>Enter <code>p= JSON.stringify(process.env)</code> — dumps all server environment variables</li>
      <li>Enter the two-line payload above — executes an OS command via the template engine</li>
      <li>Visit <a href="/profile-safe">/profile-safe</a> — input is treated as plain text, not a template</li>
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
    <p><a href="/profile">Profile (vulnerable)</a> | <a href="/profile-safe">Profile (safe)</a></p>
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

// ---------- Profile (vulnerable) ----------
const profileForm = (template, result, error, user) => page('Profile', `
  <h1>Profile</h1>
  <p>Enter a Pug greeting template to render.</p>
  <form method="post" action="/profile">
    <label for="template">Template</label><br>
    <textarea id="template" name="template" rows="5" style="width:500px;font-family:monospace">${template}</textarea><br><br>
    <button type="submit">Render</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${result ? `<h2>Result</h2><div>${result}</div>` : ''}
`, user);

app.get('/profile', requireAuth, (req, res) => {
  res.send(profileForm('p Hello, World!', '', '', req.session.user));
});

app.post('/profile', requireAuth, (req, res) => {
  const { template } = req.body || {};
  let result = '';
  let error = '';
  try {
    // VULNERABLE: user input compiled and rendered directly as a Pug template
    result = pug.render(template);
  } catch (err) {
    error = err.message;
  }
  res.send(profileForm(template, result, error, req.session.user));
});

// ---------- Profile (safe) ----------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const profileSafeForm = (name, result, user) => page('Profile (Safe)', `
  <h1>Profile (Safe)</h1>
  <p>Enter your name to render a greeting.</p>
  <form method="post" action="/profile-safe">
    <label for="name">Name</label><br>
    <input id="name" name="name" placeholder="e.g. Alice" value="${escapeHtml(name)}" required style="width:300px"><br><br>
    <button type="submit">Render</button>
  </form>
  ${result ? `<h2>Result</h2><div>${result}</div>` : ''}
`, user);

app.get('/profile-safe', requireAuth, (req, res) => {
  res.send(profileSafeForm('', '', req.session.user));
});

app.post('/profile-safe', requireAuth, (req, res) => {
  const { name } = req.body || {};
  // Safe: template is fixed; user input is passed only as data, never compiled as a template
  const result = pug.render('p Hello, #{name}!', { name });
  res.send(profileSafeForm(name, result, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
