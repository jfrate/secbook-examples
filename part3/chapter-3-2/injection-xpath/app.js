// app.js - XPath injection demonstration
// Dependencies: express, express-session, xpath, xmldom
// Install: npm install express express-session xpath xmldom

const express = require('express');
const session = require('express-session');
const xpath = require('xpath');
const { DOMParser } = require('xmldom');
const fs = require('fs');

const app = express();

// ---------- Load XML user store ----------
const xmlData = fs.readFileSync('./users.xml', 'utf8');
const doc = new DOMParser().parseFromString(xmlData);

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
  res.send(page('XPath Injection', `
    <h1>XPath Injection</h1>
    <p>XPath injection is an attack technique where user-supplied input is embedded into an XPath query without sanitization, allowing an attacker to manipulate the query's logic. XPath is used to navigate and query XML documents, and like SQL injection, unsanitized input can cause unintended data to be returned or authentication to be bypassed entirely.</p>

    <h2>How This App Works</h2>
    <p>User credentials are stored in <code>users.xml</code>. On login, the app builds this XPath query using the submitted username and password:</p>
    <pre>//users/user[username/text()='<em>USERNAME</em>' and password/text()='<em>PASSWORD</em>']</pre>
    <p>If the query returns a node, the user is logged in as that user.</p>

    <h2>The Attack</h2>
    <p>Enter the following as the username (any password):</p>
    <pre>' or '1'='1' or 'a'='b</pre>
    <p>This transforms the query into:</p>
    <pre>//users/user[username/text()='' or '1'='1' or 'a'='b' and password/text()='anything']</pre>
    <p>XPath evaluates <code>and</code> before <code>or</code>, so the three <code>or</code> terms are: <code>username=''</code> (false), <code>'1'='1'</code> (always true), and <code>'a'='b' and password='anything'</code> (false). The second term short-circuits the whole predicate to true, so the query returns the first user in the XML document — granting login as <strong>alice (admin)</strong> with no valid credentials.</p>

    <h2>Try It</h2>
    <ul>
      <li>Normal login: <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Injection bypass: username <code>' or '1'='1' or 'a'='b</code>, any password</li>
    </ul>
    <p><a href="/login">Go to login</a></p>

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

  // VULNERABLE: user input concatenated directly into XPath query
  const expr = `//users/user[username/text()='${username}' and password/text()='${password}']`;
  const nodes = xpath.select(expr, doc);

  if (!nodes || nodes.length === 0) {
    return res.status(401).send(page('Login failed', '<p>Invalid credentials.</p><p><a href="/login">Try again</a></p>'));
  }

  const node = nodes[0];
  const uname = xpath.select('string(username)', node);
  const role = xpath.select('string(role)', node);
  req.session.user = { username: uname, role: role };
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

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
