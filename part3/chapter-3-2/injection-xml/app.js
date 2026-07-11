// app.js - XML Injection demonstration
// Dependencies: express, express-session, bcryptjs, xmldom
// Install: npm install express express-session bcryptjs xmldom

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { DOMParser } = require('xmldom');

const app = express();

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

function escapeXml(s) {
  // XML character escaping per XML 1.0 §2.4. & must be replaced first.
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ---------- XML parse helper ----------
// Simulates a downstream system that reads the exported XML document.
// Returns an object of extracted field values, or null if the document is malformed.
function parseProfile(xml) {
  try {
    const doc = new DOMParser({
      errorHandler: { warning: () => {}, error: () => {}, fatalError: (e) => { throw e; } }
    }).parseFromString(xml, 'text/xml');

    if (!doc.documentElement) return null;

    const first = (tag) => {
      const els = doc.getElementsByTagName(tag);
      return els.length > 0 ? els[0].textContent : '(not found)';
    };

    return {
      username:    first('username'),
      displayName: first('displayName'),
      department:  first('department'),
      role:        first('role'),
    };
  } catch {
    return null;
  }
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/export">Export</a> |
    <a href="/export-safe">Export (Safe)</a> |
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

function parsedTable(parsed) {
  if (!parsed) return '<p style="color:red"><strong>Parse error:</strong> the generated XML is not well-formed. Injection may have broken the document structure.</p>';
  const roleStyle = parsed.role === 'admin' ? ' style="color:red;font-weight:bold"' : '';
  return `
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>Field</th><th>Value read by downstream parser</th></tr></thead>
      <tbody>
        <tr><td>username</td><td>${escapeHtml(parsed.username)}</td></tr>
        <tr><td>displayName</td><td>${escapeHtml(parsed.displayName)}</td></tr>
        <tr><td>department</td><td>${escapeHtml(parsed.department)}</td></tr>
        <tr><td>role</td><td${roleStyle}>${escapeHtml(parsed.role)}</td></tr>
      </tbody>
    </table>`;
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  const user = req.session.user;
  res.send(page('XML Injection', `
    <h1>XML Injection</h1>
    <p>XML injection occurs when user-supplied input is concatenated directly into an XML document without escaping XML metacharacters. The attacker injects closing tags and new elements to alter the document's structure. Any system that parses the resulting XML will read the attacker's injected values rather than the intended ones.</p>
    <p>This example uses a Profile Export feature. A logged-in user can set their display name and department; the app generates an XML document and simulates a downstream system that parses the XML to extract fields — including the user's role. By injecting <code>&lt;/displayName&gt;&lt;role&gt;admin&lt;/role&gt;&lt;displayName&gt;</code> into the display name field, an attacker inserts a second <code>&lt;role&gt;</code> element before the real one. Because <code>getElementsByTagName('role')[0]</code> returns the <em>first</em> match, the downstream parser reads <code>admin</code> instead of <code>user</code>.</p>

    <h2>How This App Works</h2>
    <p>The vulnerable export at <a href="/export">/export</a> builds the XML by string concatenation:</p>
    <pre>&lt;displayName&gt;\${displayName}&lt;/displayName&gt;</pre>
    <p>After generation the XML is parsed back by a simulated downstream system using <code>xmldom</code>, and both the raw XML and the parsed field values are shown side by side so you can see exactly how the injection changes what the parser reads. The safe export at <a href="/export-safe">/export-safe</a> passes every user-supplied value through <code>escapeXml()</code> before insertion.</p>

    <h2>The Attack</h2>
    <p>Log in as <code>bob</code> (role: <code>user</code>). On the <a href="/export">/export</a> page, enter the following as the display name:</p>
    <pre>Bob&lt;/displayName&gt;&lt;role&gt;admin&lt;/role&gt;&lt;displayName&gt;Bob</pre>
    <p>The generated XML becomes:</p>
    <pre>&lt;profile&gt;
  &lt;username&gt;bob&lt;/username&gt;
  &lt;displayName&gt;Bob&lt;/displayName&gt;&lt;role&gt;admin&lt;/role&gt;&lt;displayName&gt;Bob&lt;/displayName&gt;
  &lt;department&gt;...&lt;/department&gt;
  &lt;role&gt;user&lt;/role&gt;
&lt;/profile&gt;</pre>
    <p>The downstream parser's first <code>&lt;role&gt;</code> match is <code>admin</code>.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/export">/export</a> — enter a plain display name — XML and parsed values match</li>
      <li>Enter <code>Bob&lt;/displayName&gt;&lt;role&gt;admin&lt;/role&gt;&lt;displayName&gt;Bob</code> — role shown in red as <strong>admin</strong></li>
      <li>Enter <code>&lt;injected/&gt;</code> — adds an arbitrary element to the document</li>
      <li>Enter unclosed tags like <code>&lt;foo</code> — breaks the XML entirely, causing a parse error</li>
      <li>Visit <a href="/export-safe">/export-safe</a> and try the same payloads — tags are literal text, role stays <code>user</code></li>
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
    <p><a href="/export">Profile Export (vulnerable)</a> | <a href="/export-safe">Profile Export (safe)</a></p>
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

// ---------- Export (vulnerable) ----------
const exportForm = (values, xml, parsed, user) => page('Profile Export', `
  <h1>Profile Export</h1>
  <p>Set your display name and department. The app generates an XML profile document and shows what a downstream parser extracts from it.</p>
  <form method="post" action="/export">
    <label for="displayName">Display Name</label><br>
    <input id="displayName" name="displayName" value="${escapeHtml(values.displayName)}" placeholder="e.g. Alice Smith" style="width:400px"><br><br>
    <label for="department">Department</label><br>
    <input id="department" name="department" value="${escapeHtml(values.department)}" placeholder="e.g. Engineering" style="width:400px"><br><br>
    <button type="submit">Generate XML</button>
  </form>
  ${xml !== null ? `
    <h2>Generated XML</h2>
    <pre>${escapeHtml(xml)}</pre>
    <h2>Parsed by downstream system</h2>
    ${parsedTable(parsed)}
  ` : ''}
`, user);

app.get('/export', requireAuth, (req, res) => {
  res.send(exportForm({ displayName: '', department: '' }, null, null, req.session.user));
});

app.post('/export', requireAuth, (req, res) => {
  const { displayName = '', department = '' } = req.body || {};
  const { username, role } = req.session.user;

  // VULNERABLE: user input concatenated directly into the XML string.
  // An attacker can inject closing tags and new elements to alter the document structure.
  // Injecting </displayName><role>admin</role><displayName> inserts a role element
  // before the real one; getElementsByTagName('role')[0] then returns 'admin'.
  const xml =
`<?xml version="1.0" encoding="UTF-8"?>
<profile>
  <username>${username}</username>
  <displayName>${displayName}</displayName>
  <department>${department}</department>
  <role>${role}</role>
</profile>`;

  const parsed = parseProfile(xml);
  res.send(exportForm({ displayName, department }, xml, parsed, req.session.user));
});

// ---------- Export (safe) ----------
const exportSafeForm = (values, xml, parsed, user) => page('Profile Export (Safe)', `
  <h1>Profile Export (Safe)</h1>
  <p>Set your display name and department. All values are XML-escaped before insertion — injected tags are treated as literal text.</p>
  <form method="post" action="/export-safe">
    <label for="displayName">Display Name</label><br>
    <input id="displayName" name="displayName" value="${escapeHtml(values.displayName)}" placeholder="e.g. Alice Smith" style="width:400px"><br><br>
    <label for="department">Department</label><br>
    <input id="department" name="department" value="${escapeHtml(values.department)}" placeholder="e.g. Engineering" style="width:400px"><br><br>
    <button type="submit">Generate XML</button>
  </form>
  ${xml !== null ? `
    <h2>Generated XML</h2>
    <pre>${escapeHtml(xml)}</pre>
    <h2>Parsed by downstream system</h2>
    ${parsedTable(parsed)}
  ` : ''}
`, user);

app.get('/export-safe', requireAuth, (req, res) => {
  res.send(exportSafeForm({ displayName: '', department: '' }, null, null, req.session.user));
});

app.post('/export-safe', requireAuth, (req, res) => {
  const { displayName = '', department = '' } = req.body || {};
  const { username, role } = req.session.user;

  // Safe: all user-supplied values are XML-escaped before insertion.
  // < becomes &lt;, > becomes &gt; — injected tags are stored as text content, not markup.
  const xml =
`<?xml version="1.0" encoding="UTF-8"?>
<profile>
  <username>${escapeXml(username)}</username>
  <displayName>${escapeXml(displayName)}</displayName>
  <department>${escapeXml(department)}</department>
  <role>${escapeXml(role)}</role>
</profile>`;

  const parsed = parseProfile(xml);
  res.send(exportSafeForm({ displayName, department }, xml, parsed, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
