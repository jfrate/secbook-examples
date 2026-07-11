// app.js - CRLF Injection / HTTP Response Splitting demonstration
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
//
// The vulnerable /go endpoint writes a raw HTTP response directly to the socket,
// bypassing Node.js's built-in CRLF protection in res.setHeader(). This is the
// realistic code pattern used in low-level HTTP proxies, custom servers, or
// applications that construct Location headers by string concatenation.

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

// Strip CR and LF — the essential CRLF mitigation for header values.
function stripCrlf(s) {
  return String(s).replace(/[\r\n]/g, '');
}

// ---------- Header preview helper ----------
// Takes a location value (already URL-decoded) and returns HTML showing
// the raw HTTP response line by line. Lines that were injected via CRLF
// are wrapped in a red span.
function headerPreviewHtml(location) {
  const parts = location.split(/\r\n|\r|\n/);
  let html = escapeHtml('HTTP/1.1 302 Found') + '\n';
  html += escapeHtml('Location: ' + parts[0]) + '\n';
  for (let i = 1; i < parts.length; i++) {
    if (parts[i]) {
      html += `<span style="color:red;font-weight:bold">${escapeHtml(parts[i])} ← injected</span>\n`;
    }
  }
  html += escapeHtml('Content-Length: 0') + '\n';
  html += '\n';
  return html;
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/redirect">Redirect</a> |
    <a href="/redirect-safe">Redirect (Safe)</a> |
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
  res.send(page('CRLF Injection', `
    <h1>CRLF Injection / HTTP Response Splitting</h1>
    <p>HTTP headers are separated by CRLF sequences (<code>\r\n</code>, or URL-encoded as <code>%0d%0a</code>). When user-supplied input is placed into a response header without stripping these characters, an attacker can inject additional headers into the response. A blank line (<code>\r\n\r\n</code>) terminates the header block entirely, allowing the attacker to inject a fake HTTP body — a technique called HTTP Response Splitting.</p>
    <p>This example demonstrates header injection via a post-login redirect. A common pattern is to redirect users back to where they were going: <code>/go?next=/dashboard</code>. The vulnerable endpoint constructs the <code>Location</code> header by concatenating <code>next</code> directly into a raw HTTP response written to the socket. Because query-string values are URL-decoded before the application sees them, sending <code>next=http://example.com%0d%0aSet-Cookie:%20session%3Dhijacked</code> delivers a real <code>\r\n</code> to the server — splitting the header. The safe endpoint strips all CR and LF characters from the value before use.</p>

    <h2>How This App Works</h2>
    <p>The <a href="/redirect">/redirect</a> form shows a preview of what the raw HTTP response headers would look like for a given redirect URL — injected headers are highlighted in red. The <code><a href="/go">/go</a></code> endpoint (for <code>curl</code> testing) actually writes those bytes to the socket using <code>res.socket.write()</code>, bypassing Node.js's built-in header validation. The safe pair — <a href="/redirect-safe">/redirect-safe</a> and <a href="/go-safe">/go-safe</a> — strips CR/LF before use.</p>

    <h2>The Attack</h2>
    <p>Visit the <a href="/redirect">/redirect</a> form and paste this as the redirect URL:</p>
    <pre>http://example.com%0d%0aSet-Cookie:%20session%3Dhijacked%3bpath%3d%2f</pre>
    <p>URL-decoded, this is <code>http://example.com\r\nSet-Cookie: session=hijacked;path=/</code>. The raw HTTP response becomes:</p>
    <pre>HTTP/1.1 302 Found
Location: http://example.com
Set-Cookie: session=hijacked;path=/    ← injected
Content-Length: 0</pre>
    <p>Any browser following this redirect receives the injected <code>Set-Cookie</code> header and stores the attacker-controlled cookie. With a double CRLF (<code>%0d%0a%0d%0a</code>), the attacker can inject an entirely fake HTTP body — a technique used for cache poisoning and reflected XSS via CRLF.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/redirect">/redirect</a> — enter <code>/dashboard</code> — preview shows a clean redirect</li>
      <li>Enter <code>http://example.com%0d%0aSet-Cookie:%20session%3Dhijacked%3bpath%3d%2f</code> — preview shows the injected <code>Set-Cookie</code> header in red</li>
      <li>Enter <code>http://example.com%0d%0a%0d%0a&lt;h1&gt;Fake+Page&lt;/h1&gt;</code> — double CRLF terminates headers and injects a fake body</li>
      <li>Run <code>curl -v 'http://localhost:3000/go?next=http%3A%2F%2Fexample.com%0d%0aSet-Cookie%3A%20session%3Dhijacked'</code> to see the actual raw HTTP response</li>
      <li>Visit <a href="/redirect-safe">/redirect-safe</a> — same payloads — all CR/LF stripped, single clean <code>Location</code> header</li>
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
    <p><a href="/redirect">Redirect preview (vulnerable)</a> | <a href="/redirect-safe">Redirect preview (safe)</a></p>
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

// ---------- Redirect preview (vulnerable) ----------
const redirectForm = (next, previewHtml, user) => page('Redirect', `
  <h1>Redirect Service</h1>
  <p>Enter a redirect URL. The preview shows the raw HTTP 302 response that would be sent. Paste a URL-encoded value (e.g. containing <code>%0d%0a</code>) — it is decoded before being placed in the header, just as a real server would receive it from a query string.</p>
  <form method="post" action="/redirect">
    <label for="next">Redirect URL</label><br>
    <input id="next" name="next" value="${escapeHtml(next)}" placeholder="e.g. /dashboard or http://example.com%0d%0aSet-Cookie:%20x%3d1" style="width:600px"><br><br>
    <button type="submit">Preview headers</button>
  </form>
  ${previewHtml !== null ? `
    <h2>Raw HTTP response</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${previewHtml}</pre>
  ` : ''}
`, user);

app.get('/redirect', requireAuth, (req, res) => {
  res.send(redirectForm('', null, req.session.user));
});

app.post('/redirect', requireAuth, (req, res) => {
  const { next = '' } = req.body || {};
  // URL-decode the input: query strings are decoded before the app sees them,
  // so %0d%0a arrives as a real \r\n. Reproduce that here for the preview.
  let decoded = next;
  try { decoded = decodeURIComponent(next); } catch { /* leave as-is */ }

  // VULNERABLE: the decoded value is placed directly into the header string.
  // A \r\n in the value splits the header block and injects a new header line.
  const preview = headerPreviewHtml(decoded);
  res.send(redirectForm(next, preview, req.session.user));
});

// ---------- Redirect preview (safe) ----------
const redirectSafeForm = (next, previewHtml, user) => page('Redirect (Safe)', `
  <h1>Redirect Service (Safe)</h1>
  <p>Enter a redirect URL. CR and LF characters are stripped before the value is placed in the header — injection is not possible.</p>
  <form method="post" action="/redirect-safe">
    <label for="next">Redirect URL</label><br>
    <input id="next" name="next" value="${escapeHtml(next)}" placeholder="e.g. /dashboard or http://example.com%0d%0aSet-Cookie:%20x%3d1" style="width:600px"><br><br>
    <button type="submit">Preview headers</button>
  </form>
  ${previewHtml !== null ? `
    <h2>Raw HTTP response</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${previewHtml}</pre>
  ` : ''}
`, user);

app.get('/redirect-safe', requireAuth, (req, res) => {
  res.send(redirectSafeForm('', null, req.session.user));
});

app.post('/redirect-safe', requireAuth, (req, res) => {
  const { next = '' } = req.body || {};
  let decoded = next;
  try { decoded = decodeURIComponent(next); } catch { /* leave as-is */ }

  // Safe: strip all CR and LF characters before use.
  const safe = stripCrlf(decoded);
  const preview = headerPreviewHtml(safe);
  res.send(redirectSafeForm(next, preview, req.session.user));
});

// ---------- Live redirect (vulnerable) — use with curl ----------
// Writes the raw HTTP response to the socket, bypassing Node.js's built-in
// header validation. req.query.next is already URL-decoded by Express.
app.get('/go', requireAuth, (req, res) => {
  const next = req.query.next || '/';
  // VULNERABLE: next is written directly into the raw HTTP response.
  // If next contains \r\n (from %0d%0a in the URL), additional headers are injected.
  const raw = `HTTP/1.1 302 Found\r\nLocation: ${next}\r\nContent-Length: 0\r\n\r\n`;
  res.socket.write(raw);
  res.socket.end();
});

// ---------- Live redirect (safe) — use with curl ----------
app.get('/go-safe', requireAuth, (req, res) => {
  const next = req.query.next || '/';
  // Safe: CR and LF stripped; res.redirect() also validates the header value.
  res.redirect(302, stripCrlf(next));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
