// app.js - HTTP Header Injection demonstration (Host header / password-reset poisoning)
// Dependencies: express, express-session, bcryptjs
// Install: npm install express express-session bcryptjs
//
// Attack: forge the Host (or X-Forwarded-Host) request header to make the server
// build a password reset URL pointing to an attacker-controlled domain.
// Demo the attack with curl — browsers set the Host header automatically and
// standard HTML forms cannot override request headers.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();

// ---------- App origin (safe version uses this instead of the Host header) ----------
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:3000';

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

// Derive the effective host from the request.
// Many applications trust X-Forwarded-Host when running behind a reverse proxy.
// An attacker who reaches the app directly can set this header to any value.
function effectiveHost(req) {
  return req.headers['x-forwarded-host'] || req.headers['host'] || 'localhost:3000';
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/forgot">Forgot Password</a> |
    <a href="/forgot-safe">Forgot Password (Safe)</a> |
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
  res.send(page('HTTP Header Injection', `
    <h1>HTTP Header Injection — Host Header Poisoning</h1>
    <p>HTTP header injection occurs when an application trusts a user-controllable HTTP request header and uses its value to make security-sensitive decisions. Unlike CRLF injection — which exploits line breaks to add new headers — this attack manipulates the <em>value</em> of a header the application already reads. The most dangerous variant is <strong>password reset poisoning</strong> via the <code>Host</code> header: the app uses the incoming <code>Host</code> to construct the reset link, and an attacker who can forge it makes the app generate a link pointing to the attacker's server.</p>
    <p>Many applications running behind a reverse proxy also trust <code>X-Forwarded-Host</code>, which proxies set to convey the original client-facing hostname. An attacker who reaches the application directly — bypassing the proxy — can set <code>X-Forwarded-Host</code> to any value they choose. This is the attack vector used in this example: the vulnerable <code>/forgot</code> endpoint reads <code>X-Forwarded-Host</code> (falling back to <code>Host</code>) and uses it to build the reset URL. The safe <code>/forgot-safe</code> endpoint ignores both headers entirely and uses a hardcoded <code>APP_ORIGIN</code> from server configuration.</p>

    <h2>How This App Works</h2>
    <p>The Forgot Password pages accept an email address and display the reset link that <em>would be sent</em> in an email to that address. In a real app this link is emailed to the user; here it is displayed so the attack is visible. The token is a random hex string generated server-side — the only thing the attacker poisons is the <em>host</em> in the URL. When the victim clicks the poisoned link their browser sends the token to the attacker's server, giving the attacker the ability to complete the reset.</p>

    <h2>The Attack</h2>
    <p>To forge the host from a browser you need a proxy (e.g. Burp Suite). From the terminal, use <code>curl</code>:</p>
    <pre>curl -s -X POST \\
  -H "X-Forwarded-Host: attacker.example.com" \\
  -d "email=victim@company.com" \\
  http://localhost:3000/forgot</pre>
    <p>The reset URL in the response will be <code>http://attacker.example.com/reset?token=...</code>. If a real email system sent that link, the victim's click would deliver their reset token to the attacker's server.</p>

    <h2>Try It</h2>
    <ul>
      <li>Visit <a href="/forgot">/forgot</a> in a browser — reset link uses <code>localhost:3000</code></li>
      <li>Run the <code>curl</code> command above — reset link uses <code>attacker.example.com</code></li>
      <li>Try <code>-H "Host: attacker.example.com"</code> (without X-Forwarded-Host) to show the fallback</li>
      <li>Visit <a href="/forgot-safe">/forgot-safe</a> — no matter what headers you send, the link always uses <code>${APP_ORIGIN}</code></li>
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
    <p><a href="/forgot">Forgot Password (vulnerable)</a> | <a href="/forgot-safe">Forgot Password (safe)</a></p>
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

// ---------- Forgot password (vulnerable) ----------
const forgotForm = (email, resetUrl, hostUsed, user) => page('Forgot Password', `
  <h1>Forgot Password</h1>
  <p>Enter your email address. A reset link will be sent to you.</p>
  <p><strong>Note:</strong> This page reads <code>X-Forwarded-Host</code> (falling back to <code>Host</code>)
     to build the reset URL. Use <code>curl</code> with a forged header to see the attack. The header
     currently seen by the server is shown below the result.</p>
  <form method="post" action="/forgot">
    <label for="email">Email address</label><br>
    <input id="email" name="email" type="email" value="${escapeHtml(email)}"
      placeholder="e.g. alice@example.com" style="width:360px" required><br><br>
    <button type="submit">Send reset link</button>
  </form>
  ${resetUrl ? `
    <h2>Reset link that would be emailed</h2>
    <p><a href="${escapeHtml(resetUrl)}">${escapeHtml(resetUrl)}</a></p>
    <p><strong>Host header used:</strong> <code>${escapeHtml(hostUsed)}</code></p>
    ${hostUsed !== 'localhost:3000' && !hostUsed.startsWith('localhost') ? `
      <p style="color:red"><strong>&#9888; Poisoned!</strong> This link points to <code>${escapeHtml(hostUsed)}</code>, not the real application. A victim clicking it would send their reset token to that host.</p>
    ` : ''}
  ` : ''}
`, user);

app.get('/forgot', (req, res) => {
  const host = effectiveHost(req);
  res.send(forgotForm('', '', host, req.session.user || null));
});

app.post('/forgot', (req, res) => {
  const { email = '' } = req.body || {};
  // VULNERABLE: the reset URL is built using the Host (or X-Forwarded-Host) header.
  // An attacker who can forge either header makes the app generate a reset link
  // pointing to an attacker-controlled domain. The victim's token is delivered there.
  const host = effectiveHost(req);
  const token = crypto.randomBytes(20).toString('hex');
  const resetUrl = `http://${host}/reset?token=${token}`;
  res.send(forgotForm(email, resetUrl, host, req.session.user || null));
});

// ---------- Forgot password (safe) ----------
const forgotSafeForm = (email, resetUrl, user) => page('Forgot Password (Safe)', `
  <h1>Forgot Password (Safe)</h1>
  <p>Enter your email address. A reset link will be sent to you.</p>
  <p><strong>Note:</strong> This page ignores <code>Host</code> and <code>X-Forwarded-Host</code> entirely
     and always builds the reset URL from the hardcoded <code>APP_ORIGIN</code> server configuration.</p>
  <form method="post" action="/forgot-safe">
    <label for="email">Email address</label><br>
    <input id="email" name="email" type="email" value="${escapeHtml(email)}"
      placeholder="e.g. alice@example.com" style="width:360px" required><br><br>
    <button type="submit">Send reset link</button>
  </form>
  ${resetUrl ? `
    <h2>Reset link that would be emailed</h2>
    <p><a href="${escapeHtml(resetUrl)}">${escapeHtml(resetUrl)}</a></p>
    <p><strong>Origin from config:</strong> <code>${escapeHtml(APP_ORIGIN)}</code></p>
  ` : ''}
`, user);

app.get('/forgot-safe', (req, res) => {
  res.send(forgotSafeForm('', '', req.session.user || null));
});

app.post('/forgot-safe', (req, res) => {
  const { email = '' } = req.body || {};
  // Safe: APP_ORIGIN comes from server configuration, never from request headers.
  // Forging Host or X-Forwarded-Host has no effect on the generated URL.
  const token = crypto.randomBytes(20).toString('hex');
  const resetUrl = `${APP_ORIGIN}/reset?token=${token}`;
  res.send(forgotSafeForm(email, resetUrl, req.session.user || null));
});

// ---------- Reset placeholder (so the link target exists) ----------
app.get('/reset', (req, res) => {
  const { token } = req.query;
  res.send(page('Password Reset', `
    <h1>Password Reset</h1>
    ${token
      ? `<p>Token received: <code>${escapeHtml(token)}</code></p>
         <p>In a real app this would verify the token and allow a password change.
            In an attack scenario this page would be hosted by the attacker, who
            now has the victim's valid reset token.</p>`
      : '<p>No token provided.</p>'}
  `, req.session.user || null));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
  console.log(`APP_ORIGIN: ${APP_ORIGIN}`);
});
