// app.js - LDAP injection demonstration
// Dependencies: express, express-session, bcryptjs, ldapjs
// Install: npm install express express-session bcryptjs ldapjs
// No external LDAP server required — an in-process ldapjs server is started automatically.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const ldap = require('ldapjs');

const app = express();

// ---------- In-process LDAP server ----------
// Runs on port 1389 within the same Node process. Stores four users in memory.
// The Express app connects to it as an LDAP client on every search.

const LDAP_PORT = 1389;
const LDAP_BASE = 'ou=users,dc=example,dc=com';

const directory = {
  'uid=alice,ou=users,dc=example,dc=com': { uid: 'alice', role: 'admin', favoriteIceCream: 'Vanilla'    },
  'uid=bob,ou=users,dc=example,dc=com':   { uid: 'bob',   role: 'user',  favoriteIceCream: 'Chocolate'  },
  'uid=carol,ou=users,dc=example,dc=com': { uid: 'carol', role: 'user',  favoriteIceCream: 'Strawberry' },
  'uid=dan,ou=users,dc=example,dc=com':   { uid: 'dan',   role: 'user',  favoriteIceCream: 'Peach'      },
};

const ldapServer = ldap.createServer();

ldapServer.bind('dc=example,dc=com', (req, res, next) => {
  res.end();
  return next();
});

ldapServer.search(LDAP_BASE, (req, res, next) => {
  Object.entries(directory).forEach(([dn, attrs]) => {
    if (req.filter.matches(attrs)) {
      res.send({ dn, attributes: attrs });
    }
  });
  res.end();
  return next();
});

ldapServer.listen(LDAP_PORT, '127.0.0.1', () => {
  console.log(`LDAP server listening on ldap://127.0.0.1:${LDAP_PORT}`);
});

// ---------- LDAP client helper ----------
function ldapSearch(filterStr) {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({ url: `ldap://127.0.0.1:${LDAP_PORT}` });
    const results = [];

    client.on('error', err => reject(err));

    client.search(LDAP_BASE, { filter: filterStr, scope: 'sub' }, (err, searchRes) => {
      if (err) { client.destroy(); return reject(err); }

      searchRes.on('searchEntry', entry => results.push(entry.object));
      searchRes.on('error',       err   => { client.destroy(); reject(err); });
      searchRes.on('end',         ()    => { client.unbind(() => client.destroy()); resolve(results); });
    });
  });
}

// ---------- LDAP escape ----------
// Escapes all LDAP filter metacharacters per RFC 4515.
// Backslash must be escaped first to avoid double-escaping.
function escapeLdap(str) {
  return str
    .replace(/\\/g, '\\5c')
    .replace(/\*/g,  '\\2a')
    .replace(/\(/g,  '\\28')
    .replace(/\)/g,  '\\29')
    .replace(/\0/g,  '\\00');
}

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

function val(v) {
  return Array.isArray(v) ? v[0] : (v ?? '');
}

function resultsTable(rows) {
  if (!rows.length) return '<p>No results found.</p>';
  return `
    <table border="1" cellpadding="6" cellspacing="0">
      <thead><tr><th>UID</th><th>Role</th><th>Favourite Ice Cream</th></tr></thead>
      <tbody>
        ${rows.map(r => `<tr><td>${val(r.uid)}</td><td>${val(r.role)}</td><td>${val(r.favoriteIceCream)}</td></tr>`).join('')}
      </tbody>
    </table>`;
}

// ---------- Templates ----------
const nav = (user) => `
  <nav>
    <a href="/">Home</a> |
    <a href="/dashboard">Dashboard</a> |
    <a href="/admin">Admin</a> |
    <a href="/search">Search</a> |
    <a href="/search-safe">Search (Safe)</a> |
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
  res.send(page('LDAP Injection', `
    <h1>LDAP Injection</h1>
    <p>LDAP (Lightweight Directory Access Protocol) is widely used for directory services — user authentication, group membership, and attribute lookups in systems like Active Directory. LDAP queries use a filter syntax enclosed in parentheses, e.g. <code>(uid=alice)</code>. LDAP injection occurs when user-supplied input is concatenated directly into a filter string without escaping. An attacker can inject LDAP metacharacters — particularly the wildcard <code>*</code> — to change the query's meaning, retrieve unintended records, or bypass authentication.</p>
    <p>This example uses <strong>ldapjs</strong> to run a self-contained in-process LDAP server (no external directory server required). A User Search feature at <a href="/search">/search</a> looks up users by UID. The vulnerable version concatenates the search term directly into the filter string. Entering <code>*</code> changes the filter from <code>(uid=alice)</code> to <code>(uid=*)</code> — an LDAP presence filter that matches every entry with a <code>uid</code> attribute, returning all four users. The safe version at <a href="/search-safe">/search-safe</a> escapes LDAP metacharacters before inserting input into the filter.</p>

    <h2>How This App Works</h2>
    <p>An in-process ldapjs server holds four directory entries: Alice, Bob, Carol, and Dan. The vulnerable <a href="/search">/search</a> route builds the filter by string concatenation:</p>
    <pre>const filter = `(uid=${uid})`;</pre>
    <p>The constructed filter string is shown in the results section so you can see exactly what was sent to the directory. The safe version wraps the input in an <code>escapeLdap()</code> call that replaces all LDAP metacharacters with their RFC 4515 hex escape sequences before inserting into the filter.</p>

    <h2>The Attack</h2>
    <p>On the <a href="/search">/search</a> page, enter <code>*</code> as the search term:</p>
    <ul>
      <li>Filter becomes: <code>(uid=*)</code></li>
      <li>LDAP interprets this as a <em>presence filter</em> — "return any entry that has a uid attribute"</li>
      <li>All four directory entries are returned</li>
    </ul>
    <p>Other useful payloads:</p>
    <ul>
      <li><code>a*</code> — substring filter; returns all users whose uid starts with "a" (alice)</li>
      <li><code>*)(|(uid=*</code> — attempts to inject an always-true OR clause into the filter</li>
    </ul>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/search">/search</a> — enter <code>alice</code> — returns only Alice, filter shown as <code>(uid=alice)</code></li>
      <li>Enter <code>*</code> — all four users returned, filter shown as <code>(uid=*)</code></li>
      <li>Enter <code>a*</code> — only Alice returned (substring match)</li>
      <li>Visit <a href="/search-safe">/search-safe</a> — enter <code>*</code> — zero results; filter shown as <code>(uid=\\2a)</code>, looking for a user literally named <code>*</code></li>
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
    <p><a href="/search">User Search (vulnerable)</a> | <a href="/search-safe">User Search (safe)</a></p>
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

// ---------- Search (vulnerable) ----------
const searchForm = (term, filter, rows, error, user) => page('User Search', `
  <h1>User Search</h1>
  <p>Search for a directory user by UID.</p>
  <form method="post" action="/search">
    <label for="uid">UID</label><br>
    <input id="uid" name="uid" value="${term}" placeholder="e.g. alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${filter  ? `<p><strong>LDAP filter sent:</strong> <code>${filter}</code></p>` : ''}
  ${error   ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search', requireAuth, (req, res) => {
  res.send(searchForm('', '', null, '', req.session.user));
});

app.post('/search', requireAuth, async (req, res) => {
  const { uid } = req.body || {};
  // VULNERABLE: user input concatenated directly into the LDAP filter string.
  // Entering '*' changes (uid=alice) to (uid=*), a presence filter matching all entries.
  const filter = `(uid=${uid})`;
  try {
    const users = await ldapSearch(filter);
    res.send(searchForm(uid, filter, users, '', req.session.user));
  } catch (err) {
    res.send(searchForm(uid, filter, null, err.message, req.session.user));
  }
});

// ---------- Search (safe) ----------
const searchSafeForm = (term, filter, rows, error, user) => page('User Search (Safe)', `
  <h1>User Search (Safe)</h1>
  <p>Search for a directory user by UID.</p>
  <form method="post" action="/search-safe">
    <label for="uid">UID</label><br>
    <input id="uid" name="uid" value="${term}" placeholder="e.g. alice" style="width:300px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${filter  ? `<p><strong>LDAP filter sent:</strong> <code>${filter}</code></p>` : ''}
  ${error   ? `<p style="color:red"><strong>Error:</strong> ${error}</p>` : ''}
  ${rows !== null ? `<h2>Results</h2>${resultsTable(rows)}` : ''}
`, user);

app.get('/search-safe', requireAuth, (req, res) => {
  res.send(searchSafeForm('', '', null, '', req.session.user));
});

app.post('/search-safe', requireAuth, async (req, res) => {
  const { uid } = req.body || {};
  // Safe: escape all LDAP metacharacters before inserting into the filter.
  // '*' becomes '\2a', so (uid=\2a) is an equality filter for a literal '*' — no match.
  const safeUid = escapeLdap(String(uid));
  const filter  = `(uid=${safeUid})`;
  try {
    const users = await ldapSearch(filter);
    res.send(searchSafeForm(uid, filter, users, '', req.session.user));
  } catch (err) {
    res.send(searchSafeForm(uid, filter, null, err.message, req.session.user));
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
