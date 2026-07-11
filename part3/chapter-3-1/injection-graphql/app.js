// app.js - GraphQL Injection demonstration
// Dependencies: express, express-session, bcryptjs, graphql
// Install: npm install express express-session bcryptjs graphql
//
// GraphQL injection occurs when user-supplied input is interpolated directly into
// a GraphQL query string. The attack is structurally identical to SQL injection:
// the attacker supplies closing characters that end the current context and open
// a new one, requesting data outside the intended scope. The mitigation is also
// the same: use parameterised input (GraphQL variables) instead of interpolation.

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { buildSchema, graphql: executeGraphQL } = require('graphql');

const app = express();

// ---------- User directory ----------
// apiKey is a sensitive field that exists on each object and in the GraphQL type
// definition. The /search endpoint is intended to return only username and role.
// Injection allows the attacker to add apiKey to the selection set.
const USER_DIRECTORY = [
  { id: 1, username: 'alice', role: 'admin', email: 'alice@internal.corp', apiKey: 'sk-alice-prod-7f3a2b9c' },
  { id: 2, username: 'bob',   role: 'user',  email: 'bob@example.com',     apiKey: 'sk-bob-prod-4e1d8a0f'  },
  { id: 3, username: 'carol', role: 'user',  email: 'carol@example.com',   apiKey: 'sk-carol-prod-3c7b1e5a' },
];

// ---------- GraphQL schema ----------
// apiKey appears in the type definition — a common oversight: added during
// development and never removed. Application queries only request username and
// role, which developers assume is sufficient. Injection defeats that assumption.
const schema = buildSchema(`
  type User {
    id: Int!
    username: String!
    role: String!
    email: String!
    apiKey: String!
  }

  type Query {
    users(search: String): [User!]!
    user(id: Int!): User
  }
`);

const rootValue = {
  users: ({ search }) => {
    if (!search) return USER_DIRECTORY;
    return USER_DIRECTORY.filter(u =>
      u.username.toLowerCase().includes(search.toLowerCase())
    );
  },
  user: ({ id }) => USER_DIRECTORY.find(u => u.id === id) || null,
};

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
    <a href="/search">User Search</a> |
    <a href="/search-safe">User Search (Safe)</a> |
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
  res.send(page('GraphQL Injection', `
    <h1>GraphQL Injection</h1>
    <p>GraphQL injection occurs when user-supplied input is concatenated directly into a GraphQL query string. The attack is structurally identical to SQL injection: the attacker supplies closing characters that terminate the current context and opens a new one that requests data outside the intended scope. In SQL that character is <code>'</code>; in GraphQL it is <code>"</code> (the string delimiter in query arguments), paired with <code>}</code> to close the selection set.</p>
    <p>This example uses a user search feature. The server builds the query <code>{ users(search: "${'{'}q{'}"}") { username role } }</code> from user input, intending to return only <code>username</code> and <code>role</code>. The <code>User</code> type also defines <code>email</code> and <code>apiKey</code> — a common oversight when developing quickly. By injecting <code>") { username role apiKey } x: users(search: "</code>, the attacker closes the intended selection set and opens a new one that requests <code>apiKey</code>, receiving API keys the application never intended to expose through the search endpoint.</p>

    <h2>How This App Works</h2>
    <p>The raw GraphQL endpoint at <code>POST /graphql</code> accepts any query, including introspection. The <code>/search</code> form builds the query by interpolation; the <code>/search-safe</code> form uses a static query template and passes the search term as a GraphQL variable. Both forms display the query string and the full response so the structural difference is immediately visible.</p>

    <h2>Introspection</h2>
    <p>Before crafting an injection payload an attacker uses introspection to discover what fields the <code>User</code> type exposes — including <code>apiKey</code>, which never appears in normal application responses:</p>
    <pre>curl -s -X POST -H "Content-Type: application/json" \\
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \\
  http://localhost:3000/graphql</pre>

    <h2>The Attack</h2>
    <p>On the <a href="/search">/search</a> page, enter the following as the search term:</p>
    <pre>") { username role apiKey } x: users(search: "</pre>
    <p>The constructed query becomes:</p>
    <pre>{ users(search: "") { username role apiKey } x: users(search: "") { username role } }</pre>
    <p>This is syntactically valid GraphQL. The response includes <code>apiKey</code> values for all users.</p>

    <h2>Try It</h2>
    <ul>
      <li>Log in as <code>alice / password1</code> (admin) or <code>bob / password2</code> (user)</li>
      <li>Visit <a href="/search">/search</a> — enter <code>alice</code> — see the constructed query and clean result</li>
      <li>Enter <code>") { username role apiKey } x: users(search: "</code> — apiKey values appear in the response</li>
      <li>Visit <a href="/search-safe">/search-safe</a> — enter the same payload — the query template is unchanged and only <code>username</code> and <code>role</code> are returned</li>
    </ul>

    ${user ? `<p>Currently logged in as <strong>${user.username}</strong> (${user.role}).</p>` : '<p>You are not logged in.</p>'}
  `, user));
});

// ---------- Raw GraphQL endpoint ----------
// Accepts any query including introspection — demonstrates that schema discovery
// is trivial when introspection is left enabled in production.
app.post('/graphql', async (req, res) => {
  const { query, variables } = req.body || {};
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ errors: [{ message: 'Missing or invalid query' }] });
  }
  const result = await executeGraphQL({
    schema,
    source: query,
    rootValue,
    variableValues: variables || {}
  });
  res.json(result);
});

// ---------- Login / logout ----------
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

// ---------- User search (vulnerable) ----------
const searchForm = (q, queryStr, result, user) => page('User Search', `
  <h1>User Search (Vulnerable)</h1>
  <p>Search for users by name. The search term is interpolated directly into the GraphQL query string — injection is possible.</p>
  <form method="post" action="/search">
    <label for="q">Search</label><br>
    <input id="q" name="q" value="${escapeHtml(q)}"
      placeholder='e.g. alice — or: ") { username role apiKey } x: users(search: "'
      style="width:620px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${queryStr !== null ? `
    <h2>Constructed query</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(queryStr)}</pre>
    <h2>Response</h2>
    ${result.data && JSON.stringify(result.data).includes('apiKey')
      ? '<p style="color:red;font-weight:bold">&#9888; apiKey values exposed via injection.</p>'
      : ''}
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
  ` : ''}
`, user);

app.get('/search', requireAuth, (req, res) => {
  res.send(searchForm('', null, null, req.session.user));
});

app.post('/search', requireAuth, async (req, res) => {
  const { q = '' } = req.body;
  // VULNERABLE: user input interpolated directly into the GraphQL query string.
  // Injecting ") { username role apiKey } x: users(search: " closes the intended
  // selection set and opens a new one that requests the apiKey field.
  const queryStr = `{ users(search: "${q}") { username role } }`;
  const result = await executeGraphQL({ schema, source: queryStr, rootValue });
  res.send(searchForm(q, queryStr, result, req.session.user));
});

// ---------- User search (safe) ----------
const searchSafeForm = (q, queryStr, result, user) => page('User Search (Safe)', `
  <h1>User Search (Safe)</h1>
  <p>The query template is static; the search term is passed as a GraphQL variable. No input value can alter the query structure or add new field selections.</p>
  <form method="post" action="/search-safe">
    <label for="q">Search</label><br>
    <input id="q" name="q" value="${escapeHtml(q)}"
      placeholder='e.g. alice — try the same injection payload'
      style="width:620px"><br><br>
    <button type="submit">Search</button>
  </form>
  ${queryStr !== null ? `
    <h2>Query template (never changes)</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(queryStr)}</pre>
    <h2>Response</h2>
    <pre style="background:#f8f8f8;border:1px solid #ccc;padding:12px;line-height:1.6">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
  ` : ''}
`, user);

app.get('/search-safe', requireAuth, (req, res) => {
  res.send(searchSafeForm('', null, null, req.session.user));
});

app.post('/search-safe', requireAuth, async (req, res) => {
  const { q = '' } = req.body;
  // Safe: the query string is a static template; user input is a typed variable.
  // GraphQL binds variables to their declared position — no amount of input
  // can change the selection set or add new field requests.
  const queryStr = `query Search($q: String) { users(search: $q) { username role } }`;
  const result = await executeGraphQL({
    schema,
    source: queryStr,
    rootValue,
    variableValues: { q }
  });
  res.send(searchSafeForm(q, queryStr, result, req.session.user));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
