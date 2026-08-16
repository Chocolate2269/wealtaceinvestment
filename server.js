const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const session = require('express-session');
const bcrypt = require('bcrypt');
require('dotenv').config();

const DATA_FILE = path.join(__dirname, 'data', 'site.json');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_in_production';

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.warn('Warning: ADMIN_USERNAME or ADMIN_PASSWORD not set in .env. Login will fail until set.');
}

const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Serve static files (index.html, admin.html, etc.)
app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_HASH)) {
    req.session.authenticated = true;
    req.session.user = username;
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Could not log out' });
    res.json({ ok: true });
  });
});

app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Could not read site state', details: err.message });
  }
});

app.post('/api/state', requireAuth, async (req, res) => {
  const body = req.body;
  // Basic validation
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Invalid body' });
  try {
    await fs.writeFile(DATA_FILE, JSON.stringify(body, null, 2), 'utf8');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not write site state', details: err.message });
  }
});

// Convenience endpoints to add/remove plans
app.post('/api/plans/add', requireAuth, async (req, res) => {
  const { section, plan } = req.body; // section: current | old
  if (!section || !plan) return res.status(400).json({ error: 'Missing section or plan' });
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (section === 'current') data.currentPlans.push(plan);
    else data.oldPlans.push(plan);
    await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/plans/remove', requireAuth, async (req, res) => {
  const { section, index } = req.body;
  if (typeof index !== 'number' || !section) return res.status(400).json({ error: 'Missing section or index' });
  try {
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (section === 'current') data.currentPlans.splice(index, 1);
    else data.oldPlans.splice(index, 1);
    await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
