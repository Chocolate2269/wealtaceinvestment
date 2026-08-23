const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'site.json');

app.use(express.json());
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'wealtace_secret',
  resave: false,
  saveUninitialized: false
}));

const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'WeltaceAdmin!2026';

function requireAuth(req, res, next) {
  if (req.session.admin) next();
  else res.status(401).json({ error: 'Not authorized' });
}

// ADMIN LOGIN
app.post('/api/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.admin = true;
    res.json({ ok: true });
  } else res.status(401).json({ error: 'Wrong credentials' });
});

// SIGNUP
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const raw = await fs.readFile(DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    if(data.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });
    const hash = await bcrypt.hash(password, 10);
    data.users.push({ id: Date.now(), name, email, password: hash, balance: 0 });
    await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    res.json({ ok: true });
  } catch(e){ res.status(500).json({error: e.message}) }
});

// USER LOGIN
app.post('/api/user-login', async (req, res) => {
  const { email, password } = req.body;
  const raw = await fs.readFile(DATA_FILE, 'utf8');
  const data = JSON.parse(raw);
  const user = data.users.find(u => u.email === email);
  if(!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid' });
  res.json({ user: {id: user.id, name: user.name, email: user.email, balance: user.balance} });
});

// GET ALL USERS FOR ADMIN
app.get('/api/users', requireAuth, async (req, res) => {
  const raw = await fs.readFile(DATA_FILE, 'utf8');
  const data = JSON.parse(raw);
  res.json(data.users.map(u => ({id: u.id, name: u.name, email: u.email, balance: u.balance})));
});

// CREDIT USER
app.post('/api/credit', requireAuth, async (req, res) => {
  const { userId, amount } = req.body;
  const raw = await fs.readFile(DATA_FILE, 'utf8');
  const data = JSON.parse(raw);
  const user = data.users.find(u => u.id == userId);
  user.balance = (parseFloat(user.balance) || 0) + Number(amount);
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
  res.json({ ok: true });
});

// GET CURRENT USER
app.get('/api/me', async (req,res)=>{
  const raw = await fs.readFile(DATA_FILE, 'utf8');
  const data = JSON.parse(raw);
  const user = data.users.find(u => u.email == req.query.email);
  res.json(user);
})

app.listen(PORT, () => console.log(`Server running on ${PORT}`));
