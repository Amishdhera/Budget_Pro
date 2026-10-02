require('dotenv').config();
const express = require('express'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (process.env.NODE_ENV === 'production' && SECRET === 'dev-secret-change-me') {
  console.error('Set JWT_SECRET before running in production.'); process.exit(1);
}
const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
let DB = { users: {} };
try { DB = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const persist = () => { fs.writeFileSync(FILE + '.tmp', JSON.stringify(DB)); fs.renameSync(FILE + '.tmp', FILE); };

const app = express();
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// basic brute-force guard: 10 auth attempts / 15 min / IP
const hits = new Map();
const limit = (req, res, next) => {
  const k = req.ip, now = Date.now(), h = (hits.get(k) || []).filter(t => now - t < 9e5);
  if (h.length >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  h.push(now); hits.set(k, h); next();
};
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '14d' });

app.post('/api/auth/signup', limit, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (DB.users[email]) return res.status(409).json({ error: 'This email is already registered. Sign in instead.' });
  const u = DB.users[email] = { id: crypto.randomUUID(), email, hash: await bcrypt.hash(pw, 10), data: { settings: {}, estimates: [] }, createdAt: Date.now() };
  persist(); res.status(201).json({ token: token(u) });
});

app.post('/api/auth/login', limit, async (req, res) => {
  const u = DB.users[String(req.body.email || '').trim().toLowerCase()];
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.hash))) return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: token(u) });
});

const auth = (req, res, next) => {
  try {
    const { id } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    req.user = Object.values(DB.users).find(u => u.id === id);
    req.user ? next() : res.status(401).json({ error: 'Session expired' });
  } catch (e) { res.status(401).json({ error: 'Session expired' }); }
};

app.get('/api/data', auth, (req, res) => res.json(req.user.data));

app.put('/api/data', auth, (req, res) => {
  const { settings, estimates } = req.body;
  if (typeof settings !== 'object' || settings === null || !Array.isArray(estimates)) return res.status(400).json({ error: 'Invalid data' });
  req.user.data = { settings, estimates }; persist(); res.json({ ok: true });
});

app.listen(process.env.PORT || 5000, () => console.log('BudgetPro running on http://localhost:' + (process.env.PORT || 5000)));
