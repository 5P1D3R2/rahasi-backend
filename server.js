require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false }));

/* ═══ PERSISTENT STORAGE — Neon Postgres (free) — survives redeploys ═══
   Set DATABASE_URL in Render env vars. Whole app state lives as one JSONB
   document; app logic below is untouched. */
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const EMPTY = { users: [], sessions: [], ledger: [], deposits: [], withdrawals: [],
                requests: [], ratings: [], promos: [], settings: { banner: '' } };
let db = JSON.parse(JSON.stringify(EMPTY));

async function loadDb() {
  try {
    await pool.query('CREATE TABLE IF NOT EXISTS app_state (id INT PRIMARY KEY, data JSONB)');
    const r = await pool.query('SELECT data FROM app_state WHERE id = 1');
    if (r.rows.length && r.rows[0].data) {
      db = { ...JSON.parse(JSON.stringify(EMPTY)), ...r.rows[0].data };
      console.log('DB loaded from Postgres:', db.users.length, 'users,', db.sessions.length, 'sessions');
    } else {
      await pool.query('INSERT INTO app_state (id, data) VALUES (1, $1)', [JSON.stringify(db)]);
      console.log('Fresh DB created in Postgres');
    }
  } catch (e) {
    console.error('DB LOAD FAILED:', e.message);
  }
}

let saveT = null;
function save() {
  clearTimeout(saveT);
  saveT = setTimeout(async () => {
    try {
      await pool.query(
        'INSERT INTO app_state (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = $1',
        [JSON.stringify(db)]
      );
    } catch (e) { console.error('DB SAVE FAILED:', e.message); }
  }, 300);
}

const newId = () => crypto.randomBytes(6).toString('hex').toUpperCase();

/* ── config ── */
const TINYPESA_KEY = process.env.TINYPESA_API_KEY || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const WALLET_ENABLED = !!(TINYPESA_KEY && ADMIN_KEY);
const MIN_DEPOSIT = 50, MIN_WITHDRAW = 100, MIN_PRICE = 250, MAX_PRICE = 20000;
const SESSION_DAYS = 180;

/* ── helpers ── */
const normPhone = v => {
  let p = String(v || '').replace(/\D/g, '');
  if (p.startsWith('0')) p = '254' + p.slice(1);
  if (p.length === 9) p = '254' + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
};
const hashPin = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString('hex');
const userByPhone = p => db.users.find(u => u.phone === p);
const pubUser = u => ({ name: u.name, phone: u.phone, balance: u.balance, verified: !!u.verified, created: u.created });
function newSession(phone) {
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions.push({ token, phone, exp: Date.now() + SESSION_DAYS * 864e5 });
  const mine = db.sessions.filter(s => s.phone === phone);
  if (mine.length > 5) {
    const kill = new Set(mine.sort((a, b) => a.exp - b.exp).slice(0, mine.length - 5).map(s => s.token));
    db.sessions = db.sessions.filter(s => !kill.has(s.token));
  }
  return token;
}
function addLedger(phone, delta, kind, ref) {
  const u = userByPhone(phone); if (!u) return;
  u.balance = +(u.balance + delta).toFixed(2);
  db.ledger.push({ phone, delta, kind, ref: ref || '', balanceAfter: u.balance, t: Date.now() });
}
function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const s = db.sessions.find(x => x.token === t);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Please log in again' });
  req.user = userByPhone(s.phone);
  if (!req.user) return res.status(401).json({ error: 'Please log in again' });
  next();
}
const isAdmin = req => ADMIN_KEY && (req.query.key === ADMIN_KEY || req.headers['x-admin-key'] === ADMIN_KEY);

/* ── public config ── */
app.get('/config', (req, res) =>
  res.json({ walletEnabled: WALLET_ENABLED, minDeposit: MIN_DEPOSIT, minWithdraw: MIN_WITHDRAW, banner: db.settings.banner || '' }));

/* ═══ AUTH ═══ */
app.post('/auth/register', (req, res) => {
  const name = String(req.body.name || '').trim();
  const phone = normPhone(req.body.phone);
  const pin = String(req.body.pin || '');
  if (name.length < 2 || name.length > 40) return res.status(400).json({ error: 'Enter your full name' });
  if (!phone) return res.status(400).json({ error: 'Enter a valid Safaricom number (07XX…)' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  if (userByPhone(phone)) return res.status(400).json({ error: 'Account already exists — please log in' });
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { name, phone, salt, pinHash: hashPin(pin, salt), balance: 0, verified: false, created: Date.now() };
  db.users.push(user); save();
  res.json({ token: newSession(phone), user: pubUser(user) });
});
app.post('/auth/login', (req, res) => {
  const u = userByPhone(normPhone(req.body.phone));
  if (!u || hashPin(String(req.body.pin || ''), u.salt) !== u.pinHash) return res.status(401).json({ error: 'Wrong phone or PIN' });
  save();
  res.json({ token: newSession(u.phone), user: pubUser(u) });
});
app.post('/auth/logout', auth, (req, res) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  db.sessions = db.sessions.filter(s => s.token !== t); save();
  res.json({ ok: true });
});
app.get('/me', auth, (req, res) => {
  res.json({ user: pubUser(req.user), ledger: db.ledger.filter(l => l.phone === req.user.phone).slice(-30).reverse() });
});
app.post('/auth/change-pin', auth, (req, res) => {
  const u = req.user;
  if (hashPin(String(req.body.old || ''), u.salt) !== u.pinHash) return res.status(401).json({ error: 'Current PIN is wrong' });
  if (!/^\d{4}$/.test(String(req.body.pin || ''))) return res.status(400).json({ error: 'New PIN must be 4 digits' });
  u.pinHash = hashPin(String(req.body.pin), u.salt);
  db.sessions = db.sessions.filter(s => s.phone !== u.phone); save();
  res.json({ ok: true, token: newSession(u.phone) });
});
app.post('/auth/delete', auth, (req, res) => {
  const p = req.user.phone;
  db.users = db.users.filter(u => u.phone !== p);
  db.sessions = db.sessions.filter(s => s.phone !== p);
  db.ledger = db.ledger.filter(l => l.phone !== p);
  db.requests = db.requests.filter(r => r.phone !== p);
  db.withdrawals = db.withdrawals.filter(w => w.phone !== p);
  save(); res.json({ ok: true });
});

/* ═══ DEPOSITS (TinyPesa STK push) ═══
   If TinyPesa requires your dashboard link-name as account_no, set env var
   TINYPESA_TARGET in Render. Leave unset to use the deposit ID. */
app.post('/wallet/deposit', auth, async (req, res) => {
  if (!WALLET_ENABLED) return res.status(403).json({ error: 'Wallet is not enabled yet' });
  const amount = Math.floor(+req.body.amount);
  if (!(amount >= MIN_DEPOSIT)) return res.status(400).json({ error: 'Minimum deposit is KSh ' + MIN_DEPOSIT });
  if (amount > 150000) return res.status(400).json({ error: 'Amount too large' });
  const dep = { id: newId(), phone: req.user.phone, amount, status: 'pending', t: Date.now() };
  db.deposits.push(dep); save();
  const accountNo = process.env.TINYPESA_TARGET || dep.id;
  try {
    const r = await fetch('https://tinypesa.com/api/v1/express/initialize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: TINYPESA_KEY },
      body: JSON.stringify({ amount, msisdn: dep.phone, account_no: accountNo })
    });
    const raw = await r.text();
    console.log('TINYPESA REPLY [' + r.status + ']:', raw.slice(0, 300));
    let data = {};
    try { data = JSON.parse(raw); } catch { data = { success: false }; }
    if (!data.success) {
      dep.status = 'failed'; dep.lastError = raw.slice(0, 200); save();
      const html = raw.trim().toLowerCase().startsWith('<!doctype');
      const hint = html ? ' — TinyPesa served a web page instead of the API. Usually means the API endpoint has changed or the account/key is not active.'
                  : /kyc|verif|pend/i.test(raw) ? ' — KYC not approved yet.' : '';
      return res.status(400).json({ error: 'TinyPesa rejected the push' + hint });
    }
    dep.tracking = data.tracking_id; save();
    res.json({ depositId: dep.id, status: 'pending', message: 'Enter your M-Pesa PIN on the prompt sent to ' + dep.phone });
  } catch (e) {
    dep.status = 'failed'; save();
    console.log('TINYPESA FETCH ERROR:', e.message);
    res.status(500).json({ error: 'Payment service unreachable — try again' });
  }
});
app.get('/wallet/deposit/:did', auth, (req, res) => {
  const dep = db.deposits.find(d => d.id === req.params.did && d.phone === req.user.phone);
  if (!dep) return res.status(404).json({ error: 'Deposit not found' });
  res.json({ status: dep.status, balance: req.user.balance, ref: dep.ref || null });
});
app.post('/tinypesa/webhook', (req, res) => {
  res.sendStatus(200);
  const b = req.body || {};
  const receipt = b.MpesaReceiptNumber || b.mpesaReceiptNumber || '';
  if (!receipt) return;
  const phone = normPhone(b.PhoneNumber || b.phoneNumber || b.Msisdn || '');
  const amount = +b.Amount || +b.amount || 0;
  const acct = String(b.AccountNumber || b.account_no || b.accountNumber || b.Account_no || '');
  let dep = db.deposits.find(d => d.id === acct && d.status === 'pending');
  if (!dep) dep = db.deposits.find(d => d.status === 'pending' && d.phone === phone && d.amount === amount);
  if (!dep) return console.log('webhook: no matching pending deposit', phone, amount);
  dep.status = 'paid'; dep.ref = receipt;
  addLedger(dep.phone, dep.amount, 'deposit', receipt);
  const u = userByPhone(dep.phone); if (u) u.verified = true;
  save();
  console.log('DEPOSIT PAID:', dep.phone, dep.amount, receipt);
});

/* ═══ WITHDRAWALS ═══ */
app.post('/wallet/withdraw', auth, (req, res) => {
  const amount = Math.floor(+req.body.amount);
  if (!(amount >= MIN_WITHDRAW)) return res.status(400).json({ error: 'Minimum withdrawal is KSh ' + MIN_WITHDRAW });
  if (amount > req.user.balance) return res.status(400).json({ error: 'Not enough balance' });
  const w = { id: newId(), phone: req.user.phone, amount, status: 'pending', t: Date.now() };
  db.withdrawals.push(w);
  addLedger(req.user.phone, -amount, 'withdraw_pending', w.id);
  save();
  res.json({ id: w.id, message: 'Withdrawal requested — M-Pesa payment within 24 hours' });
});
app.get('/wallet/withdrawals', auth, (req, res) =>
  res.json(db.withdrawals.filter(w => w.phone === req.user.phone).slice(-20).reverse()));

/* ═══ SERVICE REQUESTS ═══ */
app.post('/services/request', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const price = Math.floor(+req.body.price);
  if (!name) return res.status(400).json({ error: 'Missing service' });
  if (!(price >= MIN_PRICE && price <= MAX_PRICE)) return res.status(400).json({ error: 'Invalid price' });
  let discount = 0, promoCode = '';
  const code = String(req.body.promo || '').trim().toUpperCase();
  if (code) {
    const pr = db.promos.find(p => p.code === code && p.active && p.uses < p.maxUses && (!p.expires || p.expires > Date.now()));
    if (!pr) return res.status(400).json({ error: 'Promo code is invalid or expired' });
    discount = pr.type === 'percent' ? Math.floor(price * pr.value / 100) : Math.min(pr.value, Math.max(0, price - 100));
    promoCode = code;
  }
  const final = price - discount;
  if (req.user.balance < final) return res.status(400).json({ error: 'Insufficient balance — deposit first' });
  const r = { id: 'RQ-' + newId(), phone: req.user.phone, name, price, discount, final, promo: promoCode, status: 'new', t: Date.now() };
  db.requests.push(r);
  if (promoCode) db.promos.find(p => p.code === promoCode).uses++;
  addLedger(req.user.phone, -final, 'service', r.id);
  req.user.verified = true;
  save();
  res.json({ requestId: r.id, price, discount, charged: final, balance: req.user.balance });
});
app.get('/services/requests', auth, (req, res) =>
  res.json(db.requests.filter(r => r.phone === req.user.phone).slice(-20).reverse()));

/* public promo preview */
app.post('/promo/check', (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  const price = Math.floor(+req.body.price || 0);
  const pr = db.promos.find(p => p.code === code && p.active && p.uses < p.maxUses && (!p.expires || p.expires > Date.now()));
  if (!pr) return res.status(404).json({ error: 'Invalid or expired code' });
  if (!(price >= MIN_PRICE)) return res.status(400).json({ error: 'Missing price' });
  const discount = Math.max(0, pr.type === 'percent' ? Math.floor(price * pr.value / 100) : Math.min(pr.value, price - 100));
  res.json({ code: pr.code, discount, final: price - discount });
});

/* ═══ RATINGS ═══ */
app.post('/ratings', (req, res) => {
  const stars = Math.round(+req.body.stars);
  const service = String(req.body.service || '').trim().slice(0, 80);
  const name = String(req.body.name || '').trim().slice(0, 40) || 'Customer';
  const comment = String(req.body.comment || '').trim().slice(0, 300);
  if (!service || !(stars >= 1 && stars <= 5)) return res.status(400).json({ error: 'Invalid rating' });
  db.ratings.push({ service, stars, name, comment, t: Date.now() });
  save(); res.json({ ok: true });
});
app.get('/ratings', (req, res) => res.json(db.ratings.slice(-500)));

/* ═══ PUBLIC RECEIPT VERIFICATION ═══ */
app.get('/verify/:rid', (req, res) => {
  const r = db.requests.find(x => x.id === req.params.rid.toUpperCase());
  if (!r) return res.status(404).json({ error: 'No receipt found with that ID' });
  res.json({ id: r.id, service: r.name, price: r.final || r.price, status: r.status, date: r.t });
});

/* ═══ ADMIN ═══ */
app.get('/admin/overview', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.json({
    walletEnabled: WALLET_ENABLED,
    users: db.users.length,
    verifiedUsers: db.users.filter(u => u.verified).length,
    pendingWithdrawals: db.withdrawals.filter(w => w.status === 'pending'),
    newRequests: db.requests.filter(r => r.status === 'new'),
    pendingDeposits: db.deposits.filter(d => d.status === 'pending').length,
    revenue: +db.ledger.filter(l => l.kind === 'service').reduce((s, l) => s - l.delta, 0).toFixed(2),
    depositsToday: db.deposits.filter(d => d.status === 'paid' && Date.now() - d.t < 864e5).length
  });
});
app.get('/admin/requests', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.json(db.requests.slice(-100).reverse());
});
app.post('/admin/withdrawal/:wid/paid', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const w = db.withdrawals.find(x => x.id === req.params.wid);
  if (!w || w.status !== 'pending') return res.status(400).json({ error: 'not found or not pending' });
  w.status = 'paid'; w.paidAt = Date.now(); save(); res.json({ ok: true });
});
app.post('/admin/request/:rid/status', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const r = db.requests.find(x => x.id === req.params.rid.toUpperCase());
  if (!r) return res.status(400).json({ error: 'not found' });
  const st = String(req.body.status || 'new').toLowerCase().slice(0, 12);
  if (!['new', 'in progress', 'done', 'refunded'].includes(st)) return res.status(400).json({ error: 'bad status' });
  r.status = st; save(); res.json({ ok: true, status: r.status });
});
app.post('/admin/refund', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const r = db.requests.find(x => x.id === String(req.body.rid || '').toUpperCase());
  if (!r) return res.status(404).json({ error: 'receipt not found' });
  if (r.status === 'refunded') return res.status(400).json({ error: 'already refunded' });
  addLedger(r.phone, r.final || r.price, 'refund', r.id);
  r.status = 'refunded'; save();
  res.json({ ok: true, message: 'Refunded KSh ' + (r.final || r.price) + ' to wallet' });
});
/* promo codes */
app.post('/admin/promo', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const code = String(req.body.code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (code.length < 3 || code.length > 15) return res.status(400).json({ error: 'Code: 3–15 letters/numbers' });
  const type = req.body.type === 'percent' ? 'percent' : 'flat';
  const value = Math.floor(+req.body.value);
  if (!(value > 0) || (type === 'percent' ? value > 90 : value > 2000)) return res.status(400).json({ error: 'Bad value' });
  if (db.promos.some(p => p.code === code)) return res.status(400).json({ error: 'Code already exists' });
  const pr = { code, type, value, maxUses: Math.max(1, Math.floor(+req.body.maxUses || 100)), uses: 0,
               expires: Date.now() + Math.max(1, Math.floor(+req.body.days || 30)) * 864e5, active: true, created: Date.now() };
  db.promos.push(pr); save(); res.json(pr);
});
app.get('/admin/promos', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.json(db.promos.slice(-50).reverse());
});
app.post('/admin/promo/:code/disable', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const pr = db.promos.find(p => p.code === req.params.code.toUpperCase());
  if (!pr) return res.status(404).json({ error: 'not found' });
  pr.active = false; save(); res.json({ ok: true });
});
app.post('/admin/banner', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  db.settings.banner = String(req.body.text || '').slice(0, 200); save();
  res.json({ banner: db.settings.banner });
});

/* ═══ ADMIN — wallet deposits: approve STK or credit manually ═══ */
app.get('/admin/deposits/pending', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.json(db.deposits.filter(d => d.status === 'pending').slice(-50).reverse());
});
app.post('/admin/deposit/:did/approve', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const dep = db.deposits.find(d => d.id === req.params.did.toUpperCase());
  if (!dep) return res.status(404).json({ error: 'not found' });
  if (dep.status !== 'pending') return res.status(400).json({ error: 'not pending' });
  dep.status = 'paid'; dep.ref = dep.ref || 'MANUAL-' + Date.now();
  addLedger(dep.phone, dep.amount, 'deposit', dep.ref);
  const u = userByPhone(dep.phone); if (u) u.verified = true;
  save();
  res.json({ ok: true, message: 'Credited KSh ' + dep.amount + ' to ' + dep.phone });
});
app.post('/admin/deposit/manual', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const phone = normPhone(req.body.phone);
  const amount = Math.floor(+req.body.amount);
  const ref = String(req.body.ref || '').trim().slice(0, 40);
  if (!phone) return res.status(400).json({ error: 'Invalid phone number' });
  if (!(amount >= 10)) return res.status(400).json({ error: 'Minimum is KSh 10' });
  const u = userByPhone(phone);
  if (!u) return res.status(404).json({ error: 'No account with that phone — customer must register first' });
  addLedger(phone, amount, 'deposit', ref || 'manual');
  u.verified = true;
  save();
  console.log('MANUAL DEPOSIT:', phone, amount, ref);
  res.json({ ok: true, message: 'Credited KSh ' + amount + ' to ' + phone });
});

/* ═══ ADMIN — backup & restore ═══ */
app.get('/admin/backup', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.setHeader('Content-Disposition', 'attachment; filename="rahasi-backup.json"');
  res.json(db);
});
app.post('/admin/restore', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  const incoming = req.body;
  if (!incoming || !Array.isArray(incoming.users) || !Array.isArray(incoming.ledger)) {
    return res.status(400).json({ error: 'That file is not a valid Rahisi backup' });
  }
  const keys = ['users', 'sessions', 'ledger', 'deposits', 'withdrawals', 'requests', 'ratings', 'promos'];
  for (const k of keys) if (Array.isArray(incoming[k])) db[k] = incoming[k];
  if (incoming.settings && typeof incoming.settings === 'object') db.settings = incoming.settings;
  save();
  console.log('DATABASE RESTORED from backup:', incoming.users.length, 'users');
  res.json({ ok: true, message: 'Restored: ' + incoming.users.length + ' users, ' +
    (incoming.requests || []).length + ' requests, ' + (incoming.ledger || []).length + ' ledger entries' });
});
app.get('/admin/export', (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'bad key' });
  res.setHeader('Content-Disposition', 'attachment; filename="rahasi-backup.json"');
  res.json(db);
});

app.get('/', (req, res) => res.send('Rahisi backend running' + (WALLET_ENABLED ? ' (wallet LIVE)' : ' (wallet waiting for TinyPesa key)')));

const PORT = process.env.PORT || 3000;
(async () => {
  await loadDb();
  app.listen(PORT, () => console.log('Rahisi backend on ' + PORT, WALLET_ENABLED ? '(LIVE)' : '(wallet disabled — add TINYPESA_API_KEY when KYC clears)'));
})();
