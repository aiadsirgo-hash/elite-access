const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const PORT = process.env.PORT || 3000;

// PostgreSQL connection (use DATABASE_URL from Neon.tech)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// IMPORTANT: All timestamps use JS Date().toISOString() = UTC with Z suffix
function utcNow() { return new Date().toISOString(); }

// ==================== DB HELPERS ====================
async function dbRun(sql, params = []) { await pool.query(sql, params); }
async function dbGet(sql, params = []) { const r = await pool.query(sql, params); return r.rows[0] || null; }
async function dbAll(sql, params = []) { const r = await pool.query(sql, params); return r.rows; }

// ==================== SCHEMA INIT ====================
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'receiver',
      ip TEXT,
      security_question TEXT,
      security_answer_hash TEXT,
      uninstall_token TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL,
      from_username TEXT NOT NULL,
      to_user_id TEXT NOT NULL,
      to_username TEXT NOT NULL,
      domain TEXT NOT NULL,
      session_data TEXT NOT NULL,
      duration_label TEXT DEFAULT 'unlimited',
      expires_at TEXT,
      revoked INTEGER DEFAULT 0,
      delivered INTEGER DEFAULT 0,
      applied INTEGER DEFAULT 0,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS history (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      domain TEXT,
      detail TEXT,
      created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS saved_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      label TEXT NOT NULL,
      domain TEXT NOT NULL,
      session_data TEXT NOT NULL,
      created_at TEXT,
      updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS support_messages (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL,
      from_username TEXT NOT NULL,
      to_user_id TEXT,
      message TEXT NOT NULL,
      is_owner_reply INTEGER DEFAULT 0,
      read INTEGER DEFAULT 0,
      created_at TEXT
    );
  `);
  console.log('Database tables ready');
}

// ==================== EXPIRY CHECKER (every 20s) ====================
setInterval(async () => {
  try {
    const now = utcNow();
    const expired = await dbAll('SELECT * FROM sessions WHERE expires_at IS NOT NULL AND expires_at <= $1 AND revoked = 0', [now]);
    for (const s of expired) {
      sendWS(s.to_user_id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Your access to ' + s.domain + ' has expired' });
      await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [s.to_user_id, 'expired', s.domain, 'Access expired', now]);
      sendWS(s.from_user_id, { type: 'session-revoked', sessionId: s.id });
    }
    await dbRun('UPDATE sessions SET revoked = 1 WHERE expires_at IS NOT NULL AND expires_at <= $1 AND revoked = 0', [now]);
  } catch(e) { console.error('Expiry check:', e.message); }
}, 20000);

// ==================== HEARTBEAT TRACKER (every 60s) ====================
// Only tracks online/offline status for display — does NOT revoke sessions or tokens.
// Sessions expire only via their expires_at or manual owner revoke.
setInterval(async () => {
  try {
    const now = new Date();
    const allReceivers = await dbAll("SELECT id, username FROM users WHERE role = 'receiver'");
    for (const r of allReceivers) {
      const hbRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['hb_' + r.id]);
      if (!hbRow) continue;
      const lastBeat = new Date(hbRow.value);
      const diffMin = (now - lastBeat) / 60000;
      // If offline for more than 5 min, just notify owner (no revoke, no token delete)
      if (diffMin > 5 && !clients.has(r.id)) {
        const flagKey = 'offline_notified_' + r.id;
        const already = await dbGet('SELECT value FROM settings WHERE key = $1', [flagKey]);
        if (!already) {
          await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', [flagKey, utcNow()]);
          for (const [uid, ws] of clients) {
            const u = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
            if (u && u.role === 'owner') {
              sendWS(uid, { type: 'receiver-offline', username: r.username, sessionsRevoked: 0 });
            }
          }
        }
      }
      // Clear offline flag when user comes back online
      if (clients.has(r.id)) {
        await dbRun('DELETE FROM settings WHERE key = $1', ['offline_notified_' + r.id]);
      }
    }
  } catch(e) { console.error('HB check:', e.message); }
}, 60000);

// Clean expired tokens every hour
setInterval(async () => { try { await dbRun('DELETE FROM tokens WHERE expires_at < $1', [utcNow()]); } catch(e) {} }, 3600000);

// ==================== HELPERS ====================
function hash(pw) { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); }
function verify(pw, stored) { if (!stored) return false; const [s, h] = stored.split(':'); return h === crypto.scryptSync(pw, s, 64).toString('hex'); }
async function makeToken(uid) {
  const t = crypto.randomBytes(48).toString('hex');
  await dbRun('INSERT INTO tokens (token, user_id, expires_at) VALUES ($1,$2,$3)', [t, uid, new Date(Date.now() + 90 * 86400000).toISOString()]);
  return t;
}
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'; }

async function checkToken(tokenStr) {
  if (!tokenStr) return null;
  const row = await dbGet('SELECT * FROM tokens WHERE token = $1', [tokenStr]);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) { await dbRun('DELETE FROM tokens WHERE token = $1', [tokenStr]); return null; }
  return await dbGet('SELECT * FROM users WHERE id = $1', [row.user_id]);
}

function authMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  checkToken(h.split(' ')[1]).then(user => {
    if (!user) return res.status(401).json({ error: 'Session expired, please login again' });
    req.user = user;
    next();
  }).catch(() => res.status(500).json({ error: 'Auth error' }));
}

function calcExpiry(label, customDateISO) {
  if (customDateISO) {
    const d = new Date(customDateISO);
    if (isNaN(d.getTime())) return null;
    return d.toISOString();
  }
  if (!label || label === 'unlimited') return null;
  const map = { '1h': 3600, '4h': 14400, '12h': 43200, '1d': 86400, '3d': 259200, '7d': 604800, '14d': 1209600, '30d': 2592000, '90d': 7776000 };
  const s = map[label];
  return s ? new Date(Date.now() + s * 1000).toISOString() : null;
}

// ==================== ROUTES ====================
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => res.json({ name: 'Elite Access Server', version: '6.2-pg', online: clients.size, time: utcNow() }));

// ==================== REGISTER ====================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role, securityQuestion, securityAnswer } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!/^[a-zA-Z0-9_.]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 chars (letters, numbers, . _)' });
    if (!password || password.length < 4) return res.status(400).json({ error: 'Password required (min 4 characters)' });
    if (await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username])) return res.status(409).json({ error: 'Username already taken' });

    const userRole = role === 'owner' ? 'owner' : 'receiver';
    const ip = getIP(req);
    const now = utcNow();

    if (userRole === 'receiver') {
      const existing = await dbGet('SELECT * FROM users WHERE ip = $1 AND role = $2', [ip, 'receiver']);
      if (existing) return res.status(403).json({ error: 'An account already exists from this device. Your existing username is: ' + existing.username, code: 'IP_DUPLICATE', existingUsername: existing.username });
      if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' });
    }

    const id = uuidv4();
    const uninstallToken = crypto.randomBytes(32).toString('hex');
    const sqHash = securityAnswer ? hash(securityAnswer.toLowerCase().trim()) : null;
    await dbRun('INSERT INTO users (id, username, password_hash, role, ip, security_question, security_answer_hash, uninstall_token, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [id, username, hash(password), userRole, ip, securityQuestion || null, sqHash, uninstallToken, now]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [id, 'registered', null, userRole + ' account created', now]);

    // Store initial device for receivers
    if (userRole === 'receiver') {
      const deviceId = req.body.deviceId || null;
      if (deviceId) {
        const ua = req.headers['user-agent'] || 'unknown';
        await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['device_history_' + id, JSON.stringify([{ deviceId, ip, lastSeen: now, ua }])]);
      }
      await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['ip_history_' + id, JSON.stringify([ip])]);
    }

    res.status(201).json({ id, username, role: userRole, token: await makeToken(id), uninstallToken });
  } catch(e) { console.error('Register:', e); res.status(500).json({ error: 'Server error' }); }
});

// ==================== LOGIN ====================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (!verify(password, user.password_hash)) return res.status(401).json({ error: 'Wrong password' });

    const ip = getIP(req);
    const now = utcNow();

    // Check if user is blocked
    const blockedRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['blocked_' + user.id]);
    if (blockedRow && blockedRow.value === '1') return res.status(403).json({ error: 'Your account has been blocked. Contact the owner.' });

    // Smart device + IP tracking for receivers
    if (user.role === 'receiver') {
      const deviceId = req.body.deviceId || null;
      const ipLimitRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['ip_limit_' + user.id]);
      const deviceLimit = ipLimitRow ? parseInt(ipLimitRow.value) : 1;

      // Load device history: [{ deviceId, ip, lastSeen, ua }]
      const devHistRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['device_history_' + user.id]);
      let devices = devHistRow ? JSON.parse(devHistRow.value) : [];

      // Also keep IP history for owner visibility
      const ipHistoryRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['ip_history_' + user.id]);
      let knownIPs = ipHistoryRow ? JSON.parse(ipHistoryRow.value) : [];
      if (user.ip && !knownIPs.includes(user.ip)) knownIPs.push(user.ip);
      if (!knownIPs.includes(ip)) knownIPs.push(ip);

      const ua = req.headers['user-agent'] || 'unknown';
      const knownDevice = deviceId ? devices.find(d => d.deviceId === deviceId) : null;

      if (knownDevice) {
        // Same device, just update IP and last seen — always allowed
        knownDevice.ip = ip;
        knownDevice.lastSeen = now;
        knownDevice.ua = ua;
      } else if (deviceId) {
        // New device — check limit
        if (devices.length >= deviceLimit) {
          // Lock the account
          await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['blocked_' + user.id, '1']);
          await dbRun('UPDATE sessions SET revoked = 1 WHERE to_user_id = $1 AND revoked = 0', [user.id]);
          await dbRun('DELETE FROM tokens WHERE user_id = $1', [user.id]);
          await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [user.id, 'device_locked', null, 'New device ' + deviceId.slice(0,8) + '… from IP ' + ip + ' — limit ' + deviceLimit + ' device(s). Known: ' + devices.map(d => d.deviceId.slice(0,8)).join(', '), now]);
          for (const [uid] of clients) {
            const u2 = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
            if (u2 && u2.role === 'owner') sendWS(uid, { type: 'device-violation', username: user.username, triedIP: ip, deviceId: deviceId.slice(0,8), knownDevices: devices.length, limit: deviceLimit });
          }
          return res.status(403).json({ error: 'Account locked. New device detected (IP: ' + ip + '). Your account allows ' + deviceLimit + ' device(s). Contact the owner.' });
        }
        devices.push({ deviceId, ip, lastSeen: now, ua });
      } else {
        // No deviceId sent (old extension version) — fall back to IP-based check
        const ipOnly = devices.length === 0 && knownIPs.length > 0;
        if (ipOnly && knownIPs.length > deviceLimit) {
          // Old behavior for old extensions without deviceId
        }
      }

      await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['device_history_' + user.id, JSON.stringify(devices)]);
      await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['ip_history_' + user.id, JSON.stringify(knownIPs)]);
      await dbRun('UPDATE users SET ip = $1 WHERE id = $2', [ip, user.id]);
    }

    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [user.id, 'login', null, 'Logged in from ' + ip, now]);
    res.json({ id: user.id, username: user.username, role: user.role, token: await makeToken(user.id), uninstallToken: user.uninstall_token });
  } catch(e) { console.error('Login:', e); res.status(500).json({ error: 'Server error' }); }
});

// ==================== SELF-RECOVERY ====================
app.post('/api/recover/question', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Enter your username' });
    const user = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!user) return res.status(404).json({ error: 'Username not found' });
    if (!user.security_question) return res.status(400).json({ error: 'No security question set. Contact the account owner.' });
    res.json({ question: user.security_question });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/recover/verify', async (req, res) => {
  try {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'Password too short (min 4)' });
    const user = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.security_answer_hash) return res.status(400).json({ error: 'No security question set' });
    if (!verify(answer.toLowerCase().trim(), user.security_answer_hash)) {
      await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [user.id, 'recovery_failed', null, 'Wrong security answer', utcNow()]);
      return res.status(401).json({ error: 'Wrong answer. Try again or contact the account owner.' });
    }
    await dbRun('UPDATE users SET password_hash = $1 WHERE id = $2', [hash(newPassword), user.id]);
    await dbRun('DELETE FROM tokens WHERE user_id = $1', [user.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [user.id, 'password_recovered', null, 'Reset via security question', utcNow()]);
    res.json({ success: true, message: 'Password reset! Login with your new password.' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== UNINSTALL HANDLER ====================
app.get('/api/uninstall/:token', async (req, res) => {
  try {
    const user = await dbGet('SELECT * FROM users WHERE uninstall_token = $1', [req.params.token]);
    if (!user) return res.send('<html><body><h2>Session ended.</h2></body></html>');

    const now = utcNow();
    const active = await dbAll('SELECT * FROM sessions WHERE to_user_id = $1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > $2)', [user.id, now]);

    await dbRun('UPDATE sessions SET revoked = 1 WHERE to_user_id = $1 AND revoked = 0', [user.id]);
    await dbRun('DELETE FROM tokens WHERE user_id = $1', [user.id]);
    await dbRun('DELETE FROM settings WHERE key = $1', ['hb_' + user.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [user.id, 'extension_removed', null, 'Extension uninstalled — all sessions revoked (' + active.length + ' sessions)', now]);

    for (const [uid, ws] of clients) {
      const u = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
      if (u && u.role === 'owner') {
        sendWS(uid, { type: 'receiver-offline', username: user.username, sessionsRevoked: active.length });
      }
    }

    await dbRun('UPDATE users SET uninstall_token = $1 WHERE id = $2', [crypto.randomBytes(32).toString('hex'), user.id]);

    res.send('<html><head><style>body{background:#0a0a0e;color:#f0ece4;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}h2{color:#D4AF37}p{color:#9a968e;margin-top:8px}</style></head><body><div><h2>Elite Access</h2><p>Account will logout shortly.</p><p style="font-size:12px;color:#555">Kindly do not remove the extension.</p></div></body></html>');
  } catch(e) { console.error('Uninstall:', e); res.send('<html><body><h2>Error</h2></body></html>'); }
});

// ==================== STANDARD ROUTES ====================
app.get('/api/me', authMW, (req, res) => res.json({ id: req.user.id, username: req.user.username, role: req.user.role }));

app.get('/api/user/:username', authMW, async (req, res) => {
  try {
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [req.params.username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ id: u.id, username: u.username, role: u.role, online: clients.has(u.id) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/reset-password', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { username, newPassword } = req.body;
    if (!username || !newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Username and new password (min 4) required' });
    const target = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!target) return res.status(404).json({ error: 'User not found' });
    const now = utcNow();
    await dbRun('UPDATE users SET password_hash = $1 WHERE id = $2', [hash(newPassword), target.id]);
    await dbRun('DELETE FROM tokens WHERE user_id = $1', [target.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [target.id, 'password_reset', null, 'Reset by owner', now]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'reset_password', null, 'Reset password for ' + username, now]);
    res.json({ success: true, message: 'Password reset for ' + username });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/receivers', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const recs = await dbAll("SELECT id, username, ip, created_at FROM users WHERE role = 'receiver' ORDER BY created_at DESC");
    res.json({ receivers: recs.map(r => ({ ...r, online: clients.has(r.id) })) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== SEND (owner only) ====================
app.post('/api/send', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Only owner can share', code: 'RECEIVER_CANNOT_SEND' });
    const { toUsername, domain, sessionData, duration, customDate } = req.body;
    if (!toUsername || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });
    const to = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [toUsername]);
    if (!to) return res.status(404).json({ error: 'User not found' });
    if (to.id === req.user.id) return res.status(400).json({ error: 'Cannot send to yourself' });
    const now = utcNow();
    const received = await dbGet('SELECT id FROM sessions WHERE to_user_id = $1 AND domain = $2 AND revoked = 0 AND (expires_at IS NULL OR expires_at > $3) LIMIT 1', [req.user.id, domain, now]);
    if (received) return res.status(403).json({ error: 'Reshare not allowed', code: 'RESHARE_BLOCKED' });

    const id = uuidv4();
    const expiresAt = calcExpiry(duration || 'unlimited', customDate);
    const durationLabel = duration || 'unlimited';

    await dbRun('INSERT INTO sessions (id, from_user_id, from_username, to_user_id, to_username, domain, session_data, duration_label, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [id, req.user.id, req.user.username, to.id, to.username, domain, JSON.stringify(sessionData), durationLabel, expiresAt, now]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'sent', domain, 'To ' + to.username + ' (' + durationLabel + ')', now]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [to.id, 'received', domain, 'From ' + req.user.username + ' (' + durationLabel + ')', now]);

    const delivered = sendWS(to.id, { type: 'session-received', sessionId: id, from: req.user.username, domain, durationLabel, expiresAt, sessionData, timestamp: now });
    if (delivered) await dbRun('UPDATE sessions SET delivered = 1 WHERE id = $1', [id]);
    res.json({ id, delivered, message: delivered ? 'Delivered instantly!' : 'User offline — will receive later.' });
  } catch(e) { console.error('Send:', e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/inbox', authMW, async (req, res) => {
  try {
    res.json({ sessions: await dbAll('SELECT id, from_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE to_user_id = $1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > $2) ORDER BY created_at DESC', [req.user.id, utcNow()]) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/sent', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.json({ sessions: [] });
    res.json({ sessions: await dbAll('SELECT id, to_username, domain, duration_label, expires_at, revoked, delivered, applied, created_at FROM sessions WHERE from_user_id = $1 ORDER BY created_at DESC LIMIT 200', [req.user.id]) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/session/:id', authMW, async (req, res) => {
  try {
    const s = await dbGet('SELECT * FROM sessions WHERE id = $1', [req.params.id]);
    if (!s) return res.status(404).json({ error: 'Session not found' });
    if (s.to_user_id !== req.user.id) return res.status(403).json({ error: 'Not your session' });
    if (s.revoked) return res.status(410).json({ error: 'Access revoked by sender' });
    if (s.expires_at && new Date(s.expires_at) < new Date()) return res.status(410).json({ error: 'Access expired' });
    await dbRun('UPDATE sessions SET applied = 1 WHERE id = $1', [s.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'applied', s.domain, 'Logged into ' + s.domain, utcNow()]);
    res.json({ id: s.id, domain: s.domain, sessionData: JSON.parse(s.session_data), from: s.from_username });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/session/:id/dismiss', authMW, async (req, res) => {
  try {
    const s = await dbGet('SELECT * FROM sessions WHERE id = $1', [req.params.id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    if (s.to_user_id !== req.user.id) return res.status(403).json({ error: 'Not your session' });
    await dbRun('UPDATE sessions SET revoked = 1 WHERE id = $1', [s.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'dismissed', s.domain, 'User dismissed session', utcNow()]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/revoke/:id', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const s = await dbGet('SELECT * FROM sessions WHERE id = $1', [req.params.id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    if (s.from_user_id !== req.user.id) return res.status(403).json({ error: 'Only sender can revoke' });
    const now = utcNow();
    await dbRun('UPDATE sessions SET revoked = 1 WHERE id = $1 AND from_user_id = $2', [req.params.id, req.user.id]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'revoked', s.domain, 'Revoked from ' + s.to_username, now]);
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [s.to_user_id, 'access_revoked', s.domain, 'Revoked by ' + req.user.username, now]);
    sendWS(s.to_user_id, { type: 'force-logout', sessionId: req.params.id, domain: s.domain, reason: 'Access revoked by ' + req.user.username });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/history', authMW, async (req, res) => {
  try { res.json({ history: await dbAll('SELECT action, domain, detail, created_at FROM history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100', [req.user.id]) }); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== USER ACTIVITY (owner views per-user history) ====================
app.get('/api/user-activity/:username', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [req.params.username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const history = await dbAll('SELECT action, domain, detail, created_at FROM history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100', [u.id]);
    const activeSessions = await dbAll('SELECT id, from_username, domain, duration_label, expires_at, revoked, applied, delivered, created_at FROM sessions WHERE to_user_id = $1 ORDER BY created_at DESC LIMIT 50', [u.id]);
    const hbRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['hb_' + u.id]);
    res.json({
      username: u.username,
      ip: u.ip,
      role: u.role,
      online: clients.has(u.id),
      lastHeartbeat: hbRow ? hbRow.value : null,
      registeredAt: u.created_at,
      history,
      sessions: activeSessions
    });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== TAMPER DETECTION ====================
app.post('/api/tamper', authMW, async (req, res) => {
  try {
    const { reason, extensionName } = req.body;
    const now = utcNow();
    await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'tamper_detected', null, (extensionName || '') + ' — ' + (reason || 'Tamper'), now]);

    const active = await dbAll('SELECT * FROM sessions WHERE to_user_id = $1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > $2)', [req.user.id, now]);
    for (const s of active) {
      sendWS(req.user.id, { type: 'force-logout', sessionId: s.id, domain: s.domain, reason: 'Security violation — ' + (extensionName || 'tamper detected') });
    }

    await dbRun('UPDATE sessions SET revoked = 1 WHERE to_user_id = $1 AND revoked = 0', [req.user.id]);
    await dbRun('DELETE FROM tokens WHERE user_id = $1', [req.user.id]);
    await dbRun('DELETE FROM settings WHERE key = $1', ['hb_' + req.user.id]);

    for (const [uid, ws] of clients) {
      const u = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
      if (u && u.role === 'owner') {
        sendWS(uid, { type: 'receiver-offline', username: req.user.username, sessionsRevoked: active.length });
      }
    }

    res.json({ ok: true, revoked: active.length });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== SETTINGS (About info) ====================
app.get('/api/about', async (req, res) => {
  try {
    const row = await dbGet('SELECT value FROM settings WHERE key = $1', ['about']);
    if (!row) return res.json({ about: { developer: '', description: '', website: '', instagram: '', facebook: '', twitter: '', telegram: '', email: '' } });
    res.json({ about: JSON.parse(row.value) });
  } catch(e) { res.json({ about: {} }); }
});

app.post('/api/about', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { about } = req.body;
    if (!about) return res.status(400).json({ error: 'About data required' });
    const json = JSON.stringify(about);
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['about', json]);
    res.json({ success: true, message: 'About info updated for all users' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Heartbeat endpoint
app.post('/api/heartbeat', authMW, async (req, res) => {
  try {
    const key = 'hb_' + req.user.id;
    const now = utcNow();
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', [key, now]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/logout', authMW, async (req, res) => {
  try {
    await dbRun('DELETE FROM tokens WHERE token = $1', [req.headers.authorization.split(' ')[1]]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== EXTENSION UPDATE ====================
app.get('/api/check-update', async (req, res) => {
  try {
    const row = await dbGet('SELECT value FROM settings WHERE key = $1', ['ext_update']);
    if (!row) return res.json({ update: false, forceUpdate: false });
    const info = JSON.parse(row.value);
    const clientVer = req.query.v || '0';
    const minVer = info.minVersion || '0';
    const isOld = clientVer !== info.version;
    const isForced = _versionCompare(clientVer, minVer) < 0;
    res.json({ update: isOld, forceUpdate: isForced, version: info.version, minVersion: minVer, downloadUrl: info.downloadUrl || '', message: info.message || '' });
  } catch(e) { res.json({ update: false, forceUpdate: false }); }
});

function _versionCompare(a, b) {
  var pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var na = pa[i] || 0, nb = pb[i] || 0;
    if (na < nb) return -1; if (na > nb) return 1;
  }
  return 0;
}

app.post('/api/set-update', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { version, downloadUrl, message, forceUpdate } = req.body;
    if (!version) return res.status(400).json({ error: 'Version required' });
    const minVersion = forceUpdate ? version : '0';
    const json = JSON.stringify({ version, downloadUrl: downloadUrl || '', message: message || '', minVersion });
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['ext_update', json]);
    res.json({ success: true, message: 'Update info set for version ' + version + (forceUpdate ? ' (FORCED)' : '') });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== SAVED SESSIONS ====================
app.post('/api/saved-sessions', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { label, domain, sessionData } = req.body;
    if (!label || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });
    const id = uuidv4();
    const now = utcNow();
    await dbRun('INSERT INTO saved_sessions (id, user_id, label, domain, session_data, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [id, req.user.id, label, domain, JSON.stringify(sessionData), now, now]);
    res.json({ id, label, domain, message: 'Session saved!' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/saved-sessions', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.json({ sessions: [] });
    res.json({ sessions: await dbAll('SELECT id, label, domain, created_at, updated_at FROM saved_sessions WHERE user_id = $1 ORDER BY updated_at DESC', [req.user.id]) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/saved-sessions/:id', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { sessionData } = req.body;
    if (!sessionData) return res.status(400).json({ error: 'Missing session data' });
    const s = await dbGet('SELECT * FROM saved_sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    await dbRun('UPDATE saved_sessions SET session_data = $1, updated_at = $2 WHERE id = $3', [JSON.stringify(sessionData), utcNow(), req.params.id]);
    res.json({ success: true, message: 'Session updated!' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/saved-sessions/:id', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    await dbRun('DELETE FROM saved_sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/saved-sessions/:id', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const s = await dbGet('SELECT * FROM saved_sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json({ id: s.id, label: s.label, domain: s.domain, sessionData: JSON.parse(s.session_data), created_at: s.created_at, updated_at: s.updated_at });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Multi-send: send saved session to multiple users at once
app.post('/api/send-multi', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { usernames, domain, sessionData, duration, customDate } = req.body;
    if (!usernames || !Array.isArray(usernames) || !usernames.length || !domain || !sessionData) return res.status(400).json({ error: 'Missing fields' });
    const now = utcNow();
    const expiresAt = calcExpiry(duration || 'unlimited', customDate);
    const durationLabel = duration || 'unlimited';
    const results = [];
    for (const toUsername of usernames) {
      try {
        const to = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [toUsername]);
        if (!to) { results.push({ username: toUsername, error: 'User not found' }); continue; }
        if (to.id === req.user.id) { results.push({ username: toUsername, error: 'Cannot send to yourself' }); continue; }
        const id = uuidv4();
        await dbRun('INSERT INTO sessions (id, from_user_id, from_username, to_user_id, to_username, domain, session_data, duration_label, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [id, req.user.id, req.user.username, to.id, to.username, domain, JSON.stringify(sessionData), durationLabel, expiresAt, now]);
        await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, 'sent', domain, 'To ' + to.username + ' (' + durationLabel + ')', now]);
        await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [to.id, 'received', domain, 'From ' + req.user.username + ' (' + durationLabel + ')', now]);
        const delivered = sendWS(to.id, { type: 'session-received', sessionId: id, from: req.user.username, domain, durationLabel, expiresAt, sessionData, timestamp: now });
        if (delivered) await dbRun('UPDATE sessions SET delivered = 1 WHERE id = $1', [id]);
        results.push({ username: to.username, id, delivered, ok: true });
      } catch(e) { results.push({ username: toUsername, error: e.message }); }
    }
    res.json({ results, total: usernames.length, sent: results.filter(r => r.ok).length });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Check if a saved session is still valid (cookies still active)
app.post('/api/check-session-status', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { savedSessionId } = req.body;
    const s = await dbGet('SELECT * FROM saved_sessions WHERE id = $1 AND user_id = $2', [savedSessionId, req.user.id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const sd = JSON.parse(s.session_data);
    const activeSessions = await dbAll('SELECT id, to_username, revoked, applied, expires_at, created_at FROM sessions WHERE from_user_id = $1 AND domain = $2 AND revoked = 0 ORDER BY created_at DESC LIMIT 50', [req.user.id, s.domain]);
    res.json({ domain: s.domain, activeSessions, updatedAt: s.updated_at });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== BLOCKED URLS ====================
app.get('/api/blocked-urls', authMW, async (req, res) => {
  try {
    const row = await dbGet('SELECT value FROM settings WHERE key = $1', ['blocked_urls']);
    res.json({ urls: row ? JSON.parse(row.value) : [] });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/blocked-urls', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { urls } = req.body;
    if (!Array.isArray(urls)) return res.status(400).json({ error: 'urls must be an array' });
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['blocked_urls', JSON.stringify(urls)]);
    // Push to all online receivers immediately
    for (const [uid, ws] of clients) {
      const u = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
      if (u && u.role === 'receiver') sendWS(uid, { type: 'blocked-urls-updated', urls });
    }
    res.json({ ok: true, count: urls.length });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== USER MANAGEMENT (block, delete, IP limit) ====================
app.post('/api/block-user', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { username, blocked } = req.body;
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['blocked_' + u.id, blocked ? '1' : '0']);
    if (blocked) {
      await dbRun('UPDATE sessions SET revoked = 1 WHERE to_user_id = $1 AND revoked = 0', [u.id]);
      await dbRun('DELETE FROM tokens WHERE user_id = $1', [u.id]);
      sendWS(u.id, { type: 'force-logout', reason: 'Your account has been blocked by the owner' });
      await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [u.id, 'blocked', null, 'Account blocked by owner', utcNow()]);
    } else {
      await dbRun('DELETE FROM settings WHERE key = $1', ['blocked_' + u.id]);
      // Clear stored IPs and devices so next login captures fresh
      await dbRun('DELETE FROM settings WHERE key = $1', ['ip_history_' + u.id]);
      await dbRun('DELETE FROM settings WHERE key = $1', ['device_history_' + u.id]);
      await dbRun('UPDATE users SET ip = NULL WHERE id = $1', [u.id]);
      await dbRun('INSERT INTO history (user_id, action, domain, detail, created_at) VALUES ($1,$2,$3,$4,$5)', [u.id, 'unblocked', null, 'Account unblocked by owner — IPs & devices reset', utcNow()]);
    }
    res.json({ ok: true, blocked });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/delete-user', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { username } = req.body;
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.role === 'owner') return res.status(403).json({ error: 'Cannot delete owner account' });
    sendWS(u.id, { type: 'force-logout', reason: 'Your account has been deleted' });
    await dbRun('UPDATE sessions SET revoked = 1 WHERE to_user_id = $1 AND revoked = 0', [u.id]);
    await dbRun('DELETE FROM tokens WHERE user_id = $1', [u.id]);
    await dbRun('DELETE FROM history WHERE user_id = $1', [u.id]);
    await dbRun('DELETE FROM support_messages WHERE from_user_id = $1 OR to_user_id = $1', [u.id]);
    await dbRun('DELETE FROM settings WHERE key LIKE $1', ['%' + u.id + '%']);
    await dbRun('DELETE FROM users WHERE id = $1', [u.id]);
    res.json({ ok: true, message: 'User ' + u.username + ' deleted' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/set-ip-limit', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { username, limit } = req.body;
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const lim = Math.max(1, Math.min(10, parseInt(limit) || 1));
    await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', ['ip_limit_' + u.id, String(lim)]);
    res.json({ ok: true, username: u.username, ipLimit: lim });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/user-settings/:username', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [req.params.username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const ipLimitRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['ip_limit_' + u.id]);
    const blockedRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['blocked_' + u.id]);
    const ipHistoryRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['ip_history_' + u.id]);
    const devHistRow = await dbGet('SELECT value FROM settings WHERE key = $1', ['device_history_' + u.id]);
    const devices = devHistRow ? JSON.parse(devHistRow.value) : [];
    res.json({
      username: u.username,
      deviceLimit: ipLimitRow ? parseInt(ipLimitRow.value) : 1,
      ipLimit: ipLimitRow ? parseInt(ipLimitRow.value) : 1,
      blocked: blockedRow ? blockedRow.value === '1' : false,
      knownIPs: ipHistoryRow ? JSON.parse(ipHistoryRow.value) : [u.ip],
      devices: devices.map(d => ({ id: d.deviceId.slice(0,8) + '…', ip: d.ip, lastSeen: d.lastSeen, ua: d.ua })),
      currentIP: u.ip
    });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== SUPPORT / COMPLAINT SYSTEM ====================
// Receiver sends a support message
app.post('/api/support/send', authMW, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 1000) return res.status(400).json({ error: 'Message too long (max 1000 chars)' });
    const id = uuidv4();
    const now = utcNow();
    await dbRun('INSERT INTO support_messages (id, from_user_id, from_username, to_user_id, message, is_owner_reply, read, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, req.user.id, req.user.username, null, message.trim(), 0, 0, now]);
    // Notify owner via WS
    for (const [uid, ws] of clients) {
      const u = await dbGet('SELECT * FROM users WHERE id = $1', [uid]);
      if (u && u.role === 'owner') {
        sendWS(uid, { type: 'support-message', from: req.user.username, message: message.trim(), id, createdAt: now });
      }
    }
    res.json({ ok: true, message: 'Message sent! The owner will respond soon.' });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Receiver gets their own conversation
app.get('/api/support/my-messages', authMW, async (req, res) => {
  try {
    const msgs = await dbAll('SELECT id, from_username, message, is_owner_reply, read, created_at FROM support_messages WHERE from_user_id = $1 OR to_user_id = $1 ORDER BY created_at ASC LIMIT 200', [req.user.id]);
    res.json({ messages: msgs });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Owner: get all conversations (grouped by user)
app.get('/api/support/conversations', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    // Get distinct users who have sent messages, with latest message and unread count
    const convos = await dbAll(`
      SELECT sm.from_username as username, sm.from_user_id as user_id,
        MAX(sm.created_at) as last_message_at,
        COUNT(CASE WHEN sm.read = 0 AND sm.is_owner_reply = 0 THEN 1 END) as unread
      FROM support_messages sm
      WHERE sm.is_owner_reply = 0
      GROUP BY sm.from_user_id, sm.from_username
      ORDER BY MAX(sm.created_at) DESC
    `);
    res.json({ conversations: convos });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Owner: get messages for a specific user
app.get('/api/support/conversation/:username', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [req.params.username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    // Mark all messages from this user as read
    await dbRun('UPDATE support_messages SET read = 1 WHERE from_user_id = $1 AND is_owner_reply = 0', [u.id]);
    const msgs = await dbAll('SELECT id, from_username, message, is_owner_reply, read, created_at FROM support_messages WHERE from_user_id = $1 OR to_user_id = $1 ORDER BY created_at ASC LIMIT 200', [u.id]);
    res.json({ messages: msgs, username: u.username, online: clients.has(u.id) });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// Owner: reply to a user
app.post('/api/support/reply', authMW, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
    const { username, message } = req.body;
    if (!username || !message || !message.trim()) return res.status(400).json({ error: 'Username and message required' });
    const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const id = uuidv4();
    const now = utcNow();
    await dbRun('INSERT INTO support_messages (id, from_user_id, from_username, to_user_id, message, is_owner_reply, read, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [id, req.user.id, req.user.username, u.id, message.trim(), 1, 0, now]);
    // Notify receiver via WS
    sendWS(u.id, { type: 'support-reply', message: message.trim(), id, createdAt: now });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ==================== WEBSOCKET ====================
const clients = new Map();
wss.on('connection', (ws) => {
  let userId = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'auth') {
        const user = await checkToken(msg.token);
        if (!user) { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); ws.close(); return; }
        userId = user.id; clients.set(userId, ws);
        ws.send(JSON.stringify({ type: 'authenticated', username: user.username, role: user.role }));
        const now = utcNow();
        const pending = await dbAll('SELECT id, from_username, domain, duration_label, expires_at, revoked, applied, created_at FROM sessions WHERE to_user_id = $1 AND revoked = 0 AND (expires_at IS NULL OR expires_at > $2) ORDER BY created_at DESC', [userId, now]);
        for (const p of pending) {
          const full = await dbGet('SELECT * FROM sessions WHERE id = $1', [p.id]);
          if (full && !full.revoked && !full.delivered) {
            ws.send(JSON.stringify({ type: 'session-received', sessionId: p.id, from: p.from_username, domain: p.domain, durationLabel: p.duration_label, expiresAt: p.expires_at, sessionData: JSON.parse(full.session_data), timestamp: p.created_at }));
            await dbRun('UPDATE sessions SET delivered = 1 WHERE id = $1', [p.id]);
          }
        }
      }
      else if (msg.type === 'check-online') { const u = await dbGet('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [msg.username]); ws.send(JSON.stringify({ type: 'online-status', username: msg.username, online: u ? clients.has(u.id) : false })); }
      else if (msg.type === 'heartbeat') { if (userId) { const k = 'hb_' + userId; const n = utcNow(); await dbRun('INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2', [k, n]); } }
      else if (msg.type === 'ping') ws.send('{"type":"pong"}');
    } catch (e) { console.error('WS msg:', e.message); }
  });
  ws.on('close', () => { if (userId) clients.delete(userId); });
});

setInterval(() => { wss.clients.forEach(ws => { if (!ws.isAlive) return ws.terminate(); ws.isAlive = false; ws.ping(); }); }, 30000);
function sendWS(uid, data) { const ws = clients.get(uid); if (ws?.readyState === 1) { ws.send(JSON.stringify(data)); return true; } return false; }

// ==================== START ====================
initDB().then(() => {
  server.listen(PORT, () => console.log('Elite Access Server v6.2-pg on port ' + PORT));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
