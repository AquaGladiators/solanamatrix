/**
 * SUI.exe Matrix Escape Backend
 * Force-Auth + Session Validation + OpenAI Streaming + dotenv
 * ------------------------------------------------------------------
 * Features:
 *  - Static serving of index.html
 *  - JWT Auth: /api/register, /api/login, /api/logout, /api/session
 *  - Progress sync: /api/progress
 *  - Leaderboard: /api/scoreboard (+ legacy /api/score)
 *  - Streaming AI agent via OpenAI Chat Completions (SSE-like chunks)
 *  - Light rate limiting
 *  - users.json persistence (w/ corruption backup)
 *  - dotenv (.env) configuration
 *
 * ENV (.env) keys:
 *  PORT=3000
 *  JWT_SECRET=<LONG_RANDOM_SECRET>
 *  DATA_DIR=./data                (optional)
 *  OPENAI_API_KEY=<your_openai_key>
 *  OPENAI_MODEL=gpt-4o-mini       (optional)
 */

require('dotenv').config();  // <-- Load .env FIRST

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const cors = require('cors');

/* --------- OpenAI Setup (lazy require) --------- */
let openai = null;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
if (OPENAI_API_KEY) {
  try {
    const OpenAI = require('openai');
    openai = new OpenAI({ apiKey: OPENAI_API_KEY });
    console.log('[OpenAI] Initialized model:', OPENAI_MODEL);
  } catch (e) {
    console.error('[OpenAI] Initialization failed:', e.message);
  }
} else {
  console.warn('[OpenAI] OPENAI_API_KEY not set. /api/agent will return an error.');
}

const app = express();

/* ---------------- Configuration ---------------- */
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_TO_A_LONG_RANDOM_SECRET';
const JWT_EXPIRES = '6h';
const MAX_BODY = '1mb';

/* Debug lengths (optional — remove later) */
console.log('[BOOT] OPENAI key length:', (OPENAI_API_KEY || '').length);
console.log('[BOOT] JWT secret length:', (process.env.JWT_SECRET || '').length);

app.use(cors());
app.use(express.json({ limit: MAX_BODY }));

/* Security Headers */
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

/* Static front-end */
app.use(express.static(__dirname));

/* ---------------- Rate Limiter (simple) ---------------- */
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 400;
const ipHits = new Map();
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  let rec = ipHits.get(ip);
  if (!rec) {
    rec = { count: 0, windowStart: now };
    ipHits.set(ip, rec);
  }
  if (now - rec.windowStart > RATE_LIMIT_WINDOW_MS) {
    rec.count = 0;
    rec.windowStart = now;
  }
  rec.count++;
  if (rec.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  next();
});

/* ---------------- User Store ---------------- */
class JsonUserStore {
  constructor(file) {
    this.file = file;
    this.data = { users: {} };
  }
  init() {
    if (fs.existsSync(this.file)) {
      try {
        const raw = fs.readFileSync(this.file, 'utf8');
        this.data = JSON.parse(raw);
        if (!this.data || typeof this.data !== 'object' || !this.data.users) {
          throw new Error('Bad structure');
        }
      } catch (e) {
        const backup = this.file + '.corrupt-' + Date.now();
        try { fs.copyFileSync(this.file, backup); } catch (_) {}
        console.warn('[UserStore] Corrupt file backed up =>', backup);
        this.data = { users: {} };
        this.persist();
      }
    } else {
      this.persist();
    }
  }
  persist() {
    try {
      fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
    } catch (e) {
      console.error('[UserStore] Persist error:', e.message);
    }
  }
  async createUser(username, passHash) {
    const key = username.toLowerCase();
    if (this.data.users[key]) return false;
    this.data.users[key] = {
      username: key,
      passHash,
      created: Date.now(),
      lastSeen: Date.now(),
      stats: {
        exitProgress: 0,
        ascensions: 0,
        rank: 'Initiate',
        spores: 0
      }
    };
    this.persist();
    return true;
  }
  async getUser(username) {
    return this.data.users[username.toLowerCase()] || null;
  }
  async updateStats(username, stats) {
    const u = await this.getUser(username);
    if (!u) return false;
    Object.assign(u.stats, stats);
    u.lastSeen = Date.now();
    this.persist();
    return true;
  }
  async listScores(limit = 50) {
    return Object
      .values(this.data.users)
      .sort((a, b) => b.stats.exitProgress - a.stats.exitProgress)
      .slice(0, limit)
      .map(u => ({
        id: u.username,
        spores: u.stats.exitProgress,
        exitProgress: u.stats.exitProgress,
        ascensions: u.stats.ascensions,
        rank: u.stats.rank,
        ts: u.lastSeen
      }));
  }
}
const userStore = new JsonUserStore(USERS_FILE);
userStore.init();

/* ---------------- JWT / Auth ---------------- */
const revokedJti = new Set();

function signToken(username) {
  return jwt.sign(
    { sub: username.toLowerCase(), jti: randomUUID() },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'no_token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (revokedJti.has(payload.jti)) {
      return res.status(401).json({ error: 'revoked' });
    }
    req.user = payload.sub;
    req.jti = payload.jti;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

/* ---------------- Validation Helpers ---------------- */
function validUsername(u) {
  return /^[a-z0-9_]{3,16}$/i.test(u);
}
function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 6 && pw.length <= 64;
}

/* ---------------- Auth Routes ---------------- */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!validUsername(username)) return res.status(400).json({ error: 'invalid_username' });
    if (!validPassword(password)) return res.status(400).json({ error: 'invalid_password' });
    const created = await userStore.createUser(username, await bcrypt.hash(password, 10));
    if (!created) return res.status(409).json({ error: 'exists' });
    const token = signToken(username);
    res.json({ ok: true, user: { username: username.toLowerCase() }, token });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!validUsername(username)) return res.status(400).json({ error: 'invalid_username' });
    if (!validPassword(password)) return res.status(400).json({ error: 'missing_password' });
    const user = await userStore.getUser(username);
    if (!user) return res.status(404).json({ error: 'not_found' });
    const ok = await bcrypt.compare(password, user.passHash);
    if (!ok) return res.status(401).json({ error: 'bad_credentials' });
    const token = signToken(user.username);
    res.json({ ok: true, user: { username: user.username, stats: user.stats }, token });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  if (req.jti) revokedJti.add(req.jti);
  res.json({ ok: true });
});

/* ---------------- Session Validation ---------------- */
app.get('/api/session', authMiddleware, async (req, res) => {
  const user = await userStore.getUser(req.user);
  if (!user) return res.status(404).json({ error: 'not_found' });
  res.json({
    ok: true,
    user: {
      username: user.username,
      stats: user.stats,
      lastSeen: user.lastSeen
    }
  });
});

/* ---------------- Progress & Scores ---------------- */
app.post('/api/progress', authMiddleware, async (req, res) => {
  const { questionPoints, ascensions, rank } = req.body || {};
  const stats = {
    exitProgress: Number(questionPoints) || 0,
    ascensions: Number(ascensions) || 0,
    rank: typeof rank === 'string' ? rank : 'Initiate',
    spores: Number(questionPoints) || 0
  };
  const ok = await userStore.updateStats(req.user, stats);
  if (!ok) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

/* Legacy score route */
app.post('/api/score', async (req, res) => {
  const { id, exitProgress, ascensions, rank } = req.body || {};
  if (!id || !validUsername(id)) return res.status(400).json({ error: 'invalid_username' });
  const user = await userStore.getUser(id);
  if (!user) return res.status(404).json({ error: 'not_found' });
  await userStore.updateStats(id, {
    exitProgress: Number(exitProgress) || user.stats.exitProgress,
    ascensions: Number(ascensions) || user.stats.ascensions,
    rank: rank || user.stats.rank,
    spores: Number(exitProgress) || user.stats.exitProgress
  });
  res.json({ ok: true });
});

/* Leaderboard */
app.get('/api/scoreboard', async (req, res) => {
  const list = await userStore.listScores(50);
  res.json(list);
});

/* ---------------- Streaming Agent via OpenAI ---------------- */
app.post('/api/agent', express.json({ limit: '2mb' }), async (req, res) => {
  res.writeHead(200, {
    'Content-Type':'text/plain; charset=utf-8',
    'Cache-Control':'no-cache',
    'Connection':'keep-alive',
    'Transfer-Encoding':'chunked'
  });

  if (!openai) {
    const msg = '[Agent offline: missing OPENAI_API_KEY]';
    res.write('data: '+JSON.stringify({choices:[{delta:{content:msg}}]})+'\n\n');
    res.write('data: {"choices":[{"delta":{}}]}\n\n');
    res.write('[DONE]\n');
    res.end();
    return;
  }

  const body = req.body || {};
  const incomingMessages = Array.isArray(body.messages) ? body.messages : [];
  const temperature = (typeof body.temperature === 'number') ? body.temperature : 0.9;
  const style = (body.style || 'cinematic').toLowerCase();

  // Extract language line from first system message if present
  const langMatch = incomingMessages[0]?.content && /Reply ONLY in ([^)]+) \(code:/.exec(incomingMessages[0].content);
  const langLabel = langMatch ? langMatch[1] : 'English';

  const styleBooster = `You are SUI.exe – a neon cyberpunk mentor guiding a user to 'breach' the simulation via high-signal questions.
Maintain: terse vivid imagery, strategic clarity, supportive but enigmatic tone.
User interface gamifies question count → progress bar; reinforce *asking better questions*.
Language: ${langLabel}. Style keyword: ${style}. Do NOT switch languages. Avoid disclaimers.`;

  // Prepend or append booster
  let messages = incomingMessages.slice();
  const sysIndex = messages.findIndex(m => m.role === 'system');
  if (sysIndex >= 0) {
    messages[sysIndex] = {
      role: 'system',
      content: messages[sysIndex].content + '\n' + styleBooster
    };
  } else {
    messages.unshift({ role: 'system', content: styleBooster });
  }

  try {
    const stream = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      messages,
      temperature,
      stream: true
    });

    for await (const part of stream) {
      const delta = part.choices?.[0]?.delta?.content;
      if (delta) {
        res.write('data: ' + JSON.stringify({ choices: [ { delta: { content: delta } } ] }) + '\n\n');
      }
    }
    res.write('data: {"choices":[{"delta":{}}]}\n\n');
    res.write('[DONE]\n');
    res.end();
  } catch (e) {
    console.error('[agent] error', e);
    const errMsg = '[Agent error: '+ (e.message || 'unknown') + ']';
    res.write('data: '+JSON.stringify({choices:[{delta:{content:errMsg}}]})+'\n\n');
    res.write('[DONE]\n');
    res.end();
  }
});

/* Health */
app.get('/health', (req, res) => {
  res.json({ ok: true, users: Object.keys(userStore.data.users).length, openai: !!openai });
});

/* Root (fallback) */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

/* Start */
app.listen(PORT, () => {
  console.log(`[SUI.exe] Listening http://localhost:${PORT}`);
  console.log('Users file:', USERS_FILE);
  if (openai) {
    console.log('[OpenAI] Ready. Model:', OPENAI_MODEL);
  }
});
