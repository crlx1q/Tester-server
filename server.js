require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;
const adminPassword = process.env.ADMIN_PASSW;
const JWT_SECRET = process.env.JWT_SECRET;
const AI_KEYS_SECRET = process.env.AI_KEYS_SECRET || process.env.JWT_SECRET || '';
const JWT_EXPIRES_IN = '8h';
const secureCookie = ((process.env.COOKIE_SECURE || '').toLowerCase() === 'true') || process.env.NODE_ENV === 'production';
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS) || 10;

const MONGO_USER = process.env.USERDB;
const MONGO_PASS = process.env.PASSWDB;
const MONGO_DB_NAME = process.env.MONGO_DB_NAME || 'AIStudyMate';
const MONGO_HOST = process.env.MONGO_HOST || 'aistudymate.9ye4bug.mongodb.net';
const MONGO_APP_NAME = process.env.MONGO_APP_NAME || 'AIStudyMate';

const buildMongoUri = () => {
  if (process.env.MONGO_URI) {
    return process.env.MONGO_URI;
  }

  if (!MONGO_USER || !MONGO_PASS) {
    console.warn('[BOOT][WARN] USERDB или PASSWDB не заданы. Подключение к MongoDB не будет установлено.');
    return null;
  }

  return `mongodb+srv://${encodeURIComponent(MONGO_USER)}:${encodeURIComponent(MONGO_PASS)}@${MONGO_HOST}/${MONGO_DB_NAME}?retryWrites=true&w=majority&appName=${encodeURIComponent(MONGO_APP_NAME)}`;
};

const mongoUri = buildMongoUri();

const logSecretStatus = (name, value) => {
  if (value) {
    console.log(`[BOOT] ${name} secret загружен (${String(value).length} символов)`);
  } else {
    console.warn(`[BOOT][WARN] ${name} secret отсутствует. Настройте переменную окружения ${name}.`);
  }
};

logSecretStatus('ADMIN_PASSW', adminPassword);
logSecretStatus('JWT_SECRET', JWT_SECRET);
logSecretStatus('USERDB', MONGO_USER);
logSecretStatus('PASSWDB', MONGO_PASS ? '********' : '');

const DEFAULT_ALLOWED_ORIGINS = [
  'https://urban-shanta-chapter1-cr1-372ff024.koyeb.app',
  'http://localhost:3000'
];

const configuredOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const allowedOrigins = configuredOrigins.length ? configuredOrigins : DEFAULT_ALLOWED_ORIGINS;
console.log(`[BOOT] Разрешенные origin: ${allowedOrigins.join(', ')}`);
console.log(`[BOOT] Флаг secure для cookie: ${secureCookie}`);

const UID_PREFIX = '700';
const UID_LENGTH = 10;
const UID_RANDOM_LENGTH = UID_LENGTH - UID_PREFIX.length;

const isBcryptHash = (value) => typeof value === 'string' && value.startsWith('$2');

const verifyPassword = async (plainPassword, storedPassword) => {
  if (!storedPassword) {
    return false;
  }

  if (isBcryptHash(storedPassword)) {
    try {
      return await bcrypt.compare(plainPassword, storedPassword);
    } catch (error) {
      console.error('[SECURITY][ERROR] Сбой при сравнении пароля.', error);
      return false;
    }
  }

  return storedPassword === plainPassword;
};

const DEFAULT_BADGES = [
  { key: 'beta', icon: 'rocket' },
  { key: 'designer', icon: 'pen-tool' },
  { key: 'programmer', icon: 'terminal' },
];

const PRO_PLANS = [
  { code: '1d', days: 1, label: '1 день' },
  { code: '1m', months: 1, label: '1 месяц' },
  { code: '3m', months: 3, label: '3 месяца' },
  { code: '6m', months: 6, label: '6 месяцев' },
  { code: '1y', months: 12, label: '12 месяцев' },
  { code: 'forever', months: null, label: 'Навсегда' },
];

const PRO_PLAN_DEFAULT = 'free';
const REGISTRATION_SETTINGS_KEY = 'registration';
const SETTINGS_CACHE_TTL_MS = 30 * 1000;

const normalizeBadgeKey = (key = '') => key.trim().toLowerCase();
const getBadgeIcon = (key = '') => {
  const normalizedKey = normalizeBadgeKey(key);
  return (DEFAULT_BADGES.find((badge) => normalizeBadgeKey(badge.key) === normalizedKey)?.icon) || 'award';
};

const getPlanByCode = (code) => PRO_PLANS.find((plan) => plan.code === code);

const registrationSettingsCache = {
  value: null,
  expiresAt: 0,
};

const DEFAULT_REGISTRATION_SETTINGS = {
  frozen: false,
  message: 'Регистрация временно недоступна. Попробуйте позже.'
};

const getRegistrationSettings = async (forceRefresh = false) => {
  const now = Date.now();
  if (!forceRefresh && registrationSettingsCache.value && registrationSettingsCache.expiresAt > now) {
    return registrationSettingsCache.value;
  }

  const doc = await Setting.findOne({ key: REGISTRATION_SETTINGS_KEY }).lean();
  const value = {
    ...DEFAULT_REGISTRATION_SETTINGS,
    ...(doc?.value || {}),
  };

  registrationSettingsCache.value = value;
  registrationSettingsCache.expiresAt = now + SETTINGS_CACHE_TTL_MS;

  return value;
};

const setRegistrationSettings = async (value = {}) => {
  const sanitized = {
    ...DEFAULT_REGISTRATION_SETTINGS,
    ...value,
  };

  sanitized.frozen = Boolean(sanitized.frozen);
  sanitized.message = String(sanitized.message || '').trim() || DEFAULT_REGISTRATION_SETTINGS.message;

  await Setting.updateOne(
    { key: REGISTRATION_SETTINGS_KEY },
    { $set: { value: sanitized } },
    { upsert: true }
  );

  registrationSettingsCache.value = sanitized;
  registrationSettingsCache.expiresAt = Date.now() + SETTINGS_CACHE_TTL_MS;

  return sanitized;
};

const invalidateRegistrationSettingsCache = () => {
  registrationSettingsCache.value = null;
  registrationSettingsCache.expiresAt = 0;
};

const isRegistrationFrozen = async () => {
  const settings = await getRegistrationSettings();
  return Boolean(settings?.frozen);
};

const getBadgesDetailedForUid = async (uid) => {
  if (!uid) {
    return [];
  }

  const normalizedUid = uid.toString();
  const badgeDocs = await Badge.find({ holders: normalizedUid }, { key: 1, icon: 1, _id: 0 }).lean();
  return badgeDocs.map((badge) => ({
    key: badge.key,
    icon: badge.icon || getBadgeIcon(badge.key),
  }));
};

const counterSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: { type: Number, required: true, default: 0 },
}, { versionKey: false });

const userSchema = new mongoose.Schema({
  id: { type: Number, unique: true, index: true, required: true },
  uid: { type: String, unique: true, index: true, required: true },
  email: { type: String, unique: true, required: true, index: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  avatarUrl: { type: String, default: '' },
  pro: {
    status: { type: Boolean, default: false },
    startDate: { type: Date, default: null },
    endDate: { type: Date, default: null },
    updatedAt: { type: Date, default: null },
    plan: { type: String, default: PRO_PLAN_DEFAULT },
  },
  createdAt: { type: Date, default: Date.now },
}, { versionKey: false });

const badgeSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  holders: { type: [String], default: [] },
  icon: { type: String, default: 'award' },
}, { versionKey: false });

const settingsSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: { type: mongoose.Schema.Types.Mixed, default: {} },
}, { versionKey: false });

const Counter = mongoose.model('Counter', counterSchema);
const User = mongoose.model('User', userSchema);
const Badge = mongoose.model('Badge', badgeSchema);
const Setting = mongoose.model('Setting', settingsSchema);

mongoose.connection.on('error', (error) => {
  console.error('[MONGO][ERROR]', error);
});

// === Secure storage for Gemini API key ===
const GEMINI_SETTING_KEY = 'ai_gemini_key_v1';

const deriveAesKey = (secret) => {
  const normalized = String(secret || '').padEnd(32, '0').slice(0, 32);
  return Buffer.from(normalized);
};

const encryptText = (plain, secret) => {
  if (!secret) throw new Error('AI_KEYS_SECRET is not configured');
  const key = deriveAesKey(secret);
  const iv = crypto.randomBytes(12); // GCM IV
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    data: enc.toString('base64'),
    tag: tag.toString('base64'),
  };
};

const decryptText = (payload, secret) => {
  if (!secret) throw new Error('AI_KEYS_SECRET is not configured');
  if (!payload || !payload.iv || !payload.data || !payload.tag) return '';
  const key = deriveAesKey(secret);
  const iv = Buffer.from(payload.iv, 'base64');
  const data = Buffer.from(payload.data, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
};

const saveGeminiKey = async (apiKey) => {
  const enc = encryptText(apiKey, AI_KEYS_SECRET);
  const doc = {
    enc,
    last4: String(apiKey).slice(-4),
    updatedAt: new Date(),
  };
  await Setting.updateOne(
    { key: GEMINI_SETTING_KEY },
    { $set: { value: doc } },
    { upsert: true }
  );
  return { last4: doc.last4, updatedAt: doc.updatedAt };
};

const loadGeminiKey = async () => {
  const doc = await Setting.findOne({ key: GEMINI_SETTING_KEY }, { value: 1, _id: 0 }).lean();
  if (!doc?.value) return '';
  try {
    return decryptText(doc.value.enc, AI_KEYS_SECRET);
  } catch (e) {
    console.error('[AI][ERROR] Failed to decrypt Gemini key', e);
    return '';
  }
};

mongoose.connection.on('disconnected', () => {
  console.warn('[MONGO] Соединение с MongoDB потеряно.');
});

const ensureDefaultBadges = async () => {
  for (const { key, icon } of DEFAULT_BADGES) {
    const normalizedKey = normalizeBadgeKey(key);
    try {
      await Badge.updateOne(
        { key: normalizedKey },
        {
          $setOnInsert: { holders: [] },
          $set: { icon: icon || getBadgeIcon(normalizedKey) }
        },
        { upsert: true }
      );
    } catch (error) {
      console.error(`[MONGO][ERROR] Не удалось обеспечить наличие бейджа ${normalizedKey}.`, error);
    }
  }
};

const initializeMongo = async () => {
  if (!mongoUri) {
    return;
  }

  try {
    await mongoose.connect(mongoUri, {
      maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE || 10),
    });
    console.log('[BOOT] Установлено соединение с MongoDB Atlas.');
    await ensureDefaultBadges();
  } catch (error) {
    console.error('[BOOT][ERROR] Не удалось подключиться к MongoDB.', error);
  }
};

initializeMongo().catch((error) => {
  console.error('[BOOT][ERROR] Ошибка инициализации MongoDB.', error);
});

const getNextSequence = async (sequenceKey) => {
  const counter = await Counter.findOneAndUpdate(
    { key: sequenceKey },
    { $inc: { value: 1 } },
    { new: true, upsert: true, setDefaultsOnInsert: true }
  ).lean();
  return counter.value;
};

const generateUid = async () => {
  while (true) {
    const randomPart = Math.floor(Math.random() * Math.pow(10, UID_RANDOM_LENGTH))
      .toString()
      .padStart(UID_RANDOM_LENGTH, '0');
    const uid = `${UID_PREFIX}${randomPart}`;
    const exists = await User.exists({ uid });
    if (!exists) {
      return uid;
    }
  }
};

const buildUserResponse = async (userDoc) => {
  if (!userDoc) {
    return null;
  }

  const user = userDoc.toObject ? userDoc.toObject() : { ...userDoc };
  const { password, ...rest } = user;

  if (rest.createdAt instanceof Date) {
    rest.createdAt = rest.createdAt.toISOString();
  }

  if (rest.pro) {
    const normalizedPro = normalizeProState(rest.pro);
    rest.pro = {
      ...normalizedPro,
      startDate: normalizedPro.startDate ? normalizedPro.startDate.toISOString() : null,
      endDate: normalizedPro.endDate ? normalizedPro.endDate.toISOString() : null,
      updatedAt: normalizedPro.updatedAt ? normalizedPro.updatedAt.toISOString() : null,
    };
  }

  const badgeDetails = await getBadgesDetailedForUid(user.uid);

  return {
    ...rest,
    badges: badgeDetails.map((badge) => badge.key),
    badgeDetails,
  };
};

const normalizeEmail = (email = '') => email.trim().toLowerCase();

const findUserById = async (userId) => {
  if (!Number.isFinite(userId)) {
    return null;
  }
  return User.findOne({ id: userId });
};

const findUserByEmail = async (email) => {
  const normalized = normalizeEmail(email);
  if (!normalized) {
    return null;
  }
  return User.findOne({ email: normalized });
};

const userExistsByEmail = async (email) => {
  const normalized = normalizeEmail(email);
  if (!normalized) {
    return false;
  }
  const exists = await User.exists({ email: normalized });
  return Boolean(exists);
};

const grantBadgesToUser = async (uid, badgeKeys = []) => {
  if (!uid || !Array.isArray(badgeKeys) || badgeKeys.length === 0) {
    return;
  }

  await Promise.all(badgeKeys.map(async (badgeKey) => {
    const normalizedKey = normalizeBadgeKey(badgeKey);
    if (!normalizedKey) {
      return;
    }

    const icon = getBadgeIcon(normalizedKey);
    try {
      await Badge.updateOne(
        { key: normalizedKey },
        {
          $set: { icon },
          $setOnInsert: { key: normalizedKey },
          $addToSet: { holders: uid.toString() }
        },
        { upsert: true }
      );
    } catch (error) {
      console.error(`[BADGES][ERROR] Не удалось выдать бейдж ${normalizedKey} пользователю ${uid}.`, error);
      throw error;
    }
  }));
};

const revokeBadgesFromUser = async (uid, badgeKeys = []) => {
  if (!uid || !Array.isArray(badgeKeys) || badgeKeys.length === 0) {
    return;
  }

  await Badge.updateMany(
    { key: { $in: badgeKeys.map((key) => normalizeBadgeKey(key)).filter(Boolean) } },
    { $pull: { holders: uid.toString() } }
  );
};

const wipeUserBadges = async (uid) => {
  if (!uid) {
    return;
  }

  await Badge.updateMany(
    {},
    { $pull: { holders: uid.toString() } }
  );
};

// Middleware
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  referrerPolicy: { policy: 'no-referrer' }
}));

if (process.env.FORCE_HTTPS === 'true') {
  console.log('[BOOT] Включен режим принудительного HTTPS (FORCE_HTTPS=true).');
  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      return next();
    }
    const host = req.headers.host;
    const url = req.originalUrl || req.url;
    return res.redirect(301, `https://${host}${url}`);
  });

  app.use(helmet.hsts({
    maxAge: 60 * 60 * 24 * 365,
    includeSubDomains: true,
    preload: true
  }));
} else {
  console.warn('[BOOT] FORCE_HTTPS выключен. HTTP соединения разрешены.');
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`[CORS] Заблокирован запрос с origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 204
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много запросов. Повторите позже.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много попыток. Повторите позже.' }
});

const buildCodeLimiter = (message) => rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message },
  keyGenerator: (req) => {
    const email = req.body?.email;
    if (typeof email === 'string' && email.trim()) {
      return email.trim().toLowerCase();
    }
    return req.ip;
  }
});

// --- Admin: Gemini API key management ---
app.post('/admin/ai/gemini-key', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const { apiKey } = req.body || {};
    if (!apiKey || typeof apiKey !== 'string' || apiKey.trim().length < 10) {
      return res.status(400).json({ success: false, message: 'Некорректный ключ API' });
    }
    const info = await saveGeminiKey(apiKey.trim());
    res.json({ success: true, last4: info.last4, updatedAt: info.updatedAt });
  } catch (error) {
    console.error('[ADMIN][ERROR] gemini-key', error);
    res.status(500).json({ success: false, message: 'Не удалось сохранить ключ Gemini' });
  }
});

app.get('/admin/ai/gemini-key', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const doc = await Setting.findOne({ key: GEMINI_SETTING_KEY }, { value: 1, _id: 0 }).lean();
    if (!doc?.value) {
      return res.json({ configured: false });
    }
    res.json({ configured: true, last4: doc.value.last4, updatedAt: doc.value.updatedAt });
  } catch (error) {
    console.error('[ADMIN][ERROR] get gemini-key', error);
    res.status(500).json({ success: false, message: 'Не удалось получить статус ключа Gemini' });
  }
});

// --- AI Proxy (Gemini) ---
const callGemini = (apiKey, payload) => new Promise((resolve, reject) => {
  const path = `/v1beta/models/gemini-2.0-flash-preview-12-20:generateContent?key=${encodeURIComponent(apiKey)}`;
  const options = {
    hostname: 'generativelanguage.googleapis.com',
    method: 'POST',
    path,
    headers: { 'Content-Type': 'application/json' },
  };
  const req = https.request(options, (res2) => {
    let raw = '';
    res2.on('data', (chunk) => raw += chunk);
    res2.on('end', () => {
      try {
        const json = JSON.parse(raw);
        resolve(json);
      } catch (e) {
        reject(e);
      }
    });
  });
  req.on('error', reject);
  req.write(JSON.stringify(payload));
  req.end();
});

const parseAnalysisResponse = (responseText = '') => {
  const lines = String(responseText).split('\n');
  let summary = '';
  const keyPoints = [];
  const questions = [];
  let current = '';
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.includes('сводка') || lower.includes('summary')) { current = 'summary'; continue; }
    if (lower.includes('ключевые') || lower.includes('key points')) { current = 'keyPoints'; continue; }
    if (lower.includes('вопрос') || lower.includes('question')) { current = 'questions'; continue; }
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (current === 'summary') {
      summary += trimmed + ' ';
    } else if (current === 'keyPoints') {
      if (/^[\-•*]/.test(trimmed)) keyPoints.push(trimmed.slice(1).trim()); else if (trimmed.length > 10) keyPoints.push(trimmed);
    } else if (current === 'questions') {
      if (/^[\-•*]/.test(trimmed)) questions.push(trimmed.slice(1).trim()); else if (trimmed.length > 10) questions.push(trimmed);
    }
  }
  if (!summary && keyPoints.length === 0 && questions.length === 0) {
    summary = responseText.slice(0, 200);
    keyPoints.push('Анализ документа выполнен', 'Информация обработана', 'Готово к изучению');
    questions.push('Что является основной темой материала?', 'Какие ключевые концепции представлены?');
  }
  return { summary: summary.trim(), keyPoints: keyPoints.slice(0, 5), questions: questions.slice(0, 5) };
};

app.post('/ai/analyze-image', async (req, res) => {
  try {
    const { mimeType, base64Image, prompt } = req.body || {};
    if (!mimeType || !base64Image) {
      return res.status(400).json({ message: 'mimeType и base64Image обязательны' });
    }
    const apiKey = await loadGeminiKey();
    if (!apiKey) {
      return res.status(503).json({ message: 'Gemini API ключ не настроен' });
    }
    const payload = {
      contents: [
        { parts: [
          { text: (prompt && String(prompt).trim()) || 'Проанализируй этот конспект. Предоставь краткую сводку (не более 150 слов), ключевые моменты (3-5 пунктов) и возможные вопросы для теста (3-5 вопросов). Ответь на русском языке.' },
          { inlineData: { mimeType, data: base64Image } }
        ]}
      ],
      generationConfig: { temperature: 0.7, topK: 40, topP: 0.95, maxOutputTokens: 1024 }
    };
    const result = await callGemini(apiKey, payload);
    const text = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return res.json(parseAnalysisResponse(text));
  } catch (error) {
    console.error('[AI][ERROR] analyze-image', error);
    return res.status(500).json({ message: 'Ошибка анализа изображения' });
  }
});

app.post('/ai/analyze-text', async (req, res) => {
  try {
    const { transcription, prompt } = req.body || {};
    if (!transcription || typeof transcription !== 'string') {
      return res.status(400).json({ message: 'transcription обязателен' });
    }
    const apiKey = await loadGeminiKey();
    if (!apiKey) {
      return res.status(503).json({ message: 'Gemini API ключ не настроен' });
    }
    const payload = {
      contents: [ { parts: [ { text: `Проанализируй эту расшифровку лекции: "${transcription}". Предоставь краткую сводку (не более 150 слов), ключевые моменты (3-5 пунктов) и возможные вопросы для теста (3-5 вопросов). Ответь на русском языке.` } ] } ],
      generationConfig: { temperature: 0.7, topK: 40, topP: 0.95, maxOutputTokens: 1024 }
    };
    const result = await callGemini(apiKey, payload);
    const text = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return res.json(parseAnalysisResponse(text));
  } catch (error) {
    console.error('[AI][ERROR] analyze-text', error);
    return res.status(500).json({ message: 'Ошибка анализа текста' });
  }
});

app.post('/ai/chat', async (req, res) => {
  try {
    const { message, history } = req.body || {};
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ message: 'message обязателен' });
    }
    const apiKey = await loadGeminiKey();
    if (!apiKey) {
      return res.status(503).json({ message: 'Gemini API ключ не настроен' });
    }
    const contents = [];
    if (Array.isArray(history)) {
      for (const msg of history) {
        if (!msg || typeof msg.text !== 'string' || typeof msg.sender !== 'string') continue;
        contents.push({ parts: [{ text: msg.text }], role: msg.sender === 'user' ? 'user' : 'model' });
      }
    }
    contents.push({ parts: [{ text: message }], role: 'user' });
    const payload = {
      contents,
      generationConfig: { temperature: 0.9, topK: 40, topP: 0.95, maxOutputTokens: 1024 },
      systemInstruction: { parts: [{ text: 'Ты - AI-репетитор StudyMate. Помогай студентам с учебой, отвечай на вопросы, объясняй сложные концепции простым языком. Будь дружелюбным и поддерживающим. Отвечай на русском языке.' }] }
    };
    const result = await callGemini(apiKey, payload);
    const text = result?.candidates?.[0]?.content?.parts?.[0]?.text || 'Извините, не удалось получить ответ.';
    return res.json({ text });
  } catch (error) {
    console.error('[AI][ERROR] chat', error);
    return res.status(500).json({ message: 'Ошибка в чате' });
  }
});

const registrationCodeLimiter = buildCodeLimiter('Слишком много запросов кода. Попробуйте позже.');
const passwordResetLimiter = buildCodeLimiter('Слишком много запросов кода сброса. Попробуйте позже.');

app.use(generalLimiter);

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// JWT Authentication Middleware
function authenticateJWT(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Admin Authentication Middleware
function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Admin access required' });
  }
}

// Логирование всех запросов
const SENSITIVE_FIELDS = new Set(['password', 'currentPassword', 'newPassword', 'verificationCode', 'resetCode', 'token', 'avatarBase64']);

const sanitizeSensitiveData = (value) => {
  if (Array.isArray(value)) {
    return value.map(sanitizeSensitiveData);
  }

  if (value && typeof value === 'object') {
    return Object.entries(value).reduce((acc, [key, val]) => {
      acc[key] = SENSITIVE_FIELDS.has(key) ? '[REDACTED]' : sanitizeSensitiveData(val);
      return acc;
    }, {});
  }

  return value;
};

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.originalUrl}`);

  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request body:', sanitizeSensitiveData(req.body));
  }

  next();
});

// --- Управление версиями приложения ---
const packageJsonPath = path.join(__dirname, 'package.json');

const buildDefaultTitle = (version) => `AIStudyMate v${version}`;
const buildDefaultMessage = (version) => `Доступна новая версия приложения (${version}). Обновитесь, чтобы получить последние улучшения.`;

const loadPackageVersion = () => {
  try {
    const raw = fs.readFileSync(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(raw);
    return pkg.version || '0.0.0';
  } catch (error) {
    console.error('Не удалось прочитать версию из package.json', error);
    return '0.0.0';
  }
};

let serverVersion = loadPackageVersion();
let latestVersionInfo = {
  version: serverVersion,
  title: buildDefaultTitle(serverVersion),
  message: buildDefaultMessage(serverVersion),
  downloadUrl: process.env.APP_DOWNLOAD_URL || '',
  publishedAt: new Date().toISOString(),
};

const clients = new Set();

const broadcastUpdate = (eventType = 'update_available') => {
  const payload = JSON.stringify({
    type: eventType,
    data: latestVersionInfo,
  });

  clients.forEach((client) => {
    if (client.readyState === client.OPEN) {
      try {
        client.send(payload);
      } catch (error) {
        console.error('Не удалось отправить сообщение WebSocket клиенту', error);
      }
    }
  });
};

const syncServerVersion = () => {
  const freshVersion = loadPackageVersion();
  if (!freshVersion || freshVersion === serverVersion) {
    return;
  }

  console.log(`Обнаружено изменение версии сервера: ${serverVersion} -> ${freshVersion}`);
  serverVersion = freshVersion;

  latestVersionInfo = {
    version: serverVersion,
    title: buildDefaultTitle(serverVersion),
    message: buildDefaultMessage(serverVersion),
    downloadUrl: latestVersionInfo.downloadUrl,
    publishedAt: new Date().toISOString(),
  };

  broadcastUpdate();
};

if (fs.existsSync(packageJsonPath)) {
  fs.watch(packageJsonPath, { persistent: false }, () => {
    setTimeout(syncServerVersion, 200);
  });
}

setInterval(syncServerVersion, 60 * 1000);

// --- Admin Routes ---
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (password === adminPassword) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: secureCookie,
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });
    
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: 'Invalid password' });
  }
});

app.get('/admin/verify-token', authenticateJWT, isAdmin, (req, res) => {
  res.json({ success: true });
});

app.get('/admin/users', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}).lean();
    const responses = await Promise.all(users.map((user) => buildUserResponse(user)));
    res.json(responses.filter(Boolean));
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось получить список пользователей.', error);
    res.status(500).json({ success: false, message: 'Не удалось получить пользователей' });
  }
});

const computeProDates = (planCode) => {
  const plan = getPlanByCode(planCode);
  if (!plan) return null;

  const startDate = new Date();

  // Forever plan (null months & days)
  if (plan.months === null && plan.days == null) {
    return { plan: plan.code, startDate, endDate: null };
  }

  const endDate = new Date(startDate);
  if (typeof plan.months === 'number') {
    endDate.setMonth(endDate.getMonth() + plan.months);
  } else if (typeof plan.days === 'number') {
    endDate.setDate(endDate.getDate() + plan.days);
  } else {
    return null; // invalid plan structure
  }

  return { plan: plan.code, startDate, endDate };
};

const normalizeProState = (proState = {}) => {
  if (!proState.status) {
    return {
      status: false,
      startDate: null,
      endDate: null,
      plan: PRO_PLAN_DEFAULT,
      updatedAt: new Date(),
    };
  }

  if (proState.endDate && new Date(proState.endDate).getTime() < Date.now()) {
    return {
      status: false,
      startDate: null,
      endDate: null,
      plan: PRO_PLAN_DEFAULT,
      updatedAt: new Date(),
    };
  }

  return {
    status: true,
    startDate: proState.startDate ? new Date(proState.startDate) : new Date(),
    endDate: proState.endDate ? new Date(proState.endDate) : null,
    plan: proState.plan || (proState.endDate ? 'custom' : 'forever'),
    updatedAt: new Date(),
  };
};

const addDurationToDate = (date, { months = 0, days = 0 }) => {
  const newDate = new Date(date);
  if (months) {
    newDate.setMonth(newDate.getMonth() + months);
  }
  if (days) {
    newDate.setDate(newDate.getDate() + days);
  }
  return newDate;
};

const extendProPlan = (user, planCode) => {
  const plan = getPlanByCode(planCode);
  if (!plan) {
    throw new Error(`Unknown PRO plan: ${planCode}`);
  }
  const now = new Date();
  if (!user.pro) {
    user.pro = {};
  }

  // If no active subscription or expired, start from now
  let start = user.pro.startDate && user.pro.status ? new Date(user.pro.startDate) : now;
  let end = user.pro.endDate && user.pro.status ? new Date(user.pro.endDate) : now;

  if (!user.pro.status || (user.pro.endDate && end < now)) {
    start = now;
    end = now;
  }

  if (plan.months != null) {
    end = addDurationToDate(end, { months: plan.months });
  } else if (plan.days != null) {
    end = addDurationToDate(end, { days: plan.days });
  } else {
    // forever
    end = null;
  }

  user.pro.status = true;
  user.pro.startDate = start;
  user.pro.endDate = end;
  user.pro.plan = plan.code;
  user.pro.updatedAt = new Date();
};

const applyProPlan = (user, status, planCode) => {
  user.pro = user.pro || {};

  if (!status) {
    user.pro.status = false;
    user.pro.startDate = null;
    user.pro.endDate = null;
    user.pro.plan = PRO_PLAN_DEFAULT;
    user.pro.updatedAt = new Date();
    return;
  }

  const computed = computeProDates(planCode);
  if (!computed) {
    throw new Error(`Unknown PRO plan: ${planCode}`);
  }

  user.pro.status = true;
  user.pro.startDate = computed.startDate;
  user.pro.endDate = computed.endDate;
  user.pro.plan = computed.plan;
  user.pro.updatedAt = new Date();
};

// Legacy PUT route kept for backward-compat
app.put('/admin/users/:userId/pro', authenticateJWT, isAdmin, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { status, plan } = req.body;
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ success: false, message: 'Некорректный идентификатор пользователя' });
  }

  try {
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (status) {
      const requestedPlan = plan || 'forever';
      applyProPlan(user, true, requestedPlan);
    } else {
      applyProPlan(user, false, PRO_PLAN_DEFAULT);
    }

    await user.save();

    res.json({ success: true, user: await buildUserResponse(user) });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось обновить статус PRO пользователя.', error);
    if (error.message && error.message.includes('Unknown PRO plan')) {
      return res.status(400).json({ success: false, message: 'Указан неизвестный тариф PRO' });
    }
    res.status(500).json({ success: false, message: 'Не удалось обновить статус PRO' });
  }
});

// Add duration to PRO like a bank
app.post('/admin/users/:userId/pro/add', authenticateJWT, isAdmin, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { plan } = req.body || {};
  if (!Number.isFinite(userId) || !plan) {
    return res.status(400).json({ success: false, message: 'Некорректные данные' });
  }
  try {
    const user = await findUserById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    extendProPlan(user, plan);
    await user.save();
    res.json({ success: true, user: await buildUserResponse(user) });
  } catch (error) {
    console.error('[ADMIN][ERROR] extendProPlan', error);
    res.status(500).json({ success: false, message: error.message || 'Ошибка продления PRO' });
  }
});

// Remove PRO completely
app.post('/admin/users/:userId/pro/remove', authenticateJWT, isAdmin, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ success: false, message: 'Некорректный идентификатор пользователя' });
  }
  try {
    const user = await findUserById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    user.pro = { status:false,startDate:null,endDate:null,plan:PRO_PLAN_DEFAULT,updatedAt:new Date() };
    await user.save();
    res.json({ success: true, user: await buildUserResponse(user) });
  } catch (error) {
    console.error('[ADMIN][ERROR] removePro', error);
    res.status(500).json({ success: false, message: 'Ошибка удаления PRO' });
  }
});

app.post('/admin/reload-db', authenticateJWT, isAdmin, async (req, res) => {
  try {
    await initializeMongo();
    res.json({ success: true, message: 'Соединение с базой данных обновлено' });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось переинициализировать базу данных.', error);
    res.status(500).json({ success: false, message: 'Не удалось обновить соединение с базой данных' });
  }
});

app.post('/admin/reload-badges', authenticateJWT, isAdmin, async (req, res) => {
  try {
    await ensureDefaultBadges();
    res.json({ success: true, message: 'Бейджи обновлены' });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось обновить бейджи.', error);
    res.status(500).json({ success: false, message: 'Не удалось обновить бейджи' });
  }
});

app.get('/admin/badges', authenticateJWT, isAdmin, async (req, res) => {
  try {
    await ensureDefaultBadges();

    const badgeDocs = await Badge.find({}, { key: 1, icon: 1, _id: 0 }).lean();
    const badgeMap = new Map();

    DEFAULT_BADGES.forEach(({ key, icon }) => {
      const normalizedKey = normalizeBadgeKey(key);
      badgeMap.set(normalizedKey, {
        key: normalizedKey,
        icon: icon || getBadgeIcon(normalizedKey),
      });
    });

    badgeDocs.forEach((badge) => {
      if (!badge?.key) {
        return;
      }
      const normalizedKey = normalizeBadgeKey(badge.key);
      badgeMap.set(normalizedKey, {
        key: normalizedKey,
        icon: badge.icon || getBadgeIcon(normalizedKey),
      });
    });

    res.json(Array.from(badgeMap.values()));
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось получить список бейджей.', error);
    res.status(500).json({ success: false, message: 'Не удалось получить список бейджей' });
  }
});

app.get('/admin/pro-plans', authenticateJWT, isAdmin, (req, res) => {
  res.json(PRO_PLANS);
});

app.get('/admin/settings/registration', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const settings = await getRegistrationSettings(true);
    res.json(settings);
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось получить настройки регистрации.', error);
    res.status(500).json({ success: false, message: 'Не удалось получить настройки регистрации' });
  }
});

app.post('/admin/settings/registration', authenticateJWT, isAdmin, async (req, res) => {
  const { frozen, message } = req.body || {};

  try {
    const updated = await setRegistrationSettings({ frozen, message });
    res.json({ success: true, settings: updated });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось обновить настройки регистрации.', error);
    res.status(500).json({ success: false, message: 'Не удалось обновить настройки регистрации' });
  }
});

app.post('/admin/users/:userId/badges', authenticateJWT, isAdmin, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { action, badges } = req.body || {};

  if (!Number.isFinite(userId)) {
    return res.status(400).json({ success: false, message: 'Некорректный идентификатор пользователя' });
  }

  if (!Array.isArray(badges) || badges.length === 0) {
    return res.status(400).json({ success: false, message: 'Не переданы бейджи для изменения' });
  }

  try {
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    if (action === 'grant') {
      await grantBadgesToUser(user.uid, badges);
    } else if (action === 'revoke') {
      await revokeBadgesFromUser(user.uid, badges);
    } else {
      return res.status(400).json({ success: false, message: 'Некорректное действие. Используйте grant или revoke.' });
    }

    res.json({ success: true, user: await buildUserResponse(user) });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось изменить бейджи пользователя.', error);
    res.status(500).json({ success: false, message: 'Не удалось изменить бейджи пользователя' });
  }
});

app.delete('/admin/users/:userId', authenticateJWT, isAdmin, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (!Number.isFinite(userId)) {
    return res.status(400).json({ success: false, message: 'Некорректный идентификатор пользователя' });
  }

  try {
    const user = await findUserById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    await wipeUserBadges(user.uid);
    await User.deleteOne({ id: userId });

    const normalizedEmail = normalizeEmail(user.email);
    registrationCodes.delete(normalizedEmail);
    passwordResetCodes.delete(normalizedEmail);

    res.json({ success: true, message: 'Пользователь полностью удален' });
  } catch (error) {
    console.error('[ADMIN][ERROR] Не удалось удалить пользователя.', error);
    res.status(500).json({ success: false, message: 'Не удалось удалить пользователя' });
  }
});

// --- Server Health Endpoints ---
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Server is running',
    currentVersion: serverVersion,
    latestVersion: latestVersionInfo,
  });
});

app.post('/admin/publish-update', (req, res) => {
  const { version, title, message, downloadUrl } = req.body;

  if (!version) {
    return res.status(400).json({ message: 'Необходимо указать версию обновления' });
  }

  latestVersionInfo = {
    version,
    title: title || buildDefaultTitle(version),
    message: message || buildDefaultMessage(version),
    downloadUrl: downloadUrl || latestVersionInfo.downloadUrl || process.env.APP_DOWNLOAD_URL || '',
    publishedAt: new Date().toISOString(),
  };

  console.log('Опубликована новая информация об обновлении:', latestVersionInfo);
  broadcastUpdate();

  res.status(200).json({
    message: 'Информация об обновлении успешно опубликована',
    latestVersion: latestVersionInfo,
  });
});

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const registrationCodes = new Map();
const REG_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const passwordResetCodes = new Map();
const PASSWORD_RESET_TTL_MS = 5 * 60 * 1000; // 5 minutes

const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// --- Эндпоинты для аутентификации ---

// Регистрация нового пользователя
app.post('/auth/register', authLimiter, async (req, res) => {
  const { email, password, name, verificationCode } = req.body;

  if (!email || !password || !name || !verificationCode) {
    return res.status(400).json({ message: 'Email, пароль, имя и код подтверждения обязательны' });
  }

  const trimmedEmail = email.trim();
  const trimmedName = name.trim();

  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Пароль должен содержать минимум 6 символов' });
  }

  if (trimmedName.length === 0) {
    return res.status(400).json({ message: 'Имя обязательно для заполнения' });
  }

  const normalizedEmail = normalizeEmail(trimmedEmail);

  const registrationSettings = await getRegistrationSettings();
  if (registrationSettings.frozen) {
    return res.status(423).json({
      message: registrationSettings.message,
      code: 'REGISTRATION_FROZEN',
    });
  }

  const storedCode = registrationCodes.get(normalizedEmail);
  if (!storedCode) {
    return res.status(400).json({ message: 'Код подтверждения не запрошен или истек' });
  }

  const now = Date.now();
  if (storedCode.expiresAt < now) {
    registrationCodes.delete(normalizedEmail);
    return res.status(400).json({ message: 'Код подтверждения истек. Запросите новый' });
  }

  if (storedCode.code !== verificationCode) {
    return res.status(400).json({ message: 'Неверный код подтверждения' });
  }

  const userExists = await userExistsByEmail(normalizedEmail);
  if (userExists) {
    return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
  }

  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось хешировать пароль нового пользователя.', error);
    return res.status(500).json({ message: 'Не удалось обработать пароль. Попробуйте позже.' });
  }

  try {
    const nextId = await getNextSequence('userId');
    const uid = await generateUid();
    const newUser = await User.create({
      id: nextId,
      email: normalizedEmail,
      password: hashedPassword,
      name: trimmedName,
      avatarUrl: '',
      pro: {
        status: false,
        startDate: null,
        endDate: null,
        updatedAt: null,
        plan: PRO_PLAN_DEFAULT,
      },
      uid,
    });

    registrationCodes.delete(normalizedEmail);

    res.status(201).json(await buildUserResponse(newUser));
  } catch (error) {
    console.error('[AUTH][ERROR] Не удалось создать нового пользователя.', error);
    res.status(500).json({ message: 'Не удалось создать пользователя. Попробуйте позже.' });
  }
});

app.post('/auth/request-code', registrationCodeLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const trimmedEmail = email.trim();

  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  const normalizedEmail = normalizeEmail(trimmedEmail);

  const registrationSettings = await getRegistrationSettings();
  if (registrationSettings.frozen) {
    return res.status(423).json({
      message: registrationSettings.message,
      code: 'REGISTRATION_FROZEN',
    });
  }

  const exists = await userExistsByEmail(normalizedEmail);
  if (exists) {
    return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
  }

  const code = generateCode();
  registrationCodes.set(normalizedEmail, {
    code,
    expiresAt: Date.now() + REG_CODE_TTL_MS,
  });

  console.log(`Registration code for ${trimmedEmail}: ${code}`);

  res.status(200).json({
    message: 'Код подтверждения отправлен на вашу почту',
    debug_code: code,
  });
});

app.post('/auth/reset-password/request', passwordResetLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const trimmedEmail = email.trim();

  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  const normalizedEmail = normalizeEmail(trimmedEmail);
  const user = await findUserByEmail(normalizedEmail);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь с таким email не найден' });
  }

  const code = generateCode();
  passwordResetCodes.set(normalizedEmail, {
    code,
    userId: user.id,
    expiresAt: Date.now() + PASSWORD_RESET_TTL_MS,
  });

  console.log(`Password reset code for ${trimmedEmail}: ${code}`);

  res.status(200).json({
    message: 'Код для сброса пароля отправлен на вашу почту',
    debug_code: code,
  });
});

app.post('/auth/reset-password/confirm', authLimiter, async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword) {
    return res.status(400).json({ message: 'Email, код и новый пароль обязательны' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'Новый пароль должен содержать минимум 6 символов' });
  }

  const trimmedEmail = email.trim();

  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  const normalizedEmail = normalizeEmail(trimmedEmail);
  const stored = passwordResetCodes.get(normalizedEmail);
  if (!stored) {
    return res.status(400).json({ message: 'Код сброса не запрошен или истек' });
  }

  if (stored.expiresAt < Date.now()) {
    passwordResetCodes.delete(normalizedEmail);
    return res.status(400).json({ message: 'Код сброса истек. Запросите новый' });
  }

  if (stored.code !== code) {
    return res.status(400).json({ message: 'Неверный код сброса' });
  }

  const user = await findUserById(stored.userId);
  if (!user || normalizeEmail(user.email) !== normalizedEmail) {
    passwordResetCodes.delete(normalizedEmail);
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  try {
    user.password = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
    await user.save();
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось хешировать пароль при сбросе.', error);
    return res.status(500).json({ message: 'Не удалось сбросить пароль. Попробуйте позже.' });
  }

  passwordResetCodes.delete(normalizedEmail);

  console.log(`Password reset for user ${user.email}`);

  res.status(200).json({ message: 'Пароль успешно сброшен' });
});

// Вход пользователя
app.post('/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны для заполнения' });
  }

  const user = await findUserByEmail(email);

  if (!user || !(await verifyPassword(password, user.password))) {
    return res.status(401).json({ message: 'Неверный email или пароль' });
  }
  
  console.log('User logged in:', user);

  // Отправляем пользователя без пароля
  res.status(200).json(await buildUserResponse(user));
});

// --- Эндпоинты для работы с профилем ---

// Обновление аватарки пользователя
app.post('/profile/avatar', async (req, res) => {
  const { userId, avatarBase64 } = req.body;

  if (!userId || !avatarBase64) {
    return res.status(400).json({ message: 'ID пользователя и данные аватарки обязательны' });
  }

  const numericId = Number(userId);
  if (!Number.isFinite(numericId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  const user = await findUserById(numericId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Обновляем аватарку пользователя
  user.avatarUrl = avatarBase64;
  try {
    await user.save();
  } catch (error) {
    console.error('[PROFILE][ERROR] Не удалось сохранить аватар пользователя.', error);
    return res.status(500).json({ message: 'Не удалось обновить аватар. Попробуйте позже.' });
  }
  
  console.log(`Avatar updated for user ${user.email}`);

  // Отправляем обновленные данные пользователя без пароля
  res.status(200).json(await buildUserResponse(user));
});

// Получение данных пользователя по ID
app.get('/profile/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  
  if (!Number.isFinite(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  const user = await findUserById(userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Отправляем данные пользователя без пароля
  res.status(200).json(await buildUserResponse(user));
});

// Обновление профиля пользователя (имя)
app.put('/profile/:userId', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { name } = req.body;

  if (!name || name.trim().length === 0) {
    return res.status(400).json({ message: 'Имя обязательно для заполнения' });
  }

  if (!Number.isFinite(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  const user = await findUserById(userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Обновляем имя пользователя
  user.name = name.trim();
  try {
    await user.save();
  } catch (error) {
    console.error('[PROFILE][ERROR] Не удалось обновить имя пользователя.', error);
    return res.status(500).json({ message: 'Не удалось обновить профиль. Попробуйте позже.' });
  }
  
  console.log(`Profile updated for user ${user.email}: name = ${user.name}`);

  // Отправляем обновленные данные пользователя без пароля
  res.status(200).json(await buildUserResponse(user));
});

// Смена пароля пользователя
app.put('/profile/:userId/password', async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Необходимо заполнить текущий и новый пароль' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'Новый пароль должен содержать минимум 6 символов' });
  }

  if (!Number.isFinite(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  const user = await findUserById(userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Проверяем текущий пароль
  if (!(await verifyPassword(currentPassword, user.password))) {
    return res.status(401).json({ message: 'Неверный текущий пароль' });
  }

  // Обновляем пароль
  try {
    user.password = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
    await user.save();
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось хешировать новый пароль пользователя.', error);
    return res.status(500).json({ message: 'Не удалось изменить пароль. Попробуйте позже.' });
  }
  
  console.log(`Password updated for user ${user.email}`);

  res.status(200).json({ message: 'Пароль успешно изменен' });
});

// Add server uptime tracking
const startTime = Date.now();
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Server is running',
    currentVersion: serverVersion,
    latestVersion: latestVersionInfo,
    uptime: Math.floor((Date.now() - startTime) / 1000) // in seconds
  });
});

// Download APK endpoint
app.get('/download-apk', (req, res) => {
  const apkPath = path.join(__dirname, 'apk', 'app-release.apk');

  // Check if file exists
  if (!fs.existsSync(apkPath)) {
    return res.status(404).json({ message: 'APK файл не найден' });
  }

  // Set headers for download
  res.setHeader('Content-Type', 'application/vnd.android.package-archive');
  res.setHeader('Content-Disposition', 'attachment; filename="aistudymate.apk"');

  // Send the file
  res.download(apkPath, 'aistudymate.apk', (err) => {
    if (err) {
      console.error('[DOWNLOAD][ERROR] Не удалось скачать APK:', err);
      res.status(500).json({ message: 'Ошибка при скачивании APK' });
    }
  });
});

const createServer = () => {
  const keyPath = process.env.SSL_KEY_PATH;
  const certPath = process.env.SSL_CERT_PATH;
  const caPath = process.env.SSL_CA_PATH;

  if (keyPath && certPath) {
    try {
      const httpsOptions = {
        key: fs.readFileSync(path.resolve(keyPath)),
        cert: fs.readFileSync(path.resolve(certPath)),
      };

      if (caPath) {
        try {
          httpsOptions.ca = fs.readFileSync(path.resolve(caPath));
        } catch (error) {
          console.warn('[BOOT][WARN] Не удалось загрузить SSL CA сертификат.', error.message);
        }
      }

      console.log('[BOOT] HTTPS сервер инициализирован с пользовательским сертификатом.');
      return https.createServer(httpsOptions, app);
    } catch (error) {
      console.error('[BOOT][ERROR] Не удалось создать HTTPS сервер. Будет использован HTTP.', error);
    }
  } else {
    console.warn('[BOOT] SSL сертификат не настроен (SSL_KEY_PATH/SSL_CERT_PATH). Сервер стартует по HTTP.');
  }

  return http.createServer(app);
};

const server = createServer();

// WebSocket Server
const wss = new WebSocketServer({
  server,
  path: '/updates',
  clientTracking: true,
});

const listenHost = '0.0.0.0';
const listenPort = process.env.NODE_ENV === 'production' ? port : (process.env.PORT || 3000);

server.listen(listenPort, listenHost, () => {
  console.log(`Server listening on ${listenHost}:${listenPort} (env: ${process.env.NODE_ENV || 'development'})`);
});

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`WebSocket клиент подключен. Всего: ${clients.size}`);

  try {
    ws.send(JSON.stringify({ type: 'latest_version', data: latestVersionInfo }));
  } catch (error) {
    console.error('Не удалось отправить начальные данные клиенту WebSocket', error);
  }

  ws.on('close', () => {
    clients.delete(ws);
    console.log(`WebSocket клиент отключен. Осталось: ${clients.size}`);
  });

  ws.on('error', (error) => {
    console.error('Ошибка WebSocket клиента', error);
  });
});

// Немедленная проверка версии при запуске
syncServerVersion();
