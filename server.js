require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 3000;
const dbPath = path.join(__dirname, 'db.json');
const badgesPath = path.join(__dirname, 'badges.json');
const adminPassword = process.env.ADMIN_PASSW;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_JWT_EXPIRES_IN = '8h';
const USER_JWT_EXPIRES_IN = '12h';
const secureCookie = ((process.env.COOKIE_SECURE || '').toLowerCase() === 'true') || process.env.NODE_ENV === 'production';
const DEFAULT_PASSWORD_SALT_ROUNDS = Number.parseInt(process.env.PASSWORD_SALT_ROUNDS || '12', 10);
const FORCE_HTTPS = (process.env.FORCE_HTTPS || 'true').toLowerCase() === 'true';
const EXPOSE_DEBUG_CODES = (process.env.EXPOSE_DEBUG_CODES || '').toLowerCase() === 'true';

if (!JWT_SECRET) {
  console.error('[BOOT][ERROR] JWT_SECRET отсутствует. Установите переменную окружения JWT_SECRET.');
  process.exit(1);
}

const logSecretStatus = (name, value) => {
  if (value) {
    console.log(`[BOOT] ${name} secret загружен (${String(value).length} символов)`);
  } else {
    console.warn(`[BOOT][WARN] ${name} secret отсутствует. Настройте переменную окружения ${name}.`);
  }
};

logSecretStatus('ADMIN_PASSW', adminPassword ? '***' : '');
logSecretStatus('JWT_SECRET', JWT_SECRET ? '***' : '');

const adminPasswordHash = process.env.ADMIN_PASSW_BCRYPT;
if (!adminPassword && !adminPasswordHash) {
  console.warn('[BOOT][WARN] ADMIN_PASSW или ADMIN_PASSW_BCRYPT не заданы. Админ вход будет невозможен.');
}

let plainAdminPasswordWarningShown = false;

const isPasswordHashed = (value) => typeof value === 'string' && value.startsWith('$2');
const hashPassword = (password) => bcrypt.hashSync(password, DEFAULT_PASSWORD_SALT_ROUNDS);
const verifyPassword = (password, hash) => {
  if (!password || !hash) {
    return false;
  }
  try {
    return bcrypt.compareSync(password, hash);
  } catch (error) {
    console.error('[SECURITY][ERROR] Ошибка при сравнении пароля.', error);
    return false;
  }
};

const compareStoredPassword = (storedPassword, inputPassword) => {
  if (!storedPassword) {
    return false;
  }

  if (isPasswordHashed(storedPassword)) {
    return verifyPassword(inputPassword, storedPassword);
  }

  return storedPassword === inputPassword;
};

const assignHashedPassword = (user, newPassword) => {
  user.password = hashPassword(newPassword);
};

const validateAdminPassword = (inputPassword) => {
  if (adminPasswordHash) {
    try {
      return bcrypt.compareSync(inputPassword, adminPasswordHash);
    } catch (error) {
      console.error('[ADMIN][ERROR] Не удалось сравнить админ пароль.', error);
      return false;
    }
  }

  if (!adminPassword) {
    return false;
  }

  if (!plainAdminPasswordWarningShown) {
    console.warn('[ADMIN][WARN] Используется простой ADMIN_PASSW без хеширования. Настоятельно рекомендуется задать ADMIN_PASSW_BCRYPT.');
    plainAdminPasswordWarningShown = true;
  }

  return inputPassword === adminPassword;
};

const issueAdminToken = () => jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: ADMIN_JWT_EXPIRES_IN });

const issueUserToken = (user) => jwt.sign({
  role: 'user',
  id: user.id,
  uid: user.uid,
  email: user.email
}, JWT_SECRET, { expiresIn: USER_JWT_EXPIRES_IN });

const setAuthCookie = (res, token, maxAgeMs = 12 * 60 * 60 * 1000) => {
  res.cookie('token', token, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: 'strict',
    maxAge: maxAgeMs
  });
};

const extractBearerToken = (authorizationHeader) => {
  if (!authorizationHeader || typeof authorizationHeader !== 'string') {
    return null;
  }
  const trimmed = authorizationHeader.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) {
    return null;
  }
  return trimmed.slice(7).trim() || null;
};

const resolveAuthToken = (req) => {
  const cookieToken = req.cookies?.token;
  if (cookieToken) {
    return cookieToken;
  }
  return extractBearerToken(req.headers.authorization);
};

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

const usedUids = new Set();

const generateUid = () => {
  let uid;
  do {
    const randomPart = Math.floor(Math.random() * Math.pow(10, UID_RANDOM_LENGTH))
      .toString()
      .padStart(UID_RANDOM_LENGTH, '0');
    uid = `${UID_PREFIX}${randomPart}`;
  } while (usedUids.has(uid));

  usedUids.add(uid);
  return uid;
};

const normalizeUser = (user) => {
  let modified = false;

  const hasValidUid = typeof user.uid === 'string' && /^\d{10}$/.test(user.uid) && user.uid.startsWith(UID_PREFIX) && !usedUids.has(user.uid);

  if (!hasValidUid) {
    user.uid = generateUid();
    modified = true;
  } else {
    usedUids.add(user.uid);
  }

  return modified;
};

const ensureDbFile = () => {
  if (!fs.existsSync(dbPath)) {
    fs.writeFileSync(dbPath, JSON.stringify({ users: [], userIdCounter: 1 }, null, 2));
  }
};

const ensureBadgesFile = () => {
  if (!fs.existsSync(badgesPath)) {
    const defaultBadges = {
      beta: [],
      designer: [],
      programmer: [],
    };
    fs.writeFileSync(badgesPath, JSON.stringify(defaultBadges, null, 2));
  }
};

const loadDb = () => {
  ensureDbFile();

  try {
    const raw = fs.readFileSync(dbPath, 'utf-8');
    const parsed = JSON.parse(raw);

    const users = Array.isArray(parsed.users) ? parsed.users : [];
    const userIdCounter = Number.isInteger(parsed.userIdCounter) ? parsed.userIdCounter : 1;

    return { users, userIdCounter };
  } catch (error) {
    console.error('Не удалось загрузить базу данных. Будет создана новая.', error);
    return { users: [], userIdCounter: 1 };
  }
};

const loadBadges = () => {
  ensureBadgesFile();

  try {
    const raw = fs.readFileSync(badgesPath, 'utf-8');
    const parsed = JSON.parse(raw);

    const entries = ['beta', 'designer', 'programmer'];
    const normalized = {};

    entries.forEach((key) => {
      const value = parsed[key];
      if (Array.isArray(value)) {
        normalized[key] = [...new Set(value.map(String))];
      } else {
        normalized[key] = [];
      }
    });

    // Сохраняем любые дополнительные кастомные бейджи
    Object.keys(parsed).forEach((key) => {
      if (!normalized[key]) {
        const value = parsed[key];
        normalized[key] = Array.isArray(value) ? [...new Set(value.map(String))] : [];
      }
    });

    return normalized;
  } catch (error) {
    console.error('Не удалось загрузить файл бейджей. Будет создан новый.', error);
    const fallback = {
      beta: [],
      designer: [],
      programmer: [],
    };
    fs.writeFileSync(badgesPath, JSON.stringify(fallback, null, 2));
    return fallback;
  }
};

let db = loadDb();
let isSavingDb = false;
let badges = loadBadges();
let isSavingBadges = false;

const saveDb = () => {
  try {
    isSavingDb = true;
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
    setTimeout(() => {
      isSavingDb = false;
    }, 50);
  } catch (error) {
    console.error('Не удалось сохранить базу данных', error);
    isSavingDb = false;
  }
};

const initializeUsers = () => {
  usedUids.clear();
  let hasChanges = false;

  db.users.forEach((user) => {
    if (normalizeUser(user)) {
      hasChanges = true;
    }

    if (user.password && !isPasswordHashed(user.password)) {
      try {
        user.password = hashPassword(user.password);
        hasChanges = true;
      } catch (error) {
        console.error('[SECURITY][ERROR] Не удалось захешировать пароль пользователя', { userId: user.id, error });
      }
    }
  });

  if (hasChanges) {
    saveDb();
  }
};

initializeUsers();

const saveBadges = () => {
  try {
    isSavingBadges = true;
    fs.writeFileSync(badgesPath, JSON.stringify(badges, null, 2));
    setTimeout(() => {
      isSavingBadges = false;
    }, 50);
  } catch (error) {
    console.error('Не удалось сохранить файл бейджей', error);
    isSavingBadges = false;
  }
};

const reloadDb = () => {
  try {
    db = loadDb();
    initializeUsers();
    console.log('База данных перезагружена из файла');
  } catch (error) {
    console.error('Не удалось перезагрузить базу данных', error);
  }
};

if (fs.existsSync(dbPath)) {
  fs.watch(dbPath, { persistent: false }, () => {
    if (isSavingDb) {
      return;
    }
    reloadDb();
  });
}

const reloadBadges = () => {
  try {
    badges = loadBadges();
    console.log('Файл бейджей перезагружен');
  } catch (error) {
    console.error('Не удалось перезагрузить бейджи', error);
  }
};

if (fs.existsSync(badgesPath)) {
  fs.watch(badgesPath, { persistent: false }, () => {
    if (isSavingBadges) {
      return;
    }
    reloadBadges();
  });
}

const getBadgesForUid = (uid) => {
  if (!uid) {
    return [];
  }

  const normalizedUid = uid.toString();
  return Object.keys(badges).filter((badgeKey) => {
    const holders = badges[badgeKey];
    return Array.isArray(holders) && holders.map(String).includes(normalizedUid);
  });
};

const buildUserResponse = (user) => {
  const { password: _, ...userResponse } = user;
  return {
    ...userResponse,
    badges: getBadgesForUid(user.uid),
  };
};

// Middleware
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  referrerPolicy: { policy: 'no-referrer' }
}));

if (FORCE_HTTPS) {
  console.log('[BOOT] Принудительный HTTPS включен (FORCE_HTTPS=true).');
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
  console.warn('[BOOT][WARN] FORCE_HTTPS=false. Соединения по HTTP разрешены и уязвимы для перехвата.');
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`[CORS] Заблокирован запрос с origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204,
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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много попыток входа. Попробуйте позже.' }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много регистраций. Попробуйте позже.' }
});

const codeRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много запросов кода. Попробуйте позже.' }
});

const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много попыток смены пароля. Попробуйте позже.' }
});

app.use(generalLimiter);

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = resolveAuthToken(req);

  if (!token) {
    return res.status(401).json({ message: 'Требуется аутентификация' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: 'Недействительный или истёкший токен' });
    }
    req.user = user;
    next();
  });
};

const requireUserRole = (req, res, next) => {
  if (!req.user || req.user.role !== 'user') {
    return res.status(403).json({ message: 'Доступ запрещён' });
  }
  next();
};

const requireSelfOrAdmin = (req, res, next) => {
  const requestedUserId = parseInt(req.params.userId || req.body.userId, 10);
  if (!req.user) {
    return res.status(401).json({ message: 'Требуется аутентификация' });
  }

  if (req.user.role === 'admin') {
    return next();
  }

  if (req.user.role === 'user' && Number.isInteger(requestedUserId) && req.user.id === requestedUserId) {
    return next();
  }

  return res.status(403).json({ message: 'Доступ запрещён' });
};

// Admin Authentication Middleware
const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Требуется доступ администратора' });
  }
};

// Логирование всех запросов
const SENSITIVE_FIELDS = new Set(['password', 'currentPassword', 'newPassword', 'verificationCode', 'token', 'avatarBase64', 'authorization']);

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
  const { password } = req.body || {};

  if (!password) {
    return res.status(400).json({ success: false, message: 'Пароль обязателен' });
  }

  if (!validateAdminPassword(password)) {
    return res.status(401).json({ success: false, message: 'Неверный пароль' });
  }

  const token = issueAdminToken();
  setAuthCookie(res, token, 8 * 60 * 60 * 1000);
  res.json({ success: true, token, expiresIn: ADMIN_JWT_EXPIRES_IN });
});

app.get('/admin/verify-token', authenticateJWT, isAdmin, (req, res) => {
  res.json({ success: true });
});

app.get('/admin/users', authenticateJWT, isAdmin, (req, res) => {
  const users = db.users.map((user) => buildUserResponse(user));
  res.json(users);
});

app.put('/admin/users/:userId/pro', authenticateJWT, isAdmin, (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { status } = req.body;
  
  const user = db.users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  user.pro = user.pro || {};
  user.pro.status = status;
  user.pro.updatedAt = new Date().toISOString();
  
  if (status) {
    user.pro.startDate = user.pro.startDate || new Date().toISOString();
  }
  
  saveDb();
  res.json({ success: true, user: buildUserResponse(user) });
});

app.post('/admin/reload-db', authenticateJWT, isAdmin, (req, res) => {
  try {
    reloadDb();
    res.json({ success: true, message: 'Database reloaded successfully' });
  } catch (error) {
    console.error('Reload DB error:', error);
    res.status(500).json({ success: false, message: 'Failed to reload database' });
  }
});

app.post('/admin/reload-badges', authenticateJWT, isAdmin, (req, res) => {
  try {
    reloadBadges();
    res.json({ success: true, message: 'Badges reloaded successfully' });
  } catch (error) {
    console.error('Reload badges error:', error);
    res.status(500).json({ success: false, message: 'Failed to reload badges' });
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

app.post('/admin/publish-update', authenticateJWT, isAdmin, (req, res) => {
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
const REG_CODE_TTL_MS = 5 * 60 * 1000; // 5 минут

const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();
const normalizeEmail = (email) => email.trim().toLowerCase();

// --- Эндпоинты для аутентификации ---

// Регистрация нового пользователя
app.post('/auth/register', registerLimiter, (req, res) => {
  const { email, password, name, verificationCode } = req.body || {};

  if (!email || !password || !name || !verificationCode) {
    return res.status(400).json({ message: 'Email, пароль, имя и код подтверждения обязательны' });
  }

  const normalizedEmail = normalizeEmail(email);
  const trimmedName = name.trim();

  if (!emailRegex.test(normalizeEmail(email))) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Пароль должен содержать минимум 6 символов' });
  }

  if (trimmedName.length === 0) {
    return res.status(400).json({ message: 'Имя обязательно для заполнения' });
  }

  const codeRecord = registrationCodes.get(normalizedEmail);
  if (!codeRecord) {
    return res.status(400).json({ message: 'Код подтверждения не запрошен или истек' });
  }

  const now = Date.now();
  if (codeRecord.expiresAt < now) {
    registrationCodes.delete(normalizedEmail);
    return res.status(400).json({ message: 'Код подтверждения истек. Запросите новый' });
  }

  if ((codeRecord.failedAttempts || 0) >= 5) {
    registrationCodes.delete(normalizedEmail);
    return res.status(429).json({ message: 'Превышено количество попыток. Запросите новый код.' });
  }

  if (codeRecord.code !== verificationCode) {
    codeRecord.failedAttempts = (codeRecord.failedAttempts || 0) + 1;
    registrationCodes.set(normalizedEmail, codeRecord);
    return res.status(400).json({ message: 'Неверный код подтверждения' });
  }

  const userExists = db.users.find((user) => normalizeEmail(user.email) === normalizedEmail);
  if (userExists) {
    return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
  }

  const newUser = {
    id: db.userIdCounter,
    email: normalizedEmail,
    password: '',
    name: trimmedName,
    avatarUrl: '',
    pro: {
      status: false,
      startDate: null,
      endDate: null,
    },
    uid: generateUid(),
    createdAt: new Date().toISOString(),
  };

  assignHashedPassword(newUser, password);

  db.userIdCounter += 1;
  db.users.push(newUser);
  saveDb();

  registrationCodes.delete(normalizedEmail);

  const token = issueUserToken(newUser);
  setAuthCookie(res, token);

  res.status(201).json({
    user: buildUserResponse(newUser),
    token,
  });
});

app.post('/auth/request-code', codeRequestLimiter, (req, res) => {
  const { email } = req.body || {};

  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const normalizedEmail = normalizeEmail(email);
  if (!emailRegex.test(normalizedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  const exists = db.users.some((user) => normalizeEmail(user.email) === normalizedEmail);
  if (exists) {
    return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
  }

  const code = generateCode();
  registrationCodes.set(normalizedEmail, {
    code,
    expiresAt: Date.now() + REG_CODE_TTL_MS,
    failedAttempts: 0,
  });

  console.log(`[SECURITY][CODE] Registration code for ${normalizedEmail}: ${code}`);

  const responsePayload = {
    message: 'Код подтверждения отправлен на вашу почту',
  };

  if (EXPOSE_DEBUG_CODES) {
    responsePayload.debug_code = code;
  }

  res.status(200).json(responsePayload);
});

// Вход пользователя
app.post('/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны для заполнения' });
  }

  const normalizedEmail = normalizeEmail(email);
  const user = db.users.find((candidate) => normalizeEmail(candidate.email) === normalizedEmail);

  if (!user || !compareStoredPassword(user.password, password)) {
    return res.status(401).json({ message: 'Неверный email или пароль' });
  }

  if (!isPasswordHashed(user.password)) {
    try {
      assignHashedPassword(user, password);
      saveDb();
    } catch (error) {
      console.error('[SECURITY][ERROR] Не удалось обновить пароль пользователя на захешированный вариант', error);
    }
  }

  const token = issueUserToken(user);
  setAuthCookie(res, token);

  res.status(200).json({
    user: buildUserResponse(user),
    token,
  });
});

app.post('/auth/logout', authenticateJWT, (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: secureCookie,
    sameSite: 'strict',
  });
  res.status(200).json({ message: 'Вы вышли из аккаунта' });
});

// --- Эндпоинты для работы с профилем ---

// Обновление аватарки пользователя
app.post('/profile/avatar', authenticateJWT, requireSelfOrAdmin, (req, res) => {
  const { userId, avatarBase64 } = req.body || {};

  const normalizedId = Number.parseInt(userId, 10);
  if (!Number.isInteger(normalizedId) || !avatarBase64 || typeof avatarBase64 !== 'string') {
    return res.status(400).json({ message: 'ID пользователя и данные аватарки обязательны' });
  }

  if (avatarBase64.length > 10 * 1024 * 1024) { // ~10MB в base64
    return res.status(413).json({ message: 'Размер аватарки слишком большой' });
  }

  const user = db.users.find((candidate) => candidate.id === normalizedId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  user.avatarUrl = avatarBase64;
  saveDb();

  res.status(200).json({
    user: buildUserResponse(user),
  });
});

// Получение данных пользователя по ID
app.get('/profile/:userId', authenticateJWT, requireSelfOrAdmin, (req, res) => {
  const userId = Number.parseInt(req.params.userId, 10);

  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  const user = db.users.find((candidate) => candidate.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  res.status(200).json({ user: buildUserResponse(user) });
});

// Обновление профиля пользователя (имя)
app.put('/profile/:userId', authenticateJWT, requireSelfOrAdmin, (req, res) => {
  const userId = Number.parseInt(req.params.userId, 10);
  const { name } = req.body || {};

  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  if (!name || name.trim().length === 0) {
    return res.status(400).json({ message: 'Имя обязательно для заполнения' });
  }

  const user = db.users.find((candidate) => candidate.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  user.name = name.trim();
  saveDb();

  res.status(200).json({ user: buildUserResponse(user) });
});

// Смена пароля пользователя
app.put('/profile/:userId/password', authenticateJWT, requireSelfOrAdmin, passwordChangeLimiter, (req, res) => {
  const userId = Number.parseInt(req.params.userId, 10);
  const { currentPassword, newPassword } = req.body || {};

  if (!Number.isInteger(userId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Необходимо заполнить текущий и новый пароль' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'Новый пароль должен содержать минимум 6 символов' });
  }

  const user = db.users.find((candidate) => candidate.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  if (!compareStoredPassword(user.password, currentPassword)) {
    return res.status(401).json({ message: 'Неверный текущий пароль' });
  }

  try {
    assignHashedPassword(user, newPassword);
    saveDb();
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось обновить пароль пользователя', { userId, error });
    return res.status(500).json({ message: 'Не удалось обновить пароль. Попробуйте позже.' });
  }

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
