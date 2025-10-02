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
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const dbPath = path.join(__dirname, 'db.json');
const badgesPath = path.join(__dirname, 'badges.json');
const adminPassword = process.env.ADMIN_PASSW;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '8h';
const secureCookie = ((process.env.COOKIE_SECURE || '').toLowerCase() === 'true') || process.env.NODE_ENV === 'production';
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS) || 10;

const logSecretStatus = (name, value) => {
  if (value) {
    console.log(`[BOOT] ${name} secret загружен (${String(value).length} символов)`);
  } else {
    console.warn(`[BOOT][WARN] ${name} secret отсутствует. Настройте переменную окружения ${name}.`);
  }
};

logSecretStatus('ADMIN_PASSW', adminPassword);
logSecretStatus('JWT_SECRET', JWT_SECRET);

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

const isBcryptHash = (value) => typeof value === 'string' && value.startsWith('$2');

const hashPasswordSyncIfNeeded = (user) => {
  if (!user || !user.password) {
    return false;
  }

  if (isBcryptHash(user.password)) {
    return false;
  }

  try {
    user.password = bcrypt.hashSync(user.password, BCRYPT_SALT_ROUNDS);
    console.log(`[SECURITY] Пароль пользователя ID=${user.id} был автоматически сконвертирован в bcrypt.`);
    return true;
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось хешировать пароль пользователя при инициализации.', error);
    return false;
  }
};

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
    const uidUpdated = normalizeUser(user);
    const passwordUpdated = hashPasswordSyncIfNeeded(user);

    if (uidUpdated || passwordUpdated) {
      hasChanges = true;
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

const codeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много запросов кода. Попробуйте позже.' }
});

app.use(generalLimiter);

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
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
};

// Admin Authentication Middleware
const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Admin access required' });
  }
};

// Логирование всех запросов
const SENSITIVE_FIELDS = new Set(['password', 'currentPassword', 'newPassword', 'verificationCode', 'token', 'avatarBase64']);

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

app.get('/admin/users', authenticateJWT, isAdmin, (req, res) => {
  const users = db.users.map(user => ({
    ...user,
    badges: getBadgesForUid(user.uid)
  }));
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

  const storedCode = registrationCodes.get(trimmedEmail.toLowerCase());
  if (!storedCode) {
    return res.status(400).json({ message: 'Код подтверждения не запрошен или истек' });
  }

  const now = Date.now();
  if (storedCode.expiresAt < now) {
    registrationCodes.delete(trimmedEmail.toLowerCase());
    return res.status(400).json({ message: 'Код подтверждения истек. Запросите новый' });
  }

  if (storedCode.code !== verificationCode) {
    return res.status(400).json({ message: 'Неверный код подтверждения' });
  }

  const userExists = db.users.find(user => user.email === trimmedEmail);
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

  const newUser = {
    id: db.userIdCounter,
    email: trimmedEmail,
    password: hashedPassword,
    name: trimmedName,
    avatarUrl: '', // Поле для будущей аватарки
    pro: {
      status: false,
      startDate: null,
      endDate: null,
    },
    uid: generateUid(),
    createdAt: new Date().toISOString(),
  };

  db.userIdCounter += 1;
  db.users.push(newUser);
  saveDb();
  console.log('New user registered:', newUser);
  console.log('All users:', db.users);

  registrationCodes.delete(trimmedEmail.toLowerCase());

  // Отправляем пользователя без пароля
  res.status(201).json(buildUserResponse(newUser));
});

app.post('/auth/request-code', codeLimiter, (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const trimmedEmail = email.trim();
  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Введите корректный email' });
  }

  const exists = db.users.some(user => user.email === trimmedEmail);
  if (exists) {
    return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
  }

  const code = generateCode();
  registrationCodes.set(trimmedEmail.toLowerCase(), {
    code,
    expiresAt: Date.now() + REG_CODE_TTL_MS,
  });

  console.log(`Registration code for ${trimmedEmail}: ${code}`);

  res.status(200).json({
    message: 'Код подтверждения отправлен на вашу почту',
    debug_code: code,
  });
});

// Вход пользователя
app.post('/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны для заполнения' });
  }

  const user = db.users.find(user => user.email === email);

  if (!user || !(await verifyPassword(password, user.password))) {
    return res.status(401).json({ message: 'Неверный email или пароль' });
  }
  
  console.log('User logged in:', user);

  // Отправляем пользователя без пароля
  res.status(200).json(buildUserResponse(user));
});

// --- Эндпоинты для работы с профилем ---

// Обновление аватарки пользователя
app.post('/profile/avatar', (req, res) => {
  const { userId, avatarBase64 } = req.body;

  if (!userId || !avatarBase64) {
    return res.status(400).json({ message: 'ID пользователя и данные аватарки обязательны' });
  }

  const user = db.users.find(user => user.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Обновляем аватарку пользователя
  user.avatarUrl = avatarBase64;
  saveDb();
  
  console.log(`Avatar updated for user ${user.email}`);

  // Отправляем обновленные данные пользователя без пароля
  res.status(200).json(buildUserResponse(user));
});

// Получение данных пользователя по ID
app.get('/profile/:userId', (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  
  const user = db.users.find(user => user.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Отправляем данные пользователя без пароля
  res.status(200).json(buildUserResponse(user));
});

// Обновление профиля пользователя (имя)
app.put('/profile/:userId', (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  const { name } = req.body;

  if (!name || name.trim().length === 0) {
    return res.status(400).json({ message: 'Имя обязательно для заполнения' });
  }

  const user = db.users.find(user => user.id === userId);
  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  // Обновляем имя пользователя
  user.name = name.trim();
  saveDb();
  
  console.log(`Profile updated for user ${user.email}: name = ${user.name}`);

  // Отправляем обновленные данные пользователя без пароля
  res.status(200).json(buildUserResponse(user));
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

  const user = db.users.find(user => user.id === userId);
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
  } catch (error) {
    console.error('[SECURITY][ERROR] Не удалось хешировать новый пароль пользователя.', error);
    return res.status(500).json({ message: 'Не удалось изменить пароль. Попробуйте позже.' });
  }
  saveDb();
  
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
