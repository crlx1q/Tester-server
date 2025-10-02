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
const multer = require('multer');

const app = express();
const port = process.env.PORT || 3000;
const dbPath = path.join(__dirname, 'db.json');
const badgesPath = path.join(__dirname, 'badges.json');
const adminPassword = process.env.ADMIN_PASSW;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '8h';
const BCRYPT_ROUNDS = 12;
const secureCookie = ((process.env.COOKIE_SECURE || '').toLowerCase() === 'true') || process.env.NODE_ENV === 'production';

// Настройка multer для загрузки файлов
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB максимум
  },
  fileFilter: (req, file, cb) => {
    // Разрешаем только изображения
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Разрешены только изображения'), false);
    }
  }
});

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
  'https://localhost:3000',
  'https://127.0.0.1:3000'
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
    // В production не разрешаем запросы без origin
    if (process.env.NODE_ENV === 'production' && !origin) {
      console.warn(`[CORS] Заблокирован запрос без origin в production`);
      return callback(new Error('Origin required in production'));
    }
    
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`[CORS] Заблокирован запрос с origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 204,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// Rate limiting - улучшенная система
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много запросов. Повторите позже.' },
  skip: (req) => {
    // Пропускаем health check
    return req.path === '/health';
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 5, // Снижено с 10 до 5
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много попыток входа. Попробуйте позже.' },
  keyGenerator: (req) => {
    // Используем IP + email для более точного ограничения
    const email = req.body?.email || 'unknown';
    return `${req.ip}-${email}`;
  }
});

const codeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 3, // Снижено с 5 до 3
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много запросов кода. Попробуйте позже.' },
  keyGenerator: (req) => {
    const email = req.body?.email || 'unknown';
    return `${req.ip}-${email}`;
  }
});

const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много попыток смены пароля. Попробуйте позже.' },
  keyGenerator: (req) => {
    const userId = req.params?.userId || 'unknown';
    return `${req.ip}-${userId}`;
  }
});

const profileUpdateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много обновлений профиля. Попробуйте позже.' },
  keyGenerator: (req) => {
    const userId = req.params?.userId || req.body?.userId || 'unknown';
    return `${req.ip}-${userId}`;
  }
});

const avatarUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Слишком много загрузок аватарок. Попробуйте позже.' },
  keyGenerator: (req) => {
    const userId = req.body?.userId || 'unknown';
    return `${req.ip}-${userId}`;
  }
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

// Улучшенная генерация кодов с использованием crypto
const crypto = require('crypto');
const generateCode = () => {
  const randomBytes = crypto.randomBytes(3);
  return randomBytes.toString('hex').toUpperCase().substring(0, 6);
};

// Валидация входных данных
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  const trimmed = email.trim();
  return emailRegex.test(trimmed) && trimmed.length <= 254;
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  return password.length >= 6 && password.length <= 128;
};

const validateName = (name) => {
  if (!name || typeof name !== 'string') return false;
  const trimmed = name.trim();
  return trimmed.length >= 1 && trimmed.length <= 100;
};

const validateUserId = (userId) => {
  const id = parseInt(userId, 10);
  return !isNaN(id) && id > 0 && Number.isInteger(id);
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

// --- Эндпоинты для аутентификации ---

// Регистрация нового пользователя
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name, verificationCode } = req.body;

    // Валидация входных данных
    if (!email || !password || !name || !verificationCode) {
      return res.status(400).json({ message: 'Email, пароль, имя и код подтверждения обязательны' });
    }

    const trimmedEmail = sanitizeInput(email);
    const trimmedName = sanitizeInput(name);
    const trimmedCode = sanitizeInput(verificationCode);

    if (!validateEmail(trimmedEmail)) {
      return res.status(400).json({ message: 'Введите корректный email' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ message: 'Пароль должен содержать от 6 до 128 символов' });
    }

    if (!validateName(trimmedName)) {
      return res.status(400).json({ message: 'Имя должно содержать от 1 до 100 символов' });
    }

    // Проверка кода подтверждения
    const storedCode = registrationCodes.get(trimmedEmail.toLowerCase());
    if (!storedCode) {
      return res.status(400).json({ message: 'Код подтверждения не запрошен или истек' });
    }

    const now = Date.now();
    if (storedCode.expiresAt < now) {
      registrationCodes.delete(trimmedEmail.toLowerCase());
      return res.status(400).json({ message: 'Код подтверждения истек. Запросите новый' });
    }

    if (storedCode.code !== trimmedCode) {
      return res.status(400).json({ message: 'Неверный код подтверждения' });
    }

    // Проверка существования пользователя
    const userExists = db.users.find(user => user.email === trimmedEmail);
    if (userExists) {
      return res.status(409).json({ message: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const newUser = {
      id: db.userIdCounter,
      email: trimmedEmail,
      password: hashedPassword,
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

    db.userIdCounter += 1;
    db.users.push(newUser);
    saveDb();
    
    console.log(`[REGISTER] Новый пользователь зарегистрирован: ${trimmedEmail}`);
    registrationCodes.delete(trimmedEmail.toLowerCase());

    // Отправляем пользователя без пароля
    res.status(201).json(buildUserResponse(newUser));
  } catch (error) {
    console.error('[REGISTER] Ошибка регистрации:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

app.post('/auth/request-code', codeLimiter, (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email обязателен' });
    }

    const trimmedEmail = sanitizeInput(email);
    if (!validateEmail(trimmedEmail)) {
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

    console.log(`[CODE] Код подтверждения для ${trimmedEmail}: ${code}`);

    res.status(200).json({
      message: 'Код подтверждения отправлен на вашу почту',
      debug_code: code, // Только для разработки - убрать в production
    });
  } catch (error) {
    console.error('[CODE] Ошибка генерации кода:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// Вход пользователя
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email и пароль обязательны для заполнения' });
    }

    const trimmedEmail = sanitizeInput(email);
    if (!validateEmail(trimmedEmail)) {
      return res.status(400).json({ message: 'Введите корректный email' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ message: 'Неверный формат пароля' });
    }

    const user = db.users.find(user => user.email === trimmedEmail);
    if (!user) {
      return res.status(401).json({ message: 'Неверный email или пароль' });
    }

    // Проверка пароля с bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Неверный email или пароль' });
    }
    
    console.log(`[LOGIN] Пользователь вошел в систему: ${trimmedEmail}`);

    // Генерируем JWT токен для пользователя
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: 'user' 
      }, 
      JWT_SECRET, 
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Устанавливаем cookie с токеном
    res.cookie('token', token, {
      httpOnly: true,
      secure: secureCookie,
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    // Отправляем пользователя без пароля и токен
    res.status(200).json({
      ...buildUserResponse(user),
      token: token
    });
  } catch (error) {
    console.error('[LOGIN] Ошибка входа:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// Выход из системы
app.post('/auth/logout', authenticateJWT, (req, res) => {
  try {
    // Очищаем cookie с токеном
    res.clearCookie('token', {
      httpOnly: true,
      secure: secureCookie,
      sameSite: 'strict'
    });
    
    console.log(`[LOGOUT] Пользователь вышел из системы: ${req.user.email}`);
    res.status(200).json({ message: 'Успешный выход из системы' });
  } catch (error) {
    console.error('[LOGOUT] Ошибка выхода:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// --- Эндпоинты для работы с профилем ---

// Обновление аватарки пользователя
app.post('/profile/avatar', authenticateJWT, avatarUploadLimiter, (req, res) => {
  try {
    const { userId, avatarBase64 } = req.body;

    if (!userId || !avatarBase64) {
      return res.status(400).json({ message: 'ID пользователя и данные аватарки обязательны' });
    }

    if (!validateUserId(userId)) {
      return res.status(400).json({ message: 'Неверный ID пользователя' });
    }

    // Проверяем, что пользователь обновляет свой профиль
    if (req.user.id !== parseInt(userId)) {
      return res.status(403).json({ message: 'Доступ запрещен' });
    }

    const user = db.users.find(user => user.id === parseInt(userId));
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    // Валидация base64 данных
    if (!avatarBase64.startsWith('data:image/') || avatarBase64.length > 10 * 1024 * 1024) {
      return res.status(400).json({ message: 'Неверный формат изображения или слишком большой размер' });
    }

    // Обновляем аватарку пользователя
    user.avatarUrl = avatarBase64;
    saveDb();
    
    console.log(`[AVATAR] Аватарка обновлена для пользователя ${user.email}`);

    // Отправляем обновленные данные пользователя без пароля
    res.status(200).json(buildUserResponse(user));
  } catch (error) {
    console.error('[AVATAR] Ошибка обновления аватарки:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// Получение данных пользователя по ID
app.get('/profile/:userId', authenticateJWT, (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    
    if (!validateUserId(userId)) {
      return res.status(400).json({ message: 'Неверный ID пользователя' });
    }

    // Проверяем, что пользователь запрашивает свои данные
    if (req.user.id !== userId) {
      return res.status(403).json({ message: 'Доступ запрещен' });
    }
    
    const user = db.users.find(user => user.id === userId);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    // Отправляем данные пользователя без пароля
    res.status(200).json(buildUserResponse(user));
  } catch (error) {
    console.error('[PROFILE] Ошибка получения профиля:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// Обновление профиля пользователя (имя)
app.put('/profile/:userId', authenticateJWT, profileUpdateLimiter, (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    const { name } = req.body;

    if (!validateUserId(userId)) {
      return res.status(400).json({ message: 'Неверный ID пользователя' });
    }

    // Проверяем, что пользователь обновляет свой профиль
    if (req.user.id !== userId) {
      return res.status(403).json({ message: 'Доступ запрещен' });
    }

    if (!name || !validateName(name)) {
      return res.status(400).json({ message: 'Имя должно содержать от 1 до 100 символов' });
    }

    const user = db.users.find(user => user.id === userId);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    // Обновляем имя пользователя
    user.name = sanitizeInput(name);
    saveDb();
    
    console.log(`[PROFILE] Профиль обновлен для пользователя ${user.email}: name = ${user.name}`);

    // Отправляем обновленные данные пользователя без пароля
    res.status(200).json(buildUserResponse(user));
  } catch (error) {
    console.error('[PROFILE] Ошибка обновления профиля:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

// Смена пароля пользователя
app.put('/profile/:userId/password', authenticateJWT, passwordChangeLimiter, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    const { currentPassword, newPassword } = req.body;

    if (!validateUserId(userId)) {
      return res.status(400).json({ message: 'Неверный ID пользователя' });
    }

    // Проверяем, что пользователь меняет свой пароль
    if (req.user.id !== userId) {
      return res.status(403).json({ message: 'Доступ запрещен' });
    }

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Необходимо заполнить текущий и новый пароль' });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ message: 'Новый пароль должен содержать от 6 до 128 символов' });
    }

    const user = db.users.find(user => user.id === userId);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    // Проверяем текущий пароль с bcrypt
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({ message: 'Неверный текущий пароль' });
    }

    // Хешируем новый пароль
    const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    user.password = hashedNewPassword;
    saveDb();
    
    console.log(`[PASSWORD] Пароль изменен для пользователя ${user.email}`);

    res.status(200).json({ message: 'Пароль успешно изменен' });
  } catch (error) {
    console.error('[PASSWORD] Ошибка смены пароля:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
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

wss.on('connection', (ws, req) => {
  // Проверяем аутентификацию через query параметры или заголовки
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token') || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    console.log('[WEBSOCKET] Отклонено подключение без токена');
    ws.close(1008, 'Authentication required');
    return;
  }

  // Проверяем JWT токен
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('[WEBSOCKET] Отклонено подключение с неверным токеном');
      ws.close(1008, 'Invalid token');
      return;
    }

    // Добавляем информацию о пользователе к WebSocket соединению
    ws.user = decoded;
    clients.add(ws);
    console.log(`[WEBSOCKET] Клиент подключен: ${decoded.email}. Всего: ${clients.size}`);

    try {
      ws.send(JSON.stringify({ type: 'latest_version', data: latestVersionInfo }));
    } catch (error) {
      console.error('[WEBSOCKET] Не удалось отправить начальные данные клиенту', error);
    }

    ws.on('close', () => {
      clients.delete(ws);
      console.log(`[WEBSOCKET] Клиент отключен: ${decoded.email}. Осталось: ${clients.size}`);
    });

    ws.on('error', (error) => {
      console.error(`[WEBSOCKET] Ошибка клиента ${decoded.email}:`, error);
    });
  });
});

// Немедленная проверка версии при запуске
syncServerVersion();
