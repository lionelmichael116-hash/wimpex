const path = require('path');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
let sharp;
try { sharp = require('sharp'); } catch (e) { sharp = null; }
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const webpush = require('web-push');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const FileType = require('file-type');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb' }));

// Password helpers (bcrypt with legacy SHA256 fallback)
function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

function verifyPassword(password, hash) {
  if (!hash) return false;
  try {
    if (typeof hash === 'string' && hash.startsWith('$2')) {
      return bcrypt.compareSync(password, hash);
    }
  } catch (e) {}
  // Legacy sha256 check
  const legacy = crypto.createHash('sha256').update(password + 'wimpex_salt').digest('hex');
  return legacy === hash;
}

// Email transporter (configure via env vars)
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

function sendEmail(to, subject, html) {
  if (!transporter) {
    console.log(`📧 Email not sent (no SMTP configured). Preview -> to:${to} subject:${subject} html:${html}`);
    return Promise.resolve();
  }
  return transporter.sendMail({ from: process.env.FROM_EMAIL || process.env.SMTP_USER, to, subject, html });
}

// ===== PERSISTENT STORAGE =====
const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const MEDIA_DIR = path.join(__dirname, '..', 'data', 'media');
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const STORIES_FILE = path.join(DATA_DIR, 'stories.json');
const SNAPS_FILE = path.join(DATA_DIR, 'snaps.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const PUSH_FILE = path.join(DATA_DIR, 'push_subscriptions.json');
const MODERATION_FILE = path.join(DATA_DIR, 'moderation_queue.json');

const JWT_SECRET = process.env.JWT_SECRET || 'wimpex_secret_key_2025';

// Helper: load JSON file
function loadData(file, defaultValue = {}) {
  try {
    if (!fs.existsSync(file)) return defaultValue;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return defaultValue;
  }
}

// Helper: save JSON file
function saveData(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

let users = loadData(USERS_FILE, {});
let stories = loadData(STORIES_FILE, {});
let snaps = loadData(SNAPS_FILE, {});
let moderationQueue = loadData(MODERATION_FILE, []);
let messages = loadData(MESSAGES_FILE, {});
let pushSubscriptions = loadData(PUSH_FILE, {});

// S3 / CDN configuration (optional)
const S3_BUCKET = process.env.S3_BUCKET || process.env.AWS_BUCKET;
const AWS_REGION = process.env.AWS_REGION || process.env.S3_REGION || 'us-east-1';
let s3Client = null;
if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY && S3_BUCKET) {
  s3Client = new S3Client({ region: AWS_REGION });
  console.log('✅ S3 client configured for bucket:', S3_BUCKET);
}

function genId() { return crypto.randomBytes(6).toString('hex'); }

// ===== AUTH MIDDLEWARE =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ===== AUTH ROUTES =====
app.post('/api/auth/signup', (req, res) => {
  const { username, email, phone, password, gender } = req.body;
  if (!username || !email || !password || !gender) return res.status(400).json({ error: 'Missing required fields' });
  if (Object.values(users).some(u => u.email === email)) return res.status(400).json({ error: 'Email already registered' });
  if (Object.values(users).some(u => u.username === username)) return res.status(400).json({ error: 'Username taken' });
  if (phone && Object.values(users).some(u => u.phone === phone)) return res.status(400).json({ error: 'Phone already registered' });

  const userId = genId();
  const hashedPassword = hashPassword(password);
  const avatar = `https://i.pravatar.cc/150?img=${Math.random() * 70 | 0}`;
  const confirmToken = crypto.randomBytes(32).toString('hex');

  users[userId] = {
    userId,
    username,
    email,
    phone: phone || '',
    password: hashedPassword,
    avatar,
    bio: 'New to Wimpex ✨',
    gender: gender || 'not-specified',
    emailConfirmed: false,
    confirmToken: confirmToken,
    friends: [],
    followers: [],
    createdAt: Date.now()
  };

  saveData(USERS_FILE, users);
  const confirmUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/api/auth/confirm?token=${confirmToken}`;
  // Send confirmation email (if SMTP configured) or log link
  sendEmail(email, 'Confirm your Wimpex account', `Hi ${username},<br><br>Please confirm your email by visiting: <a href="${confirmUrl}">${confirmUrl}</a><br><br>Thanks,<br>Wimpex Team`).catch(err => console.error('Email send error:', err));
  console.log(`📧 Confirmation link for ${username}: ${confirmUrl}`);

  const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ 
    userId, 
    username, 
    avatar, 
    token,
    message: 'Account created! Please check your email to confirm.' 
  });
});

app.post('/api/auth/login', (req, res) => {
  const { input, password, loginType } = req.body;
  if (!input || !password) return res.status(400).json({ error: 'Input and password required' });

  let user = null;
  
  if (loginType === 'email') {
    user = Object.values(users).find(u => u.email === input);
  } else if (loginType === 'phone') {
    user = Object.values(users).find(u => u.phone === input);
  } else if (loginType === 'username') {
    user = Object.values(users).find(u => u.username === input);
  } else {
    // Try all methods if not specified
    user = Object.values(users).find(u => u.email === input || u.phone === input || u.username === input);
  }

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const validPassword = verifyPassword(password, user.password);
  if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

  // If user has 2FA enabled, return a short-lived pre-auth token and indicate 2FA required
  if (user.twoFA && user.twoFA.enabled) {
    const temp = jwt.sign({ userId: user.userId, twofa: true }, JWT_SECRET, { expiresIn: '5m' });
    return res.json({ need2FA: true, tempToken: temp, userId: user.userId, username: user.username, avatar: user.avatar });
  }

  const token = jwt.sign({ userId: user.userId, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ userId: user.userId, username: user.username, avatar: user.avatar, token });
});

// Complete login with 2FA
app.post('/api/auth/login-2fa', (req, res) => {
  const { tempToken, token } = req.body;
  if (!tempToken || !token) return res.status(400).json({ error: 'Missing fields' });
  try {
    const decoded = jwt.verify(tempToken, JWT_SECRET);
    if (!decoded.twofa) return res.status(400).json({ error: 'Invalid temp token' });
    const user = users[decoded.userId];
    if (!user || !user.twoFA || !user.twoFA.enabled) return res.status(400).json({ error: '2FA not enabled' });

    const ok = speakeasy.totp.verify({ secret: user.twoFA.secret, encoding: 'base32', token, window: 1 });
    if (!ok) return res.status(401).json({ error: 'Invalid 2FA token' });

    const full = jwt.sign({ userId: user.userId, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ userId: user.userId, username: user.username, avatar: user.avatar, token: full });
  } catch (e) {
    return res.status(400).json({ error: 'Invalid or expired temp token' });
  }
});

// ===== EMAIL CONFIRMATION =====
app.get('/api/auth/confirm', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const user = Object.values(users).find(u => u.confirmToken === token);
  if (!user) return res.status(400).json({ error: 'Invalid token' });

  user.emailConfirmed = true;
  user.confirmToken = null;
  saveData(USERS_FILE, users);

  res.json({ ok: true, message: 'Email confirmed! You can now use all features.' });
});

app.post('/api/auth/resend-confirmation', authenticateToken, (req, res) => {
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.emailConfirmed) return res.status(400).json({ error: 'Email already confirmed' });
  const confirmUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/api/auth/confirm?token=${user.confirmToken}`;
  sendEmail(user.email, 'Confirm your Wimpex account', `Hi ${user.username},<br><br>Please confirm your email by visiting: <a href="${confirmUrl}">${confirmUrl}</a><br><br>Thanks,<br>Wimpex Team`).catch(err => console.error('Email send error:', err));
  console.log(`📧 Resend confirmation link for ${user.username}: ${confirmUrl}`);
  res.json({ ok: true, message: 'Confirmation email resent' });
});

// ===== PASSWORD RESET =====
app.post('/api/auth/forgot', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const ip = req.ip || req.connection.remoteAddress;
  // basic in-memory rate limiting
  if (!global._forgotRate) global._forgotRate = {};
  const key = `${ip}:${email}`;
  const entry = global._forgotRate[key] || { count: 0, last: 0 };
  if (Date.now() - entry.last < 60 * 1000 && entry.count > 5) {
    return res.status(429).json({ error: 'Too many requests, try again later' });
  }
  if (Date.now() - entry.last > 60 * 1000) { entry.count = 0; }
  entry.count += 1; entry.last = Date.now(); global._forgotRate[key] = entry;

  const user = Object.values(users).find(u => u.email === email);
  if (!user) return res.json({ ok: true, message: 'If that email exists we sent a reset link' });

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetExpires = Date.now() + 60 * 60 * 1000; // 1 hour
  saveData(USERS_FILE, users);

  const resetUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password.html?token=${resetToken}`;
  sendEmail(user.email, 'Wimpex password reset', `Hi ${user.username},<br><br>Reset your password: <a href="${resetUrl}">${resetUrl}</a><br><br>If you didn't request this, ignore.`).catch(err => console.error('Email send error:', err));
  console.log(`🔐 Password reset for ${user.username}: ${resetUrl}`);

  res.json({ ok: true, message: 'If that email exists we sent a reset link' });
});

app.post('/api/auth/reset', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and new password required' });

  const user = Object.values(users).find(u => u.resetToken === token && u.resetExpires > Date.now());
  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

  user.password = hashPassword(password);
  user.resetToken = null;
  user.resetExpires = null;
  saveData(USERS_FILE, users);

  res.json({ ok: true, message: 'Password reset successful' });
});

// Change password for authenticated user
app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!verifyPassword(currentPassword, user.password)) return res.status(401).json({ error: 'Current password incorrect' });
  user.password = hashPassword(newPassword);
  // invalidate any reset tokens
  user.resetToken = null; user.resetExpires = null;
  saveData(USERS_FILE, users);
  res.json({ ok: true, message: 'Password changed' });
});

// ===== USER ROUTES =====
app.get('/api/users/:userId', authenticateToken, (req, res) => {
  const user = users[req.params.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...userData } = user;
  res.json(userData);
});

app.put('/api/users/:userId', authenticateToken, async (req, res) => {
  if (req.user.userId !== req.params.userId && req.params.userId !== 'self') return res.status(403).json({ error: 'Unauthorized' });

  const userId = req.user.userId;
  const { bio, avatar, username, phone, email } = req.body;
  
  // Validate username uniqueness if changing
  if (username && username !== users[userId].username) {
    if (Object.values(users).some(u => u.username === username && u.userId !== userId)) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    users[userId].username = username;
  }
  
  // Validate email uniqueness if changing
  if (email && email !== users[userId].email) {
    if (Object.values(users).some(u => u.email === email && u.userId !== userId)) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    users[userId].email = email;
  }
  
  // Validate phone uniqueness if changing
  if (phone && phone !== users[userId].phone) {
    if (Object.values(users).some(u => u.phone === phone && u.userId !== userId)) {
      return res.status(400).json({ error: 'Phone already registered' });
    }
    users[userId].phone = phone;
  }
  
  if (bio !== undefined) users[userId].bio = bio;
  if (avatar) users[userId].avatar = avatar;
  
  saveData(USERS_FILE, users);
  const { password, ...userData } = users[userId];
  res.json(userData);
});

// ===== SETTINGS ROUTES =====
app.get('/api/settings', authenticateToken, (req, res) => {
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const { password, ...safeData } = user;
  res.json(safeData);
});

app.put('/api/settings', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const user = users[userId];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { avatar, bio, username, phone, email } = req.body;

  // Update avatar (can be base64 or URL)
  if (avatar) {
    if (avatar.length > 5000000) return res.status(400).json({ error: 'Image too large' });
    user.avatar = avatar;
  }

  // Update bio
  if (bio !== undefined) {
    if (bio.length > 200) return res.status(400).json({ error: 'Bio too long' });
    user.bio = bio;
  }

  // Update username
  if (username && username !== user.username) {
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 chars' });
    if (Object.values(users).some(u => u.username === username && u.userId !== userId)) {
      return res.status(400).json({ error: 'Username taken' });
    }
    user.username = username;
  }

  // Update email
  if (email && email !== user.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (Object.values(users).some(u => u.email === email && u.userId !== userId)) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    user.email = email;
  }

  // Update phone
  if (phone && phone !== user.phone) {
    if (phone.length < 10) return res.status(400).json({ error: 'Invalid phone number' });
    if (Object.values(users).some(u => u.phone === phone && u.userId !== userId)) {
      return res.status(400).json({ error: 'Phone already registered' });
    }
    user.phone = phone;
  }

  saveData(USERS_FILE, users);
  const { password, ...userData } = user;
  res.json(userData);
});

// ===== ONBOARDING =====
// Mark onboarding as complete for current user
app.post('/api/onboarding/complete', authenticateToken, (req, res) => {
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.onboardingComplete = true;
  saveData(USERS_FILE, users);
  res.json({ ok: true });
});

// Upload profile picture (base64)
app.post('/api/settings/upload-avatar', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const { avatar } = req.body;

  if (!avatar) return res.status(400).json({ error: 'Avatar required' });
  if (avatar.length > 5000000) return res.status(400).json({ error: 'Image too large (max 5MB)' });

  const user = users[userId];
  user.avatar = avatar;
  saveData(USERS_FILE, users);

  res.json({ ok: true, avatar: user.avatar });
});

// Generic media upload (base64) -> saves file under /data/media and returns public URL
app.post('/api/upload', authenticateToken, async (req, res) => {
  const { filename, data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });

  // data may be data:<mime>;base64,strip
  const match = data.match(/^data:(.+);base64,(.+)$/);
  let mime = 'application/octet-stream';
  let base64 = data;
  if (match) { mime = match[1]; base64 = match[2]; }

  const buf = Buffer.from(base64, 'base64');
  if (buf.length > 10 * 1024 * 1024) return res.status(400).json({ error: 'File too large (10MB max)' });

  const ext = filename && filename.includes('.') ? filename.split('.').pop() : mime.split('/').pop();

  // If S3 configured, prefer upload to CDN for all file types
  if (s3Client) {
    try {
      let bodyBuf = buf;
      let contentType = mime;
      // Optimize images when possible
      if (sharp && mime.startsWith('image/')) {
        bodyBuf = await sharp(buf).resize({ width: 1920, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
        contentType = 'image/jpeg';
      }
      const key = `${Date.now()}_${genId()}.${ext}`;
      const put = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: bodyBuf, ContentType: contentType, ACL: 'public-read' });
      await s3Client.send(put);
      const url = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${encodeURIComponent(key)}`;
      // create thumbnail locally if sharp available and image
      let thumbUrl = null;
      if (sharp && contentType.startsWith('image/')) {
        const thumbBuf = await sharp(bodyBuf).resize(300, 300, { fit: 'cover' }).toBuffer();
        const thumbName = `thumb_${key}`;
        const thumbPath = path.join(MEDIA_DIR, thumbName);
        fs.writeFileSync(thumbPath, thumbBuf);
        thumbUrl = `/media/${encodeURIComponent(thumbName)}`;
      }
      // moderation check (async)
      moderateUpload(req.user.userId, url, bodyBuf, contentType).catch(() => {});
      return res.json({ ok: true, url, thumb: thumbUrl });
    } catch (e) {
      console.error('S3 upload failed, falling back to local save', e);
    }
  }

  const outName = `${Date.now()}_${genId()}.${ext}`;
  const outPath = path.join(MEDIA_DIR, outName);
  try {
    // Optimize local image files if possible
    if (sharp && mime.startsWith('image/')) {
      const optimizedBuf = await sharp(buf).resize({ width: 1920, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
      fs.writeFileSync(outPath, optimizedBuf);
    } else {
      fs.writeFileSync(outPath, buf);
    }
    // optionally create thumbnail if sharp available and image
    let thumbUrl = null;
    if (sharp && mime.startsWith('image/')) {
      const thumbPath = path.join(MEDIA_DIR, `thumb_${outName}`);
      await sharp(outPath).resize(300, 300, { fit: 'cover' }).toFile(thumbPath);
      thumbUrl = `/media/${encodeURIComponent('thumb_' + outName)}`;
    }
    const url = `/media/${encodeURIComponent(outName)}`;
    // moderation check (async)
    moderateUpload(req.user.userId, url, fs.readFileSync(outPath), mime).catch(() => {});
    res.json({ ok: true, url, thumb: thumbUrl });
  } catch (err) {
    console.error('Upload error', err);
    res.status(500).json({ error: 'Failed to save file' });
  }
});

// Presign endpoint for direct uploads to S3
app.get('/api/upload/presign', authenticateToken, async (req, res) => {
  if (!s3Client) return res.status(400).json({ error: 'S3 not configured' });
  const filename = req.query.filename || `${genId()}`;
  const contentType = req.query.contentType || 'application/octet-stream';
  const key = `${Date.now()}_${genId()}_${filename}`;
  try {
    const cmd = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: contentType, ACL: 'public-read' });
    const url = await getSignedUrl(s3Client, cmd, { expiresIn: 3600 });
    const publicUrl = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${encodeURIComponent(key)}`;
    res.json({ url, key, publicUrl });
  } catch (e) {
    console.error('Presign error', e);
    res.status(500).json({ error: 'Failed to create presigned url' });
  }
});

// Moderation endpoints
app.get('/api/moderation', authenticateToken, (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ error: 'Admin required' });
  res.json(moderationQueue);
});

app.post('/api/moderation/resolve', authenticateToken, (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ error: 'Admin required' });
  const { url, action } = req.body;
  if (!url || !action) return res.status(400).json({ error: 'Missing fields' });
  const idx = moderationQueue.findIndex(q => q.url === url);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const item = moderationQueue[idx];
  item.resolved = true;
  item.action = action;
  item.resolvedAt = Date.now();
  saveModerationQueue();
  res.json({ ok: true, item });
});

// Server-side upload to CDN (optimizes images then uploads)
app.post('/api/upload/cdn', authenticateToken, async (req, res) => {
  if (!s3Client) return res.status(400).json({ error: 'S3 not configured' });
  const { filename, data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  const match = data.match(/^data:(.+);base64,(.+)$/);
  let mime = 'application/octet-stream';
  let base64 = data;
  if (match) { mime = match[1]; base64 = match[2]; }
  const buf = Buffer.from(base64, 'base64');
  try {
    let bodyBuf = buf;
    let contentType = mime;
    if (sharp && mime.startsWith('image/')) {
      bodyBuf = await sharp(buf).resize({ width: 1920, withoutEnlargement: true }).jpeg({ quality: 80 }).toBuffer();
      contentType = 'image/jpeg';
    }
    const extLocal = filename && filename.includes('.') ? filename.split('.').pop() : (contentType.split('/').pop() || 'bin');
    const key = `${Date.now()}_${genId()}.${extLocal}`;
    const put = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: bodyBuf, ContentType: contentType, ACL: 'public-read' });
    await s3Client.send(put);
    const publicUrl = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${encodeURIComponent(key)}`;
    res.json({ ok: true, url: publicUrl });
  } catch (e) {
    console.error('CDN upload failed', e);
    res.status(500).json({ error: 'Upload to CDN failed' });
  }
});

// ===== 2FA (TOTP) =====
app.get('/api/2fa/setup', authenticateToken, async (req, res) => {
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const secret = speakeasy.generateSecret({ name: `Wimpex (${user.username})` });
  // store temp secret until verified
  user.twoFATemp = secret.base32;
  saveData(USERS_FILE, users);

  const otpauth = secret.otpauth_url;
  try {
    const qr = await qrcode.toDataURL(otpauth);
    res.json({ secret: secret.base32, otpauth, qr });
  } catch (e) {
    res.json({ secret: secret.base32, otpauth });
  }
});

app.post('/api/2fa/verify', authenticateToken, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const secret = user.twoFATemp;
  if (!secret) return res.status(400).json({ error: 'No 2FA setup in progress' });

  const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(401).json({ error: 'Invalid token' });

  user.twoFA = { enabled: true, secret };
  user.twoFATemp = null;
  saveData(USERS_FILE, users);
  res.json({ ok: true, message: '2FA enabled' });
});

app.post('/api/2fa/disable', authenticateToken, (req, res) => {
  const { token, password } = req.body;
  const user = users[req.user.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.twoFA || !user.twoFA.enabled) return res.status(400).json({ error: '2FA not enabled' });
  if (!verifyPassword(password, user.password)) return res.status(401).json({ error: 'Invalid password' });
  const ok = speakeasy.totp.verify({ secret: user.twoFA.secret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(401).json({ error: 'Invalid 2FA token' });
  user.twoFA = { enabled: false, secret: null };
  saveData(USERS_FILE, users);
  res.json({ ok: true, message: '2FA disabled' });
});

// ===== WEB PUSH SETUP =====
const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(process.env.FROM_EMAIL ? `mailto:${process.env.FROM_EMAIL}` : 'mailto:admin@example.com', VAPID_PUBLIC, VAPID_PRIVATE);
} else {
  // generate temporary keys and log them for developer convenience
  try {
    const keys = webpush.generateVAPIDKeys();
    console.log('⚠️ Generated VAPID keys (set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY in env for persistence):');
    console.log('VAPID_PUBLIC_KEY=' + keys.publicKey);
    console.log('VAPID_PRIVATE_KEY=' + keys.privateKey);
    webpush.setVapidDetails(process.env.FROM_EMAIL ? `mailto:${process.env.FROM_EMAIL}` : 'mailto:admin@example.com', keys.publicKey, keys.privateKey);
  } catch (e) {
    console.warn('Web-push VAPID key generation failed or web-push not usable');
  }
}

function savePushSubscriptions() {
  saveData(PUSH_FILE, pushSubscriptions);
}

function saveModerationQueue() {
  saveData(MODERATION_FILE, moderationQueue);
}

function isAdminUser(req) {
  if (!req.user) return false;
  const uid = req.user.userId;
  if (typeof uid === 'string' && uid.startsWith('admin_')) return true;
  const user = users[uid];
  return user && user.isAdmin;
}

async function moderateUpload(userId, url, buf, contentType) {
  try {
    const info = { userId, url, contentType, flagged: false, reasons: [], createdAt: Date.now() };
    // Detect actual file type
    try {
      const ft = await FileType.fromBuffer(buf);
      if (ft && ft.mime && !ft.mime.includes(contentType.split('/')[0])) {
        info.flagged = true;
        info.reasons.push('file-type-mismatch');
      }
    } catch (e) {}

    // If image, check dimensions
    if (sharp && contentType.startsWith('image/')) {
      try {
        const meta = await sharp(buf).metadata();
        if ((meta.width && meta.width > 4000) || (meta.height && meta.height > 4000)) {
          info.flagged = true;
          info.reasons.push('huge-dimensions');
        }
      } catch (e) {}
    }

    // size-based flags
    if (buf.length > 5 * 1024 * 1024) {
      info.flagged = true;
      info.reasons.push('large-file');
    }

    if (info.flagged) {
      moderationQueue.push(info);
      saveModerationQueue();
    }
    return info;
  } catch (e) {
    console.error('Moderation check failed', e);
    return null;
  }
}

app.post('/api/push/subscribe', authenticateToken, (req, res) => {
  const { subscription } = req.body;
  if (!subscription) return res.status(400).json({ error: 'subscription required' });
  const userId = req.user.userId;
  pushSubscriptions[userId] = pushSubscriptions[userId] || [];
  // avoid duplicates
  const exists = pushSubscriptions[userId].some(s => s.endpoint === subscription.endpoint);
  if (!exists) pushSubscriptions[userId].push(subscription);
  savePushSubscriptions();
  res.json({ ok: true });
});

app.post('/api/push/unsubscribe', authenticateToken, (req, res) => {
  const { endpoint } = req.body;
  const userId = req.user.userId;
  if (!pushSubscriptions[userId]) return res.json({ ok: true });
  pushSubscriptions[userId] = pushSubscriptions[userId].filter(s => s.endpoint !== endpoint);
  savePushSubscriptions();
  res.json({ ok: true });
});

async function sendPushToSubscription(sub, payload) {
  try {
    await webpush.sendNotification(sub, JSON.stringify(payload));
    return true;
  } catch (e) {
    // if 410 or gone, indicate removal
    if (e.statusCode === 410 || e.statusCode === 404) return false;
    console.error('Push send error', e);
    return true; // don't remove for other errors
  }
}

// Send push to a user or broadcast (authenticated users can send their own notifications)
app.post('/api/push/send', authenticateToken, async (req, res) => {
  const { userId, title, body, url } = req.body;
  const payload = { title: title || 'Wimpex', body: body || '', url: url || '/' };
  const targets = [];
  if (userId) {
    if (pushSubscriptions[userId]) targets.push(...pushSubscriptions[userId]);
  } else {
    Object.values(pushSubscriptions).forEach(arr => targets.push(...arr));
  }

  const removed = [];
  await Promise.all(targets.map(async (sub) => {
    const ok = await sendPushToSubscription(sub, payload);
    if (!ok) removed.push(sub.endpoint);
  }));

  // cleanup removed subscriptions
  if (removed.length) {
    Object.keys(pushSubscriptions).forEach(uid => {
      pushSubscriptions[uid] = pushSubscriptions[uid].filter(s => !removed.includes(s.endpoint));
      if (!pushSubscriptions[uid].length) delete pushSubscriptions[uid];
    });
    savePushSubscriptions();
  }

  res.json({ ok: true, sent: targets.length - removed.length, removed: removed.length });
});

// Expose VAPID public key to clients
app.get('/api/push/publicKey', (req, res) => {
  try {
    const key = webpush.getVapidPublicKey();
    res.json({ publicKey: key });
  } catch (e) {
    res.status(500).json({ error: 'VAPID key not available' });
  }
});

// ===== STORIES =====
app.get('/api/stories', authenticateToken, (req, res) => {
  const now = Date.now();
  const active = Object.values(stories)
    .filter(s => s.expiresAt > now)
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(active);
});

app.post('/api/stories', authenticateToken, (req, res) => {
  const { media } = req.body;
  if (!media) return res.status(400).json({ error: 'Media required' });

  const storyId = genId();
  const user = users[req.user.userId];
  stories[storyId] = {
    storyId,
    userId: req.user.userId,
    username: user.username,
    avatar: user.avatar,
    media,
    views: [],
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  };

  saveData(STORIES_FILE, stories);
  res.json(stories[storyId]);
});

app.post('/api/stories/:storyId/view', authenticateToken, (req, res) => {
  const story = stories[req.params.storyId];
  if (story && !story.views.includes(req.user.userId)) {
    story.views.push(req.user.userId);
    saveData(STORIES_FILE, stories);
  }
  res.json({ ok: true });
});

app.get('/api/stories/:userId/count', authenticateToken, (req, res) => {
  const userStories = Object.values(stories).filter(s => s.userId === req.params.userId && s.expiresAt > Date.now());
  res.json({ count: userStories.length });
});

// ===== SNAPS =====
app.post('/api/snaps', authenticateToken, (req, res) => {
  const { toId, media } = req.body;
  if (!toId || !media) return res.status(400).json({ error: 'Missing fields' });

  const snapId = genId();
  const user = users[req.user.userId];
  snaps[snapId] = {
    snapId,
    fromId: req.user.userId,
    fromUsername: user.username,
    toId,
    media,
    viewed: false,
    createdAt: Date.now()
  };

  saveData(SNAPS_FILE, snaps);
  // Send web-push notification to recipient if subscribed
  (async () => {
    try {
      const subs = pushSubscriptions[toId] || [];
      if (subs.length) {
        const payload = { title: `${user.username} sent you a snap`, body: 'Open Wimpex to view it', url: '/' };
        const removed = [];
        await Promise.all(subs.map(async (sub) => {
          const ok = await sendPushToSubscription(sub, payload);
          if (!ok) removed.push(sub.endpoint);
        }));
        if (removed.length) {
          pushSubscriptions[toId] = (pushSubscriptions[toId] || []).filter(s => !removed.includes(s.endpoint));
          if (!pushSubscriptions[toId].length) delete pushSubscriptions[toId];
          savePushSubscriptions();
        }
      }
    } catch (e) {
      console.error('Error sending snap push', e);
    }
  })();

  res.json(snaps[snapId]);
});

app.get('/api/snaps', authenticateToken, (req, res) => {
  const userSnaps = Object.values(snaps).filter(s => s.toId === req.user.userId && !s.viewed);
  res.json(userSnaps);
});

app.post('/api/snaps/:snapId/view', authenticateToken, (req, res) => {
  const snap = snaps[req.params.snapId];
  if (snap) {
    snap.viewed = true;
    saveData(SNAPS_FILE, snaps);
  }
  res.json({ ok: true });
});

// ===== MESSAGES =====
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
  const convoId = [req.user.userId, req.params.userId].sort().join('-');
  const convoMessages = messages[convoId] || [];
  res.json(convoMessages);
});

app.post('/api/messages', authenticateToken, (req, res) => {
  const { toId, text } = req.body;
  if (!toId || !text) return res.status(400).json({ error: 'Missing fields' });

  const convoId = [req.user.userId, toId].sort().join('-');
  if (!messages[convoId]) messages[convoId] = [];

  const msg = {
    id: genId(),
    from: req.user.userId,
    to: toId,
    text,
    timestamp: Date.now(),
    read: false
  };
  messages[convoId].push(msg);
  saveData(MESSAGES_FILE, messages);
  // send push notification to recipient
  (async () => {
    try {
      const subs = pushSubscriptions[msg.to] || [];
      if (subs.length) {
        const payload = { title: `${users[msg.from]?.username || 'Someone'} sent a message`, body: msg.text.slice(0, 120), url: `/` , actions: [{action:'view',title:'Open'}] };
        const removed = [];
        await Promise.all(subs.map(async (sub) => {
          const ok = await sendPushToSubscription(sub, payload);
          if (!ok) removed.push(sub.endpoint);
        }));
        if (removed.length) {
          pushSubscriptions[msg.to] = (pushSubscriptions[msg.to] || []).filter(s => !removed.includes(s.endpoint));
          if (!pushSubscriptions[msg.to].length) delete pushSubscriptions[msg.to];
          savePushSubscriptions();
        }
      }
    } catch (e) { console.error('Message push error', e); }
  })();

  res.json(msg);
});

// ===== FRIENDS =====
app.post('/api/friends/:userId/follow', authenticateToken, (req, res) => {
  const targetUser = users[req.params.userId];
  const currentUser = users[req.user.userId];
  if (!targetUser || !currentUser) return res.status(404).json({ error: 'User not found' });

  if (!currentUser.friends.includes(req.params.userId)) {
    currentUser.friends.push(req.params.userId);
  }
  if (!targetUser.followers.includes(req.user.userId)) {
    targetUser.followers.push(req.user.userId);
  }
  saveData(USERS_FILE, users);
  res.json({ ok: true });
});

app.get('/api/friends/:userId', authenticateToken, (req, res) => {
  const user = users[req.params.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ friends: user.friends, followers: user.followers });
});

// ===== SEARCH =====
app.get('/api/search', authenticateToken, (req, res) => {
  const q = req.query.q?.toLowerCase() || '';
  if (q.length < 1) return res.json([]);

  const results = Object.values(users)
    .filter(u => u.userId !== req.user.userId && (
      u.username.toLowerCase().includes(q) || 
      u.email.toLowerCase().includes(q) ||
      (u.phone && u.phone.includes(q))
    ))
    .map(u => ({ 
      userId: u.userId, 
      username: u.username, 
      avatar: u.avatar, 
      bio: u.bio,
      phone: u.phone || '',
      gender: u.gender || 'not-specified',
      isFriend: users[req.user.userId].friends.includes(u.userId)
    }))
    .slice(0, 20);

  res.json(results);
});

// ===== RECOMMENDATIONS =====
app.get('/api/recommendations', authenticateToken, (req, res) => {
  const currentUser = users[req.user.userId];
  if (!currentUser) return res.status(404).json({ error: 'User not found' });

  // Get users the current user doesn't follow
  const potentialFriends = Object.values(users)
    .filter(u => 
      u.userId !== req.user.userId && 
      !currentUser.friends.includes(u.userId) &&
      u.emailConfirmed === true  // Only recommend confirmed users
    )
    .map(u => ({
      userId: u.userId,
      username: u.username,
      avatar: u.avatar,
      bio: u.bio,
      gender: u.gender || 'not-specified',
      mutualFriends: currentUser.friends.filter(fId => (users[fId]?.friends || []).includes(u.userId)).length
    }))
    .sort((a, b) => b.mutualFriends - a.mutualFriends)  // Sort by mutual friends
    .slice(0, 12);

  res.json(potentialFriends);
});

// ===== FRIENDS =====
app.post('/api/friends/add', authenticateToken, (req, res) => {
  const { targetId } = req.body;
  const currentUser = users[req.user.userId];
  const targetUser = users[targetId];
  
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  if (currentUser.friends.includes(targetId)) return res.status(400).json({ error: 'Already friends' });

  currentUser.friends.push(targetId);
  targetUser.followers.push(req.user.userId);
  saveData(USERS_FILE, users);
  
  // notify target user
  (async () => {
    try {
      const subs = pushSubscriptions[targetId] || [];
      if (subs.length) {
        const payload = { title: `${currentUser.username} added you`, body: 'You have a new friend', url: `/`, actions: [{action:'view',title:'View'}] };
        const removed = [];
        await Promise.all(subs.map(async (sub) => {
          const ok = await sendPushToSubscription(sub, payload);
          if (!ok) removed.push(sub.endpoint);
        }));
        if (removed.length) {
          pushSubscriptions[targetId] = (pushSubscriptions[targetId] || []).filter(s => !removed.includes(s.endpoint));
          if (!pushSubscriptions[targetId].length) delete pushSubscriptions[targetId];
          savePushSubscriptions();
        }
      }
    } catch (e) { console.error('Friend push error', e); }
  })();

  res.json({ ok: true, friend: { 
    userId: targetUser.userId,
    username: targetUser.username,
    avatar: targetUser.avatar,
    phone: targetUser.phone || '',
    bio: targetUser.bio
  }});
});

app.get('/api/friends', authenticateToken, (req, res) => {
  const currentUser = users[req.user.userId];
  const friendsList = currentUser.friends.map(friendId => {
    const friend = users[friendId];
    return {
      userId: friend.userId,
      username: friend.username,
      avatar: friend.avatar,
      phone: friend.phone || '',
      bio: friend.bio
    };
  });
  res.json(friendsList);
});

app.post('/api/friends/remove', authenticateToken, (req, res) => {
  const { targetId } = req.body;
  const currentUser = users[req.user.userId];
  const targetUser = users[targetId];
  
  if (!targetUser) return res.status(404).json({ error: 'User not found' });

  currentUser.friends = currentUser.friends.filter(id => id !== targetId);
  targetUser.followers = targetUser.followers.filter(id => id !== req.user.userId);
  saveData(USERS_FILE, users);
  
  res.json({ ok: true });
});

// Serve static client
app.use('/', express.static(path.join(__dirname, '..', 'client')));
// Serve uploaded media
app.use('/media', express.static(MEDIA_DIR));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// WebSocket: active connections for real-time messaging
const connections = new Map(); // userId -> ws

wss.on('connection', (ws) => {
  let userId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    const { type } = msg;

    if (type === 'auth') {
      const token = msg.token;
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.userId;
        connections.set(userId, ws);
        ws.send(JSON.stringify({ type: 'auth-ok', userId }));
      } catch (e) {
        ws.send(JSON.stringify({ type: 'auth-fail' }));
      }
      return;
    }

    if (!userId) return;

    if (type === 'message') {
      const { toId, text } = msg;
      const targetWs = connections.get(toId);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
          type: 'new-message',
          from: userId,
          fromUsername: users[userId]?.username || 'Unknown',
          text,
          time: Date.now()
        }));
      }
      return;
    }

    if (type === 'typing') {
      const { toId } = msg;
      const targetWs = connections.get(toId);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({ type: 'user-typing', from: userId }));
      }
      return;
    }

    if (type === 'snap-sent') {
      const { toId } = msg;
      const targetWs = connections.get(toId);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({
          type: 'snap-notification',
          from: userId,
          fromUsername: users[userId]?.username || 'Unknown'
        }));
      }
      return;
    }

    if (type === 'signal') {
      const { toId, data } = msg;
      const targetWs = connections.get(toId);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({ type: 'signal', from: userId, data }));
      }
      return;
    }
  });

  ws.on('close', () => {
    if (userId) connections.delete(userId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🌟 Wimpex server running on http://localhost:${PORT}`));
