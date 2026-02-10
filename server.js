const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Try to load nodemailer
try {
  var nodemailer = require('nodemailer');
} catch (e) {
  console.log('Nodemailer not installed');
  var nodemailer = null;
}

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const DATA_DIR = '/tmp/data';

console.log('Data directory:', DATA_DIR);

// Ensure data directory exists
try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    console.log('Created data directory');
  }
} catch (e) {
  console.error('Failed to create data directory:', e.message);
}

const DB = {
  users: path.join(DATA_DIR, 'users.json'),
  purchases: path.join(DATA_DIR, 'purchases.json'),
  sales: path.join(DATA_DIR, 'sales.json'),
  branches: path.join(DATA_DIR, 'branches.json'),
  resetCodes: path.join(DATA_DIR, 'resetCodes.json'),
  emails: path.join(DATA_DIR, 'emails.json'),
  reviews: path.join(DATA_DIR, 'reviews.json')
};

// Initialize DB files
Object.values(DB).forEach(file => {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, '[]');
      console.log('Created:', path.basename(file));
    }
  } catch (e) {
    console.error('Failed to create', path.basename(file), ':', e.message);
  }
});

// Gmail SMTP Configuration
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;

let gmailTransporter = null;
if (nodemailer && GMAIL_USER && GMAIL_PASS) {
  gmailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_PASS }
  });
  console.log('Gmail configured:', GMAIL_USER);
} else {
  console.log('Gmail not configured');
}

const sendEmail = async (to, subject, text) => {
  const email = { id: crypto.randomUUID(), to, subject, text, sentAt: new Date().toISOString() };
  try {
    const emails = JSON.parse(fs.readFileSync(DB.emails, 'utf8') || '[]');
    emails.push(email);
    fs.writeFileSync(DB.emails, JSON.stringify(emails, null, 2));
  } catch (e) {}
  
  if (gmailTransporter) {
    try {
      await gmailTransporter.sendMail({
        from: '"ProfitTrack" <' + GMAIL_USER + '>',
        to, subject, text,
        html: text.replace(/\n/g, '<br>')
      });
      console.log('Email sent to', to);
      return { ...email, sent: true };
    } catch (err) {
      console.error('Email failed:', err.message);
    }
  }
  
  console.log('Email logged (Gmail not configured)');
  return { ...email, sent: false };
};

const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd + JWT_SECRET).digest('hex');

const generateToken = (user) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ id: user.id, login: user.login, email: user.email, name: user.name, iat: Date.now() })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + payload).digest('base64url');
  return header + '.' + payload + '.' + signature;
};

const verifyToken = (token) => {
  try {
    const parts = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(parts[0] + '.' + parts[1]).digest('base64url');
    if (parts[2] !== expected) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch (e) { return null; }
};

const setCORS = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

const parseBody = (req) => new Promise((resolve, reject) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
});

const getAuthUser = (req) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const decoded = verifyToken(auth.substring(7));
  if (!decoded) return null;
  const users = JSON.parse(fs.readFileSync(DB.users, 'utf8') || '[]');
  return users.find(u => u.id === decoded.id);
};

const readDB = (dbName) => {
  try { return JSON.parse(fs.readFileSync(DB[dbName], 'utf8') || '[]'); } 
  catch (e) { return []; }
};

const writeDB = (dbName, data) => {
  fs.writeFileSync(DB[dbName], JSON.stringify(data, null, 2));
};

const routes = {
  'POST /api/auth/register': async (req, res) => {
    const { name, login, password, email } = await parseBody(req);
    if (!name || !login || !password) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Заполните все поля' })); }
    if (!email) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Email обязателен' })); }
    const users = readDB('users');
    if (users.find(u => u.login === login)) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Логин занят' })); }
    const newUser = { id: crypto.randomUUID(), name, login, email, password: hashPassword(password), createdAt: new Date().toISOString() };
    users.push(newUser);
    writeDB('users', users);
    const token = generateToken(newUser);
    res.writeHead(201); res.end(JSON.stringify({ token, user: { id: newUser.id, name, login, email } }));
  },
  
  'POST /api/auth/login': async (req, res) => {
    const { login, password } = await parseBody(req);
    const users = readDB('users');
    const user = users.find(u => u.login === login && u.password === hashPassword(password));
    if (!user) { res.writeHead(401); return res.end(JSON.stringify({ error: 'Неверный логин или пароль' })); }
    const token = generateToken(user);
    res.writeHead(200); res.end(JSON.stringify({ token, user: { id: user.id, name: user.name, login: user.login, email: user.email } }));
  },
  
  'POST /api/auth/forgot-password': async (req, res) => {
    const { email } = await parseBody(req);
    const users = readDB('users');
    const user = users.find(u => u.email === email);
    if (!user) { res.writeHead(404); return res.end(JSON.stringify({ error: 'Email не найден' })); }
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const resetCodes = readDB('resetCodes');
    const filtered = resetCodes.filter(c => c.email !== email);
    filtered.push({ email, code, expiresAt: Date.now() + 15 * 60 * 1000 });
    writeDB('resetCodes', filtered);
    await sendEmail(email, 'Восстановление пароля - ProfitTrack', 'Здравствуйте, ' + user.name + '!\n\nВаш код: ' + code + '\n\nКод действителен 15 минут.');
    res.writeHead(200); res.end(JSON.stringify({ message: 'Код отправлен', code }));
  },
  
  'POST /api/auth/verify-code': async (req, res) => {
    const { email, code } = await parseBody(req);
    const resetCodes = readDB('resetCodes');
    const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
    if (!resetCode || Date.now() > resetCode.expiresAt) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Неверный код' })); }
    res.writeHead(200); res.end(JSON.stringify({ message: 'Код подтвержден' }));
  },
  
  'POST /api/auth/reset-password': async (req, res) => {
    const { email, code, newPassword } = await parseBody(req);
    if (!newPassword || newPassword.length < 4) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Пароль минимум 4 символа' })); }
    const resetCodes = readDB('resetCodes');
    const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
    if (!resetCode || Date.now() > resetCode.expiresAt) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Неверный код' })); }
    const users = readDB('users');
    const idx = users.findIndex(u => u.email === email);
    users[idx].password = hashPassword(newPassword);
    writeDB('users', users);
    writeDB('resetCodes', resetCodes.filter(c => c.code !== code.toUpperCase()));
    res.writeHead(200); res.end(JSON.stringify({ message: 'Пароль изменен' }));
  }
};

const serveStatic = (req, res) => {
  const url = req.url === '/' ? '/index.html' : req.url;
  const filePath = path.join(__dirname, 'public', url);
  try {
    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    const contentType = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  } catch (e) {
    res.writeHead(404); res.end('Not found');
  }
};

const server = http.createServer(async (req, res) => {
  setCORS(res);
  if (req.method === 'OPTIONS') { res.writeHead(200); return res.end(); }
  
  const pathname = req.url.split('?')[0];
  const routeKey = req.method + ' ' + pathname;
  
  if (routes[routeKey]) {
    try { await routes[routeKey](req, res); } 
    catch (e) { console.error(e); res.writeHead(500); res.end(JSON.stringify({ error: 'Server error' })); }
    return;
  }
  
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log('Server running on port', PORT);
  console.log('Gmail:', GMAIL_USER ? 'Configured' : 'Not configured');
});
