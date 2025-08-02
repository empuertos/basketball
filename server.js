// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const csurf = require('csurf');
const db = require('./db');
const { requireAdmin } = require('./auth');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback-secret-change-this';

// security headers
app.use(helmet());

// parse form and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// session middleware
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax', // adjust if you have cross-site needs
    secure: false, // set to true if using HTTPS in production
    maxAge: 1000 * 60 * 60 * 4 // 4 hours
  }
}));

// CSRF protection for state-changing POSTs
app.use(csurf());

// serve frontend (you can point to your existing HTML)
app.use(express.static(path.join(__dirname, 'public')));

// helper to get setting
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value);
}

// Route: login form (POST)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing credentials');

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).send('Invalid username or password');

  bcrypt.compare(password, user.password_hash, (err, ok) => {
    if (err) return res.status(500).send('Server error');
    if (!ok) return res.status(401).send('Invalid username or password');

    // success: set session
    req.session.user = { id: user.id, username: user.username, is_admin: !!user.is_admin };
    res.redirect('/?login=success');
  });
});

// Route: logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// Admin-protected endpoints

// Get current embed code & events (admin or viewer)
app.get('/api/state', (req, res) => {
  const embed = getSetting('embed_code') || '';
  const events = db.prepare('SELECT * FROM events ORDER BY datetime ASC').all();
  res.json({ embed, events, user: req.session.user || null, csrfToken: req.csrfToken() });
});

// Set embed code (admin only)
app.post('/api/embed', requireAdmin, (req, res) => {
  const { embed } = req.body;
  setSetting('embed_code', embed || '');
  res.json({ success: true });
});

// Add event (admin only)
app.post('/api/events', requireAdmin, (req, res) => {
  const { name, datetime } = req.body;
  if (!name || !datetime) return res.status(400).json({ error: 'Missing name or datetime' });
  db.prepare('INSERT INTO events(name, datetime) VALUES(?,?)').run(name.trim(), datetime);
  res.json({ success: true });
});

// Delete event (admin only)
app.delete('/api/events/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM events WHERE id = ?').run(id);
  res.json({ success: true });
});

// Utility: create initial admin if none exists (run once)
async function ensureAdmin() {
  const existing = db.prepare('SELECT * FROM users WHERE is_admin = 1 LIMIT 1').get();
  if (!existing) {
    const defaultUsername = 'admin';
    const defaultPassword = 'ChangeMe!123'; // you should prompt to change immediately
    const hash = await bcrypt.hash(defaultPassword, 12);
    db.prepare('INSERT INTO users(username, password_hash, is_admin) VALUES(?,?,1)').run(defaultUsername, hash);
    console.log(`Created default admin account: ${defaultUsername} / ${defaultPassword} (please change)`);
  }
}

ensureAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});
