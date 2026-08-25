const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'app.db'));
db.exec('PRAGMA journal_mode = WAL;');

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS branches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      address TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      branch_id INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      serial TEXT NOT NULL,
      branch_id INTEGER,
      date TEXT NOT NULL,
      responsible TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'مسودة',
      created_by INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (branch_id) REFERENCES branches(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS report_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      item_id INTEGER,
      item_name TEXT NOT NULL,
      unit TEXT DEFAULT '',
      qty REAL DEFAULT 0,
      price REAL DEFAULT 0,
      total REAL DEFAULT 0,
      waste_type TEXT DEFAULT 'أخرى',
      prod_date TEXT DEFAULT '',
      exp_date TEXT DEFAULT '',
      reason TEXT DEFAULT '',
      FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE,
      FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      unit TEXT DEFAULT '',
      default_price REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL,
      module TEXT NOT NULL,
      action TEXT NOT NULL,
      allowed INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(role, module, action)
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const branchCount = db.prepare('SELECT COUNT(*) AS c FROM branches').get().c;
  if (branchCount === 0) {
    db.prepare('INSERT INTO branches (name, address) VALUES (?, ?)').run('المركز الرئيسي', '');
    db.prepare('INSERT INTO branches (name, address) VALUES (?, ?)').run('فرع الرياض', '');
  }

  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount === 0) {
    const hash = hashPassword('admin123');
    db.prepare('INSERT INTO users (username, password_hash, name, role, branch_id) VALUES (?, ?, ?, ?, ?)')
      .run('admin', hash, 'مدير النظام', 'admin', 1);
  }

  const itemCount = db.prepare('SELECT COUNT(*) AS c FROM items').get().c;
  if (itemCount === 0) {
    const insert = db.prepare('INSERT INTO items (name, unit, default_price) VALUES (?, ?, ?)');
    [
      ['معصوب حليب', 'طبق', 15],
      ['معصوب موز', 'طبق', 18],
      ['معصوب تمر', 'طبق', 17],
      ['عصير برتقال', 'كوب', 8],
      ['شاي', 'كوب', 5]
    ].forEach(i => insert.run(i[0], i[1], i[2]));
  }

  if (!db.prepare('SELECT value FROM settings WHERE key = ?').get('serial_counter')) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('serial_counter', '0');
  }

  // Initialize default permissions if not exist
  const permCount = db.prepare('SELECT COUNT(*) AS c FROM permissions').get().c;
  if (permCount === 0) {
    const defaultPerms = [
      // Admin - full access
      { role: 'admin', module: 'dashboard', action: 'view', allowed: 1 },
      { role: 'admin', module: 'reports', action: 'create', allowed: 1 },
      { role: 'admin', module: 'reports', action: 'read', allowed: 1 },
      { role: 'admin', module: 'reports', action: 'update', allowed: 1 },
      { role: 'admin', module: 'reports', action: 'delete', allowed: 1 },
      { role: 'admin', module: 'reports', action: 'export', allowed: 1 },
      { role: 'admin', module: 'items', action: 'create', allowed: 1 },
      { role: 'admin', module: 'items', action: 'read', allowed: 1 },
      { role: 'admin', module: 'items', action: 'update', allowed: 1 },
      { role: 'admin', module: 'items', action: 'delete', allowed: 1 },
      { role: 'admin', module: 'branches', action: 'create', allowed: 1 },
      { role: 'admin', module: 'branches', action: 'read', allowed: 1 },
      { role: 'admin', module: 'branches', action: 'update', allowed: 1 },
      { role: 'admin', module: 'branches', action: 'delete', allowed: 1 },
      { role: 'admin', module: 'users', action: 'create', allowed: 1 },
      { role: 'admin', module: 'users', action: 'read', allowed: 1 },
      { role: 'admin', module: 'users', action: 'update', allowed: 1 },
      { role: 'admin', module: 'users', action: 'delete', allowed: 1 },
      { role: 'admin', module: 'settings', action: 'read', allowed: 1 },
      { role: 'admin', module: 'settings', action: 'update', allowed: 1 },
      { role: 'admin', module: 'permissions', action: 'read', allowed: 1 },
      { role: 'admin', module: 'permissions', action: 'update', allowed: 1 },
      // Manager
      { role: 'manager', module: 'dashboard', action: 'view', allowed: 1 },
      { role: 'manager', module: 'reports', action: 'create', allowed: 1 },
      { role: 'manager', module: 'reports', action: 'read', allowed: 1 },
      { role: 'manager', module: 'reports', action: 'update', allowed: 1 },
      { role: 'manager', module: 'reports', action: 'delete', allowed: 1 },
      { role: 'manager', module: 'reports', action: 'export', allowed: 1 },
      { role: 'manager', module: 'items', action: 'create', allowed: 1 },
      { role: 'manager', module: 'items', action: 'read', allowed: 1 },
      { role: 'manager', module: 'items', action: 'update', allowed: 1 },
      { role: 'manager', module: 'items', action: 'delete', allowed: 1 },
      { role: 'manager', module: 'branches', action: 'read', allowed: 1 },
      { role: 'manager', module: 'users', action: 'read', allowed: 0 },
      { role: 'manager', module: 'settings', action: 'read', allowed: 0 },
      { role: 'manager', module: 'permissions', action: 'read', allowed: 0 },
      // Employee
      { role: 'employee', module: 'dashboard', action: 'view', allowed: 1 },
      { role: 'employee', module: 'reports', action: 'create', allowed: 1 },
      { role: 'employee', module: 'reports', action: 'read', allowed: 1 },
      { role: 'employee', module: 'reports', action: 'update', allowed: 1 },
      { role: 'employee', module: 'reports', action: 'delete', allowed: 0 },
      { role: 'employee', module: 'reports', action: 'export', allowed: 1 },
      { role: 'employee', module: 'items', action: 'read', allowed: 1 },
      { role: 'employee', module: 'items', action: 'create', allowed: 0 },
      { role: 'employee', module: 'items', action: 'update', allowed: 0 },
      { role: 'employee', module: 'items', action: 'delete', allowed: 0 },
      { role: 'employee', module: 'branches', action: 'read', allowed: 0 },
      { role: 'employee', module: 'users', action: 'read', allowed: 0 },
      { role: 'employee', module: 'settings', action: 'read', allowed: 0 },
      { role: 'employee', module: 'permissions', action: 'read', allowed: 0 },
    ];
    const insertPerm = db.prepare('INSERT INTO permissions (role, module, action, allowed) VALUES (?, ?, ?, ?)');
    defaultPerms.forEach(p => insertPerm.run(p.role, p.module, p.action, p.allowed));
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
}

function nextSerial() {
  const counter = parseInt(db.prepare('SELECT value FROM settings WHERE key = ?').get('serial_counter').value, 10) + 1;
  db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(counter), 'serial_counter');
  return 'WR-' + String(counter).padStart(5, '0');
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires);
  return token;
}

function getUserByToken(token) {
  const row = db.prepare(`
    SELECT u.* FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);
  return row || null;
}

function cleanupSessions() {
  db.prepare('DELETE FROM sessions WHERE expires_at <= datetime(\'now\')').run();
}

function getPermissions(role) {
  const perms = db.prepare('SELECT module, action, allowed FROM permissions WHERE role = ?').all(role);
  const result = {};
  perms.forEach(p => {
    if (!result[p.module]) result[p.module] = {};
    result[p.module][p.action] = !!p.allowed;
  });
  return result;
}

function hasPermission(role, module, action) {
  const perm = db.prepare('SELECT allowed FROM permissions WHERE role = ? AND module = ? AND action = ?').get(role, module, action);
  return perm ? !!perm.allowed : false;
}

function updatePermissions(role, permissions) {
  const update = db.prepare('UPDATE permissions SET allowed = ? WHERE role = ? AND module = ? AND action = ?');
  const insert = db.prepare('INSERT OR IGNORE INTO permissions (role, module, action, allowed) VALUES (?, ?, ?, ?)');
  const transaction = db.transaction(() => {
    for (const [module, actions] of Object.entries(permissions)) {
      for (const [action, allowed] of Object.entries(actions)) {
        const result = update.run(allowed ? 1 : 0, role, module, action);
        if (result.changes === 0) {
          insert.run(role, module, action, allowed ? 1 : 0);
        }
      }
    }
  });
  transaction();
}

function getAllPermissions() {
  return db.prepare('SELECT * FROM permissions ORDER BY role, module, action').all();
}

function getItemByName(name) {
  return db.prepare('SELECT * FROM items WHERE name = ?').get(name);
}

module.exports = { db, init, hashPassword, verifyPassword, nextSerial, createSession, getUserByToken, cleanupSessions, getPermissions, hasPermission, updatePermissions, getAllPermissions, getItemByName };