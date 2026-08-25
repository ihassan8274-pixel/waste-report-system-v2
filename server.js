const express = require('express');
const path = require('node:path');
const D = require('./database');

D.init();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(roles) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'غير مصرح' });
    const user = D.getUserByToken(token);
    if (!user) return res.status(401).json({ error: 'انتهت الجلسة، سجل الدخول مرة أخرى' });
    if (roles && !roles.includes(user.role)) return res.status(403).json({ error: 'لا تملك صلاحية لهذا الإجراء' });
    req.user = user;
    req.token = token;
    req.permissions = D.getPermissions(user.role);
    next();
  };
}

function err(res, e) {
  console.error(e);
  res.status(500).json({ error: e.message || 'خطأ في الخادم' });
}

// ============ AUTH ============
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = D.db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || '').trim());
    if (!user || !D.verifyPassword(String(password || ''), user.password_hash)) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }
    const token = D.createSession(user.id);
    const branch = D.db.prepare('SELECT * FROM branches WHERE id = ?').get(user.branch_id);
    const permissions = D.getPermissions(user.role);
    res.json({ token, user: publicUser(user, branch, permissions) });
  } catch (e) { err(res, e); }
});

app.post('/api/logout', auth(), (req, res) => {
  try {
    D.db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token);
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

app.get('/api/me', auth(), (req, res) => {
  const branch = D.db.prepare('SELECT * FROM branches WHERE id = ?').get(req.user.branch_id);
  res.json({ user: publicUser(req.user, branch, req.permissions) });
});

function publicUser(u, branch, permissions) {
  return {
    id: u.id, username: u.username, name: u.name, role: u.role,
    branch_id: u.branch_id, branch: branch ? branch.name : null,
    permissions: permissions || {}
  };
}

// ============ BRANCHES ============
app.get('/api/branches', auth(), (req, res) => {
  try {
    if (!req.permissions.branches?.read) return res.status(403).json({ error: 'لا تملك صلاحية عرض الفروع' });
    res.json({ branches: D.db.prepare('SELECT * FROM branches ORDER BY id').all() });
  } catch (e) { err(res, e); }
});

app.post('/api/branches', auth(), (req, res) => {
  try {
    if (!req.permissions.branches?.create) return res.status(403).json({ error: 'لا تملك صلاحية إضافة فروع' });
    const { name, address } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'اسم الفرع مطلوب' });
    const r = D.db.prepare('INSERT INTO branches (name, address) VALUES (?, ?)').run(String(name).trim(), String(address || ''));
    res.json({ branch: D.db.prepare('SELECT * FROM branches WHERE id = ?').get(r.lastInsertRowid) });
  } catch (e) { err(res, e); }
});

app.put('/api/branches/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.branches?.update) return res.status(403).json({ error: 'لا تملك صلاحية تعديل الفروع' });
    const { name, address } = req.body || {};
    D.db.prepare('UPDATE branches SET name = ?, address = ? WHERE id = ?').run(String(name || ''), String(address || ''), req.params.id);
    res.json({ branch: D.db.prepare('SELECT * FROM branches WHERE id = ?').get(req.params.id) });
  } catch (e) { err(res, e); }
});

app.delete('/api/branches/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.branches?.delete) return res.status(403).json({ error: 'لا تملك صلاحية حذف الفروع' });
    const id = req.params.id;
    D.db.prepare('UPDATE users SET branch_id = NULL WHERE branch_id = ?').run(id);
    D.db.prepare('UPDATE reports SET branch_id = NULL WHERE branch_id = ?').run(id);
    D.db.prepare('DELETE FROM branches WHERE id = ?').run(id);
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

// ============ USERS ============
app.get('/api/users', auth(), (req, res) => {
  try {
    if (!req.permissions.users?.read) return res.status(403).json({ error: 'لا تملك صلاحية عرض المستخدمين' });
    const users = D.db.prepare(`
      SELECT u.*, b.name AS branch_name FROM users u
      LEFT JOIN branches b ON b.id = u.branch_id ORDER BY u.id
    `).all();
    res.json({ users: users.map(u => ({ ...u, password_hash: undefined })) });
  } catch (e) { err(res, e); }
});

app.post('/api/users', auth(), (req, res) => {
  try {
    if (!req.permissions.users?.create) return res.status(403).json({ error: 'لا تملك صلاحية إضافة مستخدمين' });
    const { username, password, name, role, branch_id } = req.body || {};
    if (!username || !password || !name) return res.status(400).json({ error: 'بيانات المستخدم ناقصة' });
    const exists = D.db.prepare('SELECT id FROM users WHERE username = ?').get(String(username).trim());
    if (exists) return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
    const r = D.db.prepare('INSERT INTO users (username, password_hash, name, role, branch_id) VALUES (?, ?, ?, ?, ?)')
      .run(String(username).trim(), D.hashPassword(String(password)), String(name), role || 'employee', branch_id || null);
    res.json({ user: D.db.prepare('SELECT id, username, name, role, branch_id FROM users WHERE id = ?').get(r.lastInsertRowid) });
  } catch (e) { err(res, e); }
});

app.put('/api/users/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.users?.update) return res.status(403).json({ error: 'لا تملك صلاحية تعديل المستخدمين' });
    const { name, role, branch_id, password } = req.body || {};
    if (password) {
      D.db.prepare('UPDATE users SET name = ?, role = ?, branch_id = ?, password_hash = ? WHERE id = ?')
        .run(String(name), role || 'employee', branch_id || null, D.hashPassword(String(password)), req.params.id);
    } else {
      D.db.prepare('UPDATE users SET name = ?, role = ?, branch_id = ? WHERE id = ?')
        .run(String(name), role || 'employee', branch_id || null, req.params.id);
    }
    res.json({ user: D.db.prepare('SELECT id, username, name, role, branch_id FROM users WHERE id = ?').get(req.params.id) });
  } catch (e) { err(res, e); }
});

app.delete('/api/users/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.users?.delete) return res.status(403).json({ error: 'لا تملك صلاحية حذف المستخدمين' });
    if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'لا يمكن حذف حسابك الحالي' });
    const u = D.db.prepare('SELECT role FROM users WHERE id = ?').get(req.params.id);
    if (!u) return res.status(404).json({ error: 'المستخدم غير موجود' });
    if (u.role === 'admin') return res.status(400).json({ error: 'لا يمكن حذف مستخدم مدير' });
    D.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
    D.db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

app.put('/api/me/password', auth(), (req, res) => {
  try {
    const { current, next } = req.body || {};
    const u = D.db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!D.verifyPassword(String(current || ''), u.password_hash)) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });
    D.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(D.hashPassword(String(next)), req.user.id);
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

// ============ ITEMS ============
app.get('/api/items', auth(), (req, res) => {
  try {
    res.json({ items: D.db.prepare('SELECT * FROM items ORDER BY name').all() });
  } catch (e) { err(res, e); }
});

app.post('/api/items', auth(), (req, res) => {
  try {
    if (!req.permissions.items?.create) return res.status(403).json({ error: 'لا تملك صلاحية إضافة أصناف' });
    const { name, unit, default_price } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'اسم الصنف مطلوب' });
    const r = D.db.prepare('INSERT INTO items (name, unit, default_price) VALUES (?, ?, ?)')
      .run(String(name).trim(), String(unit || ''), Number(default_price) || 0);
    res.json({ item: D.db.prepare('SELECT * FROM items WHERE id = ?').get(r.lastInsertRowid) });
  } catch (e) { err(res, e); }
});

app.put('/api/items/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.items?.update) return res.status(403).json({ error: 'لا تملك صلاحية تعديل الأصناف' });
    const { name, unit, default_price } = req.body || {};
    D.db.prepare('UPDATE items SET name = ?, unit = ?, default_price = ? WHERE id = ?')
      .run(String(name || ''), String(unit || ''), Number(default_price) || 0, req.params.id);
    res.json({ item: D.db.prepare('SELECT * FROM items WHERE id = ?').get(req.params.id) });
  } catch (e) { err(res, e); }
});

app.delete('/api/items/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.items?.delete) return res.status(403).json({ error: 'لا تملك صلاحية حذف الأصناف' });
    D.db.prepare('DELETE FROM items WHERE id = ?').run(req.params.id);
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

app.get('/api/items/search', auth(), (req, res) => {
  try {
    const { q } = req.query;
    if (!q) return res.json({ items: [] });
    const items = D.db.prepare('SELECT * FROM items WHERE name LIKE ? ORDER BY name LIMIT 10').all(`%${q}%`);
    res.json({ items });
  } catch (e) { err(res, e); }
});

app.get('/api/items/:id/details', auth(), (req, res) => {
  try {
    const item = D.db.prepare('SELECT * FROM items WHERE id = ?').get(req.params.id);
    if (!item) return res.status(404).json({ error: 'الصنف غير موجود' });
    res.json({ item });
  } catch (e) { err(res, e); }
});

app.get('/api/items/:id/usage', auth(), (req, res) => {
  try {
    const usage = D.db.prepare(`
      SELECT 
        ri.item_name,
        COUNT(DISTINCT ri.report_id) AS report_count,
        SUM(ri.qty) AS total_qty,
        SUM(ri.total) AS total_value,
        MIN(r.date) AS first_used,
        MAX(r.date) AS last_used
      FROM report_items ri
      JOIN reports r ON r.id = ri.report_id
      WHERE ri.item_id = ? OR ri.item_name = ?
      GROUP BY ri.item_name
    `).get(req.params.id, req.body?.item_name || '');
    res.json({ usage: usage || {} });
  } catch (e) { err(res, e); }
});

app.get('/api/items/stats', auth(), (req, res) => {
  try {
    const stats = D.db.prepare(`
      SELECT 
        i.id,
        i.name,
        i.unit,
        i.default_price,
        COUNT(DISTINCT ri.report_id) AS report_count,
        COALESCE(SUM(ri.qty), 0) AS total_qty,
        COALESCE(SUM(ri.total), 0) AS total_value
      FROM items i
      LEFT JOIN report_items ri ON ri.item_id = i.id
      GROUP BY i.id
      ORDER BY total_value DESC
    `).all();
    res.json({ stats });
  } catch (e) { err(res, e); }
});

// ============ REPORTS ============
app.get('/api/reports', auth(), (req, res) => {
  try {
    const { branch, from, to, status, q } = req.query;
    let sql = `
      SELECT r.*, b.name AS branch_name, u.name AS creator_name,
        (SELECT COUNT(*) FROM report_items ri WHERE ri.report_id = r.id) AS item_count,
        (SELECT COALESCE(SUM(ri.total), 0) FROM report_items ri WHERE ri.report_id = r.id) AS total_value,
        (SELECT COALESCE(SUM(ri.qty), 0) FROM report_items ri WHERE ri.report_id = r.id) AS total_qty
      FROM reports r
      LEFT JOIN branches b ON b.id = r.branch_id
      LEFT JOIN users u ON u.id = r.created_by
      WHERE 1=1`;
    const params = [];
    if (req.user.role === 'employee') { sql += ' AND r.created_by = ?'; params.push(req.user.id); }
    if (branch) { sql += ' AND r.branch_id = ?'; params.push(branch); }
    if (from) { sql += ' AND r.date >= ?'; params.push(from); }
    if (to) { sql += ' AND r.date <= ?'; params.push(to); }
    if (status) { sql += ' AND r.status = ?'; params.push(status); }
    if (q) { sql += ' AND (r.serial LIKE ? OR r.responsible LIKE ? OR r.notes LIKE ?)'; params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
    sql += ' ORDER BY r.created_at DESC, r.id DESC';
    res.json({ reports: D.db.prepare(sql).all(...params) });
  } catch (e) { err(res, e); }
});

app.get('/api/reports/:id', auth(), (req, res) => {
  try {
    const report = D.db.prepare(`
      SELECT r.*, b.name AS branch_name, u.name AS creator_name
      FROM reports r
      LEFT JOIN branches b ON b.id = r.branch_id
      LEFT JOIN users u ON u.id = r.created_by
      WHERE r.id = ?
    `).get(req.params.id);
    if (!report) return res.status(404).json({ error: 'المحضر غير موجود' });
    if (req.user.role === 'employee' && report.created_by !== req.user.id) return res.status(403).json({ error: 'لا تملك صلاحية لهذا المحضر' });
    const items = D.db.prepare('SELECT * FROM report_items WHERE report_id = ? ORDER BY id').all(report.id);
    res.json({ report, items });
  } catch (e) { err(res, e); }
});

function parseReportBody(body) {
  return {
    branch_id: body.branch_id || null,
    date: body.date || new Date().toLocaleDateString('en-GB'),
    responsible: String(body.responsible || ''),
    notes: String(body.notes || ''),
    status: body.status || 'مسودة'
  };
}

app.post('/api/reports', auth(), (req, res) => {
  try {
    const data = parseReportBody(req.body);
    const serial = D.nextSerial();
    const r = D.db.prepare(`
      INSERT INTO reports (serial, branch_id, date, responsible, notes, status, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(serial, data.branch_id, data.date, data.responsible, data.notes, data.status, req.user.id);
    const reportId = Number(r.lastInsertRowid);
    insertItems(reportId, req.body.items || []);
    res.json({ report: D.db.prepare('SELECT * FROM reports WHERE id = ?').get(reportId), serial });
  } catch (e) { err(res, e); }
});

app.put('/api/reports/:id', auth(), (req, res) => {
  try {
    const existing = D.db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'المحضر غير موجود' });
    if (req.user.role === 'employee' && existing.created_by !== req.user.id) return res.status(403).json({ error: 'لا تملك صلاحية لهذا المحضر' });
    const data = parseReportBody(req.body);
    D.db.prepare(`
      UPDATE reports SET branch_id = ?, date = ?, responsible = ?, notes = ?, status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(data.branch_id, data.date, data.responsible, data.notes, data.status, req.params.id);
    D.db.prepare('DELETE FROM report_items WHERE report_id = ?').run(req.params.id);
    insertItems(Number(req.params.id), req.body.items || []);
    res.json({ report: D.db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id) });
  } catch (e) { err(res, e); }
});

function insertItems(reportId, items) {
  const insert = D.db.prepare(`
    INSERT INTO report_items (report_id, item_id, item_name, unit, qty, price, total, waste_type, prod_date, exp_date, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  D.db.exec('BEGIN');
  try {
    for (const it of items) {
      const qty = Number(it.qty) || 0;
      const price = Number(it.price) || 0;
      const itemName = String(it.item_name || it.name || '');
      const itemId = it.item_id || null;
      insert.run(reportId, itemId, itemName, String(it.unit || ''),
        qty, price, Number((qty * price).toFixed(2)),
        it.waste_type || 'أخرى', String(it.prod_date || ''), String(it.exp_date || ''), String(it.reason || ''));
    }
    D.db.exec('COMMIT');
  } catch (e) {
    D.db.exec('ROLLBACK');
    throw e;
  }
}

app.delete('/api/reports/:id', auth(), (req, res) => {
  try {
    if (!req.permissions.reports?.delete) return res.status(403).json({ error: 'لا تملك صلاحية حذف المحاضر' });
    D.db.prepare('DELETE FROM report_items WHERE report_id = ?').run(req.params.id);
    const r = D.db.prepare('DELETE FROM reports WHERE id = ?').run(req.params.id);
    if (!r.changes) return res.status(404).json({ error: 'المحضر غير موجود' });
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

app.get('/api/reports/:id/export', auth(), (req, res) => {
  try {
    const report = D.db.prepare(`
      SELECT r.*, b.name AS branch_name FROM reports r
      LEFT JOIN branches b ON b.id = r.branch_id WHERE r.id = ?
    `).get(req.params.id);
    if (!report) return res.status(404).json({ error: 'المحضر غير موجود' });
    if (req.user.role === 'employee' && report.created_by !== req.user.id) return res.status(403).json({ error: 'لا تملك صلاحية لهذا المحضر' });
    const items = D.db.prepare('SELECT * FROM report_items WHERE report_id = ? ORDER BY id').all(report.id);
    const rows = [['#', 'اسم الصنف', 'الوحدة', 'الكمية', 'سعر الوحدة', 'الإجمالي', 'نوع الفاقد', 'تاريخ الإنتاج', 'تاريخ الصلاحية', 'سبب الهالك']];
    items.forEach((it, i) => rows.push([i + 1, it.item_name, it.unit, it.qty, it.price, it.total, it.waste_type, it.prod_date, it.exp_date, it.reason]));
    let total = 0, qty = 0;
    items.forEach(it => { total += it.total; qty += it.qty; });
    rows.push([]);
    rows.push(['الإجمالي الكلي', '', '', '', '', total.toFixed(2)]);
    rows.push(['إجمالي الكميات', '', '', qty.toFixed(1)]);
    const csv = '\uFEFF' + rows.map(r => r.map(c => `"${String(c == null ? '' : c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="WasteReport_${report.serial}.csv"`);
    res.send(csv);
  } catch (e) { err(res, e); }
});

// ============ STATS ============
app.get('/api/stats', auth(), (req, res) => {
  try {
    const { from, to, branch } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (from) { where += ' AND r.date >= ?'; params.push(from); }
    if (to) { where += ' AND r.date <= ?'; params.push(to); }
    if (branch) { where += ' AND r.branch_id = ?'; params.push(branch); }
    if (req.user.role === 'employee') { where += ' AND r.created_by = ?'; params.push(req.user.id); }

    const totals = D.db.prepare(`
      SELECT COUNT(DISTINCT r.id) AS reports_count,
        COALESCE(SUM(ri.qty),0) AS total_qty,
        COALESCE(SUM(ri.total),0) AS total_value,
        COALESCE(SUM(ri.qty * ri.price),0) AS total_cost
      FROM reports r JOIN report_items ri ON ri.report_id = r.id ${where}
    `).get(...params);

    const monthly = D.db.prepare(`
      SELECT substr(r.date, 4, 2) || '/' || substr(r.date, 7) AS month,
        COALESCE(SUM(ri.total),0) AS value
      FROM reports r JOIN report_items ri ON ri.report_id = r.id ${where}
      GROUP BY month ORDER BY month
    `).all(...params);

    const byBranch = D.db.prepare(`
      SELECT COALESCE(b.name, 'بدون فرع') AS branch,
        COALESCE(SUM(ri.total),0) AS value,
        COUNT(DISTINCT r.id) AS count
      FROM reports r JOIN report_items ri ON ri.report_id = r.id
      LEFT JOIN branches b ON b.id = r.branch_id ${where}
      GROUP BY b.id ORDER BY value DESC
    `).all(...params);

    const byType = D.db.prepare(`
      SELECT ri.waste_type AS type, COALESCE(SUM(ri.total),0) AS value, SUM(ri.qty) AS qty
      FROM reports r JOIN report_items ri ON ri.report_id = r.id ${where}
      GROUP BY ri.waste_type ORDER BY value DESC
    `).all(...params);

    const topItems = D.db.prepare(`
      SELECT ri.item_name AS name, SUM(ri.qty) AS qty, COALESCE(SUM(ri.total),0) AS value
      FROM reports r JOIN report_items ri ON ri.report_id = r.id ${where}
      GROUP BY ri.item_name ORDER BY value DESC LIMIT 10
    `).all(...params);

    res.json({ totals, monthly, byBranch, byType, topItems });
  } catch (e) { err(res, e); }
});

// ============ SETTINGS ============
app.get('/api/settings', auth(), (req, res) => {
  try {
    if (!req.permissions.settings?.read) return res.status(403).json({ error: 'لا تملك صلاحية عرض الإعدادات' });
    const rows = D.db.prepare('SELECT * FROM settings').all();
    const s = {};
    rows.forEach(r => s[r.key] = r.value);
    res.json({ settings: s });
  } catch (e) { err(res, e); }
});

app.put('/api/settings', auth(), (req, res) => {
  try {
    if (!req.permissions.settings?.update) return res.status(403).json({ error: 'لا تملك صلاحية تعديل الإعدادات' });
    const allowed = ['company_name', 'company_subtitle', 'company_logo'];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        const exists = D.db.prepare('SELECT key FROM settings WHERE key = ?').get(key);
        if (exists) D.db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(String(req.body[key]), key);
        else D.db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(key, String(req.body[key]));
      }
    }
    res.json({ ok: true });
  } catch (e) { err(res, e); }
});

// ============ PERMISSIONS ============
app.get('/api/permissions', auth(['admin']), (req, res) => {
  try {
    const permissions = D.getAllPermissions();
    const grouped = {};
    permissions.forEach(p => {
      if (!grouped[p.role]) grouped[p.role] = {};
      if (!grouped[p.role][p.module]) grouped[p.role][p.module] = {};
      grouped[p.role][p.module][p.action] = !!p.allowed;
    });
    res.json({ permissions: grouped });
  } catch (e) { err(res, e); }
});

app.get('/api/permissions/:role', auth(), (req, res) => {
  try {
    const permissions = D.getPermissions(req.params.role);
    res.json({ permissions });
  } catch (e) { err(res, e); }
});

app.put('/api/permissions/:role', auth(['admin']), (req, res) => {
  try {
    const { permissions } = req.body || {};
    if (!permissions) return res.status(400).json({ error: 'الصلاحيات مطلوبة' });
    D.updatePermissions(req.params.role, permissions);
    res.json({ ok: true, permissions: D.getPermissions(req.params.role) });
  } catch (e) { err(res, e); }
});

app.get('/api/me/permissions', auth(), (req, res) => {
  try {
    const permissions = D.getPermissions(req.user.role);
    res.json({ permissions });
  } catch (e) { err(res, e); }
});

D.cleanupSessions();
setInterval(D.cleanupSessions, 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log('نظام محضر الهالك يعمل على: http://localhost:' + PORT);
});