const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
const SECRET = 'predictiveflow_secret_2026';

app.use(cors({
  origin: ['http://localhost', 'http://localhost:5173', 'capacitor://localhost', 'https://localhost'],
  credentials: true
}));
app.use(express.json());

// Middleware auth
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }) }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  next();
};

// AUTH
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, role, full_name FROM users WHERE id = ?').get(req.user.id);
  res.json({ user });
});

// MACHINES
app.get('/api/machines', auth, (req, res) => {
  const machines = db.prepare('SELECT * FROM machines ORDER BY created_at DESC').all();
  res.json({ machines });
});

app.post('/api/machines', auth, adminOnly, (req, res) => {
  const { name, type, location, description } = req.body;
  const result = db.prepare('INSERT INTO machines (name, type, location, description) VALUES (?, ?, ?, ?)').run(name, type, location, description);
  const machine = db.prepare('SELECT * FROM machines WHERE id = ?').get(result.lastInsertRowid);
  res.json({ machine });
});

app.put('/api/machines/:id', auth, adminOnly, (req, res) => {
  const { name, type, location, description, status } = req.body;
  db.prepare('UPDATE machines SET name=?, type=?, location=?, description=?, status=? WHERE id=?').run(name, type, location, description, status, req.params.id);
  const machine = db.prepare('SELECT * FROM machines WHERE id = ?').get(req.params.id);
  res.json({ machine });
});

app.delete('/api/machines/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM machines WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// COMPOSANTS
app.get('/api/machines/:id/components', auth, (req, res) => {
  const components = db.prepare('SELECT * FROM components WHERE machine_id = ?').all(req.params.id);
  res.json({ components });
});

app.post('/api/machines/:id/components', auth, adminOnly, (req, res) => {
  const { name, type, threshold_min, threshold_max, unit } = req.body;
  const result = db.prepare('INSERT INTO components (machine_id, name, type, threshold_min, threshold_max, unit) VALUES (?, ?, ?, ?, ?, ?)').run(req.params.id, name, type, threshold_min, threshold_max, unit);
  const component = db.prepare('SELECT * FROM components WHERE id = ?').get(result.lastInsertRowid);
  res.json({ component });
});

// CAPTEURS
app.post('/api/sensors/push', auth, (req, res) => {
  const { component_id, value } = req.body;
  db.prepare('INSERT INTO sensor_data (component_id, value) VALUES (?, ?)').run(component_id, value);
  const component = db.prepare('SELECT * FROM components WHERE id = ?').get(component_id);
  if (component && (value < component.threshold_min || value > component.threshold_max)) {
    const machine = db.prepare('SELECT * FROM machines WHERE id = ?').get(component.machine_id);
    db.prepare('INSERT INTO alerts (machine_id, component_id, severity, value, unit, threshold_min, threshold_max) VALUES (?, ?, ?, ?, ?, ?, ?)').run(component.machine_id, component_id, value > component.threshold_max * 1.2 ? 'critical' : 'warning', value, component.unit, component.threshold_min, component.threshold_max);
    db.prepare('UPDATE machines SET status = ? WHERE id = ?').run('warning', component.machine_id);
  }
  res.json({ success: true });
});

app.get('/api/sensors/overview', auth, (req, res) => {
  const sensors = db.prepare(`
    SELECT s.value, s.recorded_at, c.name as component_name, c.id as component_id, c.type, c.unit, c.threshold_min, c.threshold_max
    FROM sensor_data s JOIN components c ON s.component_id = c.id
    WHERE s.id IN (SELECT MAX(id) FROM sensor_data GROUP BY component_id)
  `).all();
  res.json({ sensors });
});

// ALERTES
app.get('/api/alerts', auth, (req, res) => {
  const alerts = db.prepare(`
    SELECT a.*, m.name as machine_name, c.name as component_name
    FROM alerts a
    LEFT JOIN machines m ON a.machine_id = m.id
    LEFT JOIN components c ON a.component_id = c.id
    WHERE a.resolved_at IS NULL
    ORDER BY a.created_at DESC LIMIT 50
  `).all();
  res.json({ alerts });
});

app.put('/api/alerts/:id/resolve', auth, (req, res) => {
  db.prepare('UPDATE alerts SET resolved_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ADMIN
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, email, full_name, role, created_at FROM users').all();
  res.json({ users });
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { email, password, full_name, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)').run(email, hash, full_name, role || 'client');
  const user = db.prepare('SELECT id, email, full_name, role FROM users WHERE id = ?').get(result.lastInsertRowid);
  res.json({ user });
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// PROJETS
app.get('/api/projects', auth, (req, res) => {
  const projects = db.prepare('SELECT * FROM projects ORDER BY created_at DESC').all();
  const result = projects.map(p => ({
    ...p,
    steps: db.prepare('SELECT * FROM project_steps WHERE project_id = ?').all(p.id),
    interventions: db.prepare('SELECT * FROM interventions WHERE project_id = ?').all(p.id)
  }));
  res.json({ projects: result });
});

app.post('/api/projects', auth, adminOnly, (req, res) => {
  const { name, description, start_date, end_date } = req.body;
  const result = db.prepare('INSERT INTO projects (name, description, start_date, end_date) VALUES (?, ?, ?, ?)').run(name, description, start_date, end_date);
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(result.lastInsertRowid);
  res.json({ project });
});

app.get('/api/projects/:id', auth, (req, res) => {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  project.steps = db.prepare('SELECT * FROM project_steps WHERE project_id = ?').all(project.id);
  project.interventions = db.prepare('SELECT * FROM interventions WHERE project_id = ?').all(project.id);
  res.json({ project });
});

app.post('/api/projects/:id/steps', auth, adminOnly, (req, res) => {
  const { title } = req.body;
  const result = db.prepare('INSERT INTO project_steps (project_id, title) VALUES (?, ?)').run(req.params.id, title);
  const step = db.prepare('SELECT * FROM project_steps WHERE id = ?').get(result.lastInsertRowid);
  res.json({ step });
});

app.patch('/api/projects/:id/steps/:stepId', auth, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE project_steps SET status = ? WHERE id = ?').run(status, req.params.stepId);
  const steps = db.prepare('SELECT * FROM project_steps WHERE project_id = ?').all(req.params.id);
  const done = steps.filter(s => s.status === 'done').length;
  const progress = steps.length > 0 ? Math.round((done / steps.length) * 100) : 0;
  db.prepare('UPDATE projects SET progress = ? WHERE id = ?').run(progress, req.params.id);
  res.json({ success: true });
});

app.post('/api/projects/:id/interventions', auth, adminOnly, (req, res) => {
  const { date, description, technician } = req.body;
  const result = db.prepare('INSERT INTO interventions (project_id, date, description, technician) VALUES (?, ?, ?, ?)').run(req.params.id, date, description, technician);
  const intervention = db.prepare('SELECT * FROM interventions WHERE id = ?').get(result.lastInsertRowid);
  res.json({ intervention });
});

// DEVIS
app.get('/api/quotes', auth, adminOnly, (req, res) => {
  const quotes = db.prepare('SELECT * FROM quotes ORDER BY created_at DESC').all();
  res.json({ quotes });
});

app.post('/api/quotes', auth, adminOnly, (req, res) => {
  const { client_id, items, discount, notes } = req.body;
  const client = db.prepare('SELECT * FROM users WHERE id = ?').get(client_id);
  const total = items.reduce((s, it) => s + (it.quantity * it.unit_price), 0) * (1 - (discount || 0) / 100);
  const result = db.prepare('INSERT INTO quotes (client_id, client_name, total, discount, notes, items) VALUES (?, ?, ?, ?, ?, ?)').run(client_id, client?.full_name || client?.email, total, discount, notes, JSON.stringify(items));
  const quote = db.prepare('SELECT * FROM quotes WHERE id = ?').get(result.lastInsertRowid);
  res.json({ quote });
});

app.get('/api/quotes/:id', auth, adminOnly, (req, res) => {
  const quote = db.prepare('SELECT * FROM quotes WHERE id = ?').get(req.params.id);
  if (!quote) return res.status(404).json({ error: 'Devis introuvable' });
  res.json({ quote });
});

app.patch('/api/quotes/:id/status', auth, adminOnly, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE quotes SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ success: true });
});

// FACTURES
app.get('/api/invoices', auth, adminOnly, (req, res) => {
  const invoices = db.prepare('SELECT * FROM invoices ORDER BY created_at DESC').all();
  res.json({ invoices });
});

app.patch('/api/invoices/:id/pay', auth, adminOnly, (req, res) => {
  db.prepare('UPDATE invoices SET status = ? WHERE id = ?').run('paid', req.params.id);
  res.json({ success: true });
});

// MESSAGES
app.get('/api/messages/contacts', auth, (req, res) => {
  const contacts = db.prepare('SELECT id, email, full_name, role FROM users WHERE id != ?').all(req.user.id);
  res.json({ contacts });
});

app.get('/api/messages/conversation/:userId', auth, (req, res) => {
  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at ASC
  `).all(req.user.id, req.params.userId, req.params.userId, req.user.id);
  res.json({ messages });
});

app.post('/api/messages', auth, (req, res) => {
  const { receiver_id, content } = req.body;
  const result = db.prepare('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)').run(req.user.id, receiver_id, content);
  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(result.lastInsertRowid);
  res.json({ message });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
