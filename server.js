const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { client, initDB } = require('./db');
const { weibullAnalysis } = require('./weibull');

const app = express();
const SECRET = process.env.JWT_SECRET || 'predictiveflow_secret_2026';

app.use(cors({
  origin: ['http://localhost', 'http://localhost:5173', 'capacitor://localhost', 'https://localhost'],
  credentials: true
}));
app.use(express.json());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Trop de tentatives, réessaie dans 15 minutes' } });

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }) }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  next();
};

// AUTH
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await client.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Identifiants incorrects' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } });
  } catch (e) { res.status(500).json({ error: e.message }) }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const result = await client.execute('SELECT id, email, role, full_name FROM users WHERE id = ?', [req.user.id]);
  res.json({ user: result.rows[0] });
});

// MACHINES
app.get('/api/machines', auth, async (req, res) => {
  const result = await client.execute('SELECT * FROM machines ORDER BY created_at DESC');
  res.json({ machines: result.rows });
});

app.post('/api/machines', auth, adminOnly, async (req, res) => {
  const { name, type, location, description } = req.body;
  const result = await client.execute('INSERT INTO machines (name, type, location, description) VALUES (?, ?, ?, ?)', [name, type, location, description]);
  const machine = await client.execute('SELECT * FROM machines WHERE id = ?', [result.lastInsertRowid]);
  res.json({ machine: machine.rows[0] });
});

app.put('/api/machines/:id', auth, adminOnly, async (req, res) => {
  const { name, type, location, description, status } = req.body;
  await client.execute('UPDATE machines SET name=?, type=?, location=?, description=?, status=? WHERE id=?', [name, type, location, description, status, req.params.id]);
  const result = await client.execute('SELECT * FROM machines WHERE id = ?', [req.params.id]);
  res.json({ machine: result.rows[0] });
});

app.delete('/api/machines/:id', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM machines WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// COMPOSANTS
app.get('/api/machines/:id/components', auth, async (req, res) => {
  const result = await client.execute('SELECT * FROM components WHERE machine_id = ?', [req.params.id]);
  res.json({ components: result.rows });
});

app.post('/api/machines/:id/components', auth, adminOnly, async (req, res) => {
  const { name, type, threshold_min, threshold_max, unit } = req.body;
  const result = await client.execute('INSERT INTO components (machine_id, name, type, threshold_min, threshold_max, unit) VALUES (?, ?, ?, ?, ?, ?)', [req.params.id, name, type, threshold_min, threshold_max, unit]);
  const component = await client.execute('SELECT * FROM components WHERE id = ?', [result.lastInsertRowid]);
  res.json({ component: component.rows[0] });
});

app.put('/api/machines/:machineId/components/:componentId', auth, adminOnly, async (req, res) => {
  const { name, type, threshold_min, threshold_max, unit } = req.body;
  await client.execute('UPDATE components SET name=?, type=?, threshold_min=?, threshold_max=?, unit=? WHERE id=?', [name, type, threshold_min, threshold_max, unit, req.params.componentId]);
  const result = await client.execute('SELECT * FROM components WHERE id = ?', [req.params.componentId]);
  res.json({ component: result.rows[0] });
});

app.delete('/api/machines/:machineId/components/:componentId', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM components WHERE id = ?', [req.params.componentId]);
  res.json({ success: true });
});

// CAPTEURS
app.post('/api/sensors/push', auth, async (req, res) => {
  const { component_id, value } = req.body;
  await client.execute('INSERT INTO sensor_data (component_id, value) VALUES (?, ?)', [component_id, value]);
  const compResult = await client.execute('SELECT * FROM components WHERE id = ?', [component_id]);
  const component = compResult.rows[0];
  if (component && (value < component.threshold_min || value > component.threshold_max)) {
    const severity = value > component.threshold_max * 1.2 ? 'critical' : 'warning';
    await client.execute('INSERT INTO alerts (machine_id, component_id, severity, value, unit, threshold_min, threshold_max) VALUES (?, ?, ?, ?, ?, ?, ?)', [component.machine_id, component_id, severity, value, component.unit, component.threshold_min, component.threshold_max]);
    await client.execute('UPDATE machines SET status = ? WHERE id = ?', ['warning', component.machine_id]);
  }
  res.json({ success: true });
});

app.get('/api/sensors/overview', auth, async (req, res) => {
  const result = await client.execute(`SELECT s.value, s.recorded_at, c.name as component_name, c.id as component_id, c.type, c.unit, c.threshold_min, c.threshold_max FROM sensor_data s JOIN components c ON s.component_id = c.id WHERE s.id IN (SELECT MAX(id) FROM sensor_data GROUP BY component_id)`);
  res.json({ sensors: result.rows });
});

// ALERTES
app.get('/api/alerts', auth, async (req, res) => {
  const result = await client.execute(`SELECT a.*, m.name as machine_name, c.name as component_name FROM alerts a LEFT JOIN machines m ON a.machine_id = m.id LEFT JOIN components c ON a.component_id = c.id WHERE a.resolved_at IS NULL ORDER BY a.created_at DESC LIMIT 50`);
  res.json({ alerts: result.rows });
});

app.put('/api/alerts/:id/resolve', auth, async (req, res) => {
  await client.execute('UPDATE alerts SET resolved_at = CURRENT_TIMESTAMP WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ADMIN
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const result = await client.execute('SELECT id, email, full_name, role, created_at FROM users');
  res.json({ users: result.rows });
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { email, password, full_name, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  const result = await client.execute('INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)', [email, hash, full_name, role || 'client']);
  const user = await client.execute('SELECT id, email, full_name, role FROM users WHERE id = ?', [result.lastInsertRowid]);
  res.json({ user: user.rows[0] });
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// PROJETS
app.get('/api/projects', auth, async (req, res) => {
  const projects = await client.execute('SELECT * FROM projects ORDER BY created_at DESC');
  const result = await Promise.all(projects.rows.map(async p => ({
    ...p,
    steps: (await client.execute('SELECT * FROM project_steps WHERE project_id = ?', [p.id])).rows,
    interventions: (await client.execute('SELECT * FROM interventions WHERE project_id = ?', [p.id])).rows
  })));
  res.json({ projects: result });
});

app.post('/api/projects', auth, adminOnly, async (req, res) => {
  const { name, description, start_date, end_date } = req.body;
  const result = await client.execute('INSERT INTO projects (name, description, start_date, end_date) VALUES (?, ?, ?, ?)', [name, description, start_date, end_date]);
  const project = await client.execute('SELECT * FROM projects WHERE id = ?', [result.lastInsertRowid]);
  res.json({ project: project.rows[0] });
});

app.get('/api/projects/:id', auth, async (req, res) => {
  const result = await client.execute('SELECT * FROM projects WHERE id = ?', [req.params.id]);
  const project = result.rows[0];
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  project.steps = (await client.execute('SELECT * FROM project_steps WHERE project_id = ?', [project.id])).rows;
  project.interventions = (await client.execute('SELECT * FROM interventions WHERE project_id = ?', [project.id])).rows;
  res.json({ project });
});

app.delete('/api/projects/:id', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM projects WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/projects/:id/steps', auth, adminOnly, async (req, res) => {
  const result = await client.execute('INSERT INTO project_steps (project_id, title) VALUES (?, ?)', [req.params.id, req.body.title]);
  const step = await client.execute('SELECT * FROM project_steps WHERE id = ?', [result.lastInsertRowid]);
  res.json({ step: step.rows[0] });
});

app.patch('/api/projects/:id/steps/:stepId', auth, async (req, res) => {
  await client.execute('UPDATE project_steps SET status = ? WHERE id = ?', [req.body.status, req.params.stepId]);
  const steps = (await client.execute('SELECT * FROM project_steps WHERE project_id = ?', [req.params.id])).rows;
  const done = steps.filter(s => s.status === 'done').length;
  const progress = steps.length > 0 ? Math.round((done / steps.length) * 100) : 0;
  await client.execute('UPDATE projects SET progress = ? WHERE id = ?', [progress, req.params.id]);
  res.json({ success: true });
});

app.post('/api/projects/:id/interventions', auth, adminOnly, async (req, res) => {
  const { date, description, technician } = req.body;
  const result = await client.execute('INSERT INTO interventions (project_id, date, description, technician) VALUES (?, ?, ?, ?)', [req.params.id, date, description, technician]);
  const intervention = await client.execute('SELECT * FROM interventions WHERE id = ?', [result.lastInsertRowid]);
  res.json({ intervention: intervention.rows[0] });
});

// DEVIS
app.get('/api/quotes', auth, adminOnly, async (req, res) => {
  const result = await client.execute('SELECT * FROM quotes ORDER BY created_at DESC');
  res.json({ quotes: result.rows });
});

app.get('/api/quotes/:id', auth, adminOnly, async (req, res) => {
  const result = await client.execute('SELECT * FROM quotes WHERE id = ?', [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Devis introuvable' });
  res.json({ quote: result.rows[0] });
});

app.post('/api/quotes', auth, adminOnly, async (req, res) => {
  const { client_id, items, discount, notes } = req.body;
  const clientResult = await client.execute('SELECT * FROM users WHERE id = ?', [client_id]);
  const clientUser = clientResult.rows[0];
  const total = items.reduce((s, it) => s + (it.quantity * it.unit_price), 0) * (1 - (discount || 0) / 100);
  const result = await client.execute('INSERT INTO quotes (client_id, client_name, total, discount, notes, items) VALUES (?, ?, ?, ?, ?, ?)', [client_id, clientUser?.full_name || clientUser?.email, total, discount, notes, JSON.stringify(items)]);
  const quote = await client.execute('SELECT * FROM quotes WHERE id = ?', [result.lastInsertRowid]);
  res.json({ quote: quote.rows[0] });
});

app.patch('/api/quotes/:id/status', auth, adminOnly, async (req, res) => {
  await client.execute('UPDATE quotes SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/quotes/:id', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM quotes WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// FACTURES
app.get('/api/invoices', auth, adminOnly, async (req, res) => {
  const result = await client.execute('SELECT * FROM invoices ORDER BY created_at DESC');
  res.json({ invoices: result.rows });
});

app.post('/api/invoices', auth, adminOnly, async (req, res) => {
  const { client_id, items, notes } = req.body;
  const clientResult = await client.execute('SELECT * FROM users WHERE id = ?', [client_id]);
  const clientUser = clientResult.rows[0];
  const total = (items || []).reduce((s, it) => s + (it.quantity * it.unit_price), 0);
  const result = await client.execute('INSERT INTO invoices (client_id, client_name, total, notes, items) VALUES (?, ?, ?, ?, ?)', [client_id, clientUser?.full_name || clientUser?.email, total, notes, JSON.stringify(items)]);
  const invoice = await client.execute('SELECT * FROM invoices WHERE id = ?', [result.lastInsertRowid]);
  res.json({ invoice: invoice.rows[0] });
});

app.patch('/api/invoices/:id/pay', auth, adminOnly, async (req, res) => {
  await client.execute('UPDATE invoices SET status = ? WHERE id = ?', ['paid', req.params.id]);
  res.json({ success: true });
});

app.delete('/api/invoices/:id', auth, adminOnly, async (req, res) => {
  await client.execute('DELETE FROM invoices WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// MESSAGES
app.get('/api/messages/contacts', auth, async (req, res) => {
  const result = await client.execute('SELECT id, email, full_name, role FROM users WHERE id != ?', [req.user.id]);
  res.json({ contacts: result.rows });
});

app.get('/api/messages/conversation/:userId', auth, async (req, res) => {
  const result = await client.execute('SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY created_at ASC', [req.user.id, req.params.userId, req.params.userId, req.user.id]);
  res.json({ messages: result.rows });
});

app.post('/api/messages', auth, async (req, res) => {
  const { receiver_id, content } = req.body;
  const result = await client.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)', [req.user.id, receiver_id, content]);
  const message = await client.execute('SELECT * FROM messages WHERE id = ?', [result.lastInsertRowid]);
  res.json({ message: message.rows[0] });
});

// WEIBULL
app.get('/api/weibull/machine/:machineId', auth, async (req, res) => {
  const machineId = Number(req.params.machineId);
  const components = (await client.execute('SELECT * FROM components WHERE machine_id = ?', [machineId])).rows;
  const results = await Promise.all(components.map(async c => {
    const data = (await client.execute('SELECT * FROM sensor_data WHERE component_id = ? ORDER BY recorded_at ASC', [c.id])).rows;
    if (data.length < 3) return { component_id: c.id, component_name: c.name, error: 'Pas assez de données (minimum 3 mesures)' };
    const values = data.map(d => d.value);
    const timestamps = data.map(d => new Date(d.recorded_at).getTime());
    const result = weibullAnalysis(values, timestamps);
    return { component_id: c.id, component_name: c.name, data_points: data.length, ...result };
  }));
  res.json({ machine_id: machineId, components: results });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;

initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  process.exit(1);
});
