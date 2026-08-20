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

const nextId = (collection) => {
  const items = db.get(collection).value();
  return items.length > 0 ? Math.max(...items.map(i => i.id)) + 1 : 1;
};

// AUTH
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email }).value();
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  res.json({ user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } });
});

// MACHINES
app.get('/api/machines', auth, (req, res) => {
  const machines = db.get('machines').value();
  res.json({ machines });
});

app.post('/api/machines', auth, adminOnly, (req, res) => {
  const machine = { id: nextId('machines'), ...req.body, status: 'ok', created_at: new Date().toISOString() };
  db.get('machines').push(machine).write();
  res.json({ machine });
});

app.put('/api/machines/:id', auth, adminOnly, (req, res) => {
  db.get('machines').find({ id: Number(req.params.id) }).assign(req.body).write();
  const machine = db.get('machines').find({ id: Number(req.params.id) }).value();
  res.json({ machine });
});

app.delete('/api/machines/:id', auth, adminOnly, (req, res) => {
  db.get('machines').remove({ id: Number(req.params.id) }).write();
  res.json({ success: true });
});

// COMPOSANTS
app.get('/api/machines/:id/components', auth, (req, res) => {
  const components = db.get('components').filter({ machine_id: Number(req.params.id) }).value();
  res.json({ components });
});

app.post('/api/machines/:id/components', auth, adminOnly, (req, res) => {
  const component = { id: nextId('components'), machine_id: Number(req.params.id), ...req.body };
  db.get('components').push(component).write();
  res.json({ component });
});

// CAPTEURS
app.post('/api/sensors/push', auth, (req, res) => {
  const { component_id, value } = req.body;
  const data = { id: nextId('sensor_data'), component_id, value, recorded_at: new Date().toISOString() };
  db.get('sensor_data').push(data).write();
  const component = db.get('components').find({ id: component_id }).value();
  if (component && (value < component.threshold_min || value > component.threshold_max)) {
    const alert = { id: nextId('alerts'), machine_id: component.machine_id, component_id, severity: value > component.threshold_max * 1.2 ? 'critical' : 'warning', value, unit: component.unit, threshold_min: component.threshold_min, threshold_max: component.threshold_max, resolved_at: null, created_at: new Date().toISOString() };
    db.get('alerts').push(alert).write();
    db.get('machines').find({ id: component.machine_id }).assign({ status: 'warning' }).write();
  }
  res.json({ success: true });
});

app.get('/api/sensors/overview', auth, (req, res) => {
  const components = db.get('components').value();
  const sensors = components.map(c => {
    const latest = db.get('sensor_data').filter({ component_id: c.id }).sortBy('recorded_at').last().value();
    return latest ? { ...latest, component_name: c.name, type: c.type, unit: c.unit, threshold_min: c.threshold_min, threshold_max: c.threshold_max } : null;
  }).filter(Boolean);
  res.json({ sensors });
});

// ALERTES
app.get('/api/alerts', auth, (req, res) => {
  const machines = db.get('machines').value();
  const components = db.get('components').value();
  const alerts = db.get('alerts').filter({ resolved_at: null }).value().map(a => ({
    ...a,
    machine_name: machines.find(m => m.id === a.machine_id)?.name,
    component_name: components.find(c => c.id === a.component_id)?.name
  }));
  res.json({ alerts });
});

app.put('/api/alerts/:id/resolve', auth, (req, res) => {
  db.get('alerts').find({ id: Number(req.params.id) }).assign({ resolved_at: new Date().toISOString() }).write();
  res.json({ success: true });
});

// ADMIN
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.get('users').value().map(u => ({ id: u.id, email: u.email, full_name: u.full_name, role: u.role, created_at: u.created_at }));
  res.json({ users });
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { email, password, full_name, role } = req.body;
  const user = { id: nextId('users'), email, password: bcrypt.hashSync(password, 10), full_name, role: role || 'client', created_at: new Date().toISOString() };
  db.get('users').push(user).write();
  res.json({ user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role } });
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  db.get('users').remove({ id: Number(req.params.id) }).write();
  res.json({ success: true });
});

// PROJETS
app.get('/api/projects', auth, (req, res) => {
  const projects = db.get('projects').value().map(p => ({
    ...p,
    steps: db.get('project_steps').filter({ project_id: p.id }).value(),
    interventions: db.get('interventions').filter({ project_id: p.id }).value()
  }));
  res.json({ projects });
});

app.post('/api/projects', auth, adminOnly, (req, res) => {
  const project = { id: nextId('projects'), ...req.body, status: 'planned', progress: 0, created_at: new Date().toISOString() };
  db.get('projects').push(project).write();
  res.json({ project });
});

app.get('/api/projects/:id', auth, (req, res) => {
  const project = db.get('projects').find({ id: Number(req.params.id) }).value();
  if (!project) return res.status(404).json({ error: 'Projet introuvable' });
  project.steps = db.get('project_steps').filter({ project_id: project.id }).value();
  project.interventions = db.get('interventions').filter({ project_id: project.id }).value();
  res.json({ project });
});

app.post('/api/projects/:id/steps', auth, adminOnly, (req, res) => {
  const step = { id: nextId('project_steps'), project_id: Number(req.params.id), title: req.body.title, status: 'todo' };
  db.get('project_steps').push(step).write();
  res.json({ step });
});

app.patch('/api/projects/:id/steps/:stepId', auth, (req, res) => {
  db.get('project_steps').find({ id: Number(req.params.stepId) }).assign({ status: req.body.status }).write();
  const steps = db.get('project_steps').filter({ project_id: Number(req.params.id) }).value();
  const done = steps.filter(s => s.status === 'done').length;
  const progress = steps.length > 0 ? Math.round((done / steps.length) * 100) : 0;
  db.get('projects').find({ id: Number(req.params.id) }).assign({ progress }).write();
  res.json({ success: true });
});

app.post('/api/projects/:id/interventions', auth, adminOnly, (req, res) => {
  const intervention = { id: nextId('interventions'), project_id: Number(req.params.id), ...req.body, created_at: new Date().toISOString() };
  db.get('interventions').push(intervention).write();
  res.json({ intervention });
});

// DEVIS
app.get('/api/quotes', auth, adminOnly, (req, res) => {
  res.json({ quotes: db.get('quotes').value() });
});

app.get('/api/quotes/:id', auth, adminOnly, (req, res) => {
  const quote = db.get('quotes').find({ id: Number(req.params.id) }).value();
  if (!quote) return res.status(404).json({ error: 'Devis introuvable' });
  res.json({ quote });
});

app.post('/api/quotes', auth, adminOnly, (req, res) => {
  const { client_id, items, discount, notes } = req.body;
  const client = db.get('users').find({ id: Number(client_id) }).value();
  const total = items.reduce((s, it) => s + (it.quantity * it.unit_price), 0) * (1 - (discount || 0) / 100);
  const quote = { id: nextId('quotes'), client_id, client_name: client?.full_name || client?.email, total, discount, notes, items, status: 'draft', created_at: new Date().toISOString() };
  db.get('quotes').push(quote).write();
  res.json({ quote });
});

app.patch('/api/quotes/:id/status', auth, adminOnly, (req, res) => {
  db.get('quotes').find({ id: Number(req.params.id) }).assign({ status: req.body.status }).write();
  res.json({ success: true });
});

// FACTURES
app.get('/api/invoices', auth, adminOnly, (req, res) => {
  res.json({ invoices: db.get('invoices').value() });
});

app.patch('/api/invoices/:id/pay', auth, adminOnly, (req, res) => {
  db.get('invoices').find({ id: Number(req.params.id) }).assign({ status: 'paid' }).write();
  res.json({ success: true });
});

// MESSAGES
app.get('/api/messages/contacts', auth, (req, res) => {
  const contacts = db.get('users').value().filter(u => u.id !== req.user.id).map(u => ({ id: u.id, email: u.email, full_name: u.full_name, role: u.role }));
  res.json({ contacts });
});

app.get('/api/messages/conversation/:userId', auth, (req, res) => {
  const messages = db.get('messages').value().filter(m =>
    (m.sender_id === req.user.id && m.receiver_id === Number(req.params.userId)) ||
    (m.sender_id === Number(req.params.userId) && m.receiver_id === req.user.id)
  );
  res.json({ messages });
});

app.post('/api/messages', auth, (req, res) => {
  const message = { id: nextId('messages'), sender_id: req.user.id, receiver_id: req.body.receiver_id, content: req.body.content, created_at: new Date().toISOString() };
  db.get('messages').push(message).write();
  res.json({ message });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// COMPOSANTS - modifier et supprimer
app.put('/api/machines/:machineId/components/:componentId', auth, adminOnly, (req, res) => {
  db.get('components').find({ id: Number(req.params.componentId) }).assign(req.body).write();
  const component = db.get('components').find({ id: Number(req.params.componentId) }).value();
  res.json({ component });
});

app.delete('/api/machines/:machineId/components/:componentId', auth, adminOnly, (req, res) => {
  db.get('components').remove({ id: Number(req.params.componentId) }).write();
  res.json({ success: true });
});

// FACTURES - créer et modifier
app.post('/api/invoices', auth, adminOnly, (req, res) => {
  const { client_id, items, notes } = req.body;
  const client = db.get('users').find({ id: Number(client_id) }).value();
  const total = (items || []).reduce((s, it) => s + (it.quantity * it.unit_price), 0);
  const invoice = { id: nextId('invoices'), client_id, client_name: client?.full_name || client?.email, total, notes, items, status: 'pending', created_at: new Date().toISOString() };
  db.get('invoices').push(invoice).write();
  res.json({ invoice });
});

app.put('/api/invoices/:id', auth, adminOnly, (req, res) => {
  db.get('invoices').find({ id: Number(req.params.id) }).assign(req.body).write();
  const invoice = db.get('invoices').find({ id: Number(req.params.id) }).value();
  res.json({ invoice });
});

app.delete('/api/invoices/:id', auth, adminOnly, (req, res) => {
  db.get('invoices').remove({ id: Number(req.params.id) }).write();
  res.json({ success: true });
});

// WEIBULL
const { weibullAnalysis } = require('./weibull');

app.get('/api/weibull/:componentId', auth, (req, res) => {
  const componentId = Number(req.params.componentId)
  const component = db.get('components').find({ id: componentId }).value()
  if (!component) return res.status(404).json({ error: 'Composant introuvable' })

  const data = db.get('sensor_data').filter({ component_id: componentId }).sortBy('recorded_at').value()
  if (data.length < 3) return res.status(400).json({ error: 'Pas assez de données (minimum 3 mesures)' })

  const values = data.map(d => d.value)
  const timestamps = data.map(d => new Date(d.recorded_at).getTime())
  const result = weibullAnalysis(values, timestamps)

  if (!result) return res.status(400).json({ error: 'Calcul impossible' })

  res.json({
    component_name: component.name,
    component_id: componentId,
    data_points: data.length,
    ...result
  })
})

app.get('/api/weibull/machine/:machineId', auth, (req, res) => {
  const machineId = Number(req.params.machineId)
  const components = db.get('components').filter({ machine_id: machineId }).value()

  const results = components.map(c => {
    const data = db.get('sensor_data').filter({ component_id: c.id }).sortBy('recorded_at').value()
    if (data.length < 3) return { component_id: c.id, component_name: c.name, error: 'Pas assez de données' }
    const values = data.map(d => d.value)
    const timestamps = data.map(d => new Date(d.recorded_at).getTime())
    const result = weibullAnalysis(values, timestamps)
    return { component_id: c.id, component_name: c.name, data_points: data.length, ...result }
  })

  res.json({ machine_id: machineId, components: results })
})
