const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors({
  origin: ['http://localhost', 'http://localhost:5173', 'capacitor://localhost', 'https://localhost'],
  credentials: true
}));
app.use(express.json());

const SECRET = 'predictiveflow_secret_2026';
const users = [
  { id: 1, email: 'admin@flowpack.fr', password: 'admin123', role: 'admin', full_name: 'Admin Flowpack' }
];

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } });
});

app.get('/api/auth/me', (req, res) => {
  const auth = req.headers.authorization?.split(' ')[1];
  if (!auth) return res.status(401).json({ error: 'Non autorisé' });
  try {
    const decoded = jwt.verify(auth, SECRET);
    res.json({ user: decoded });
  } catch { res.status(401).json({ error: 'Token invalide' }) }
});

app.get('/api/machines', (req, res) => res.json({ machines: [] }));
app.post('/api/machines', (req, res) => res.json({ machine: { id: 1, ...req.body } }));
app.get('/api/alerts', (req, res) => res.json({ alerts: [] }));
app.get('/api/alerts/stats', (req, res) => res.json({ stats: {} }));
app.get('/api/sensors/overview', (req, res) => res.json({ sensors: [] }));
app.get('/api/admin/users', (req, res) => res.json({ users }));
app.post('/api/admin/users', (req, res) => res.json({ user: { id: users.length + 1, ...req.body } }));
app.get('/api/quotes', (req, res) => res.json({ quotes: [] }));
app.get('/api/invoices', (req, res) => res.json({ invoices: [] }));
app.get('/api/projects', (req, res) => res.json({ projects: [] }));
app.get('/api/messages/contacts', (req, res) => res.json({ contacts: [] }));
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
