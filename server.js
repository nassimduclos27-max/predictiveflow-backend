const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(express.json());

const SECRET = 'predictiveflow_secret_2026';
const users = [
  { id: 1, email: 'admin@flowpack.fr', password: 'admin123', role: 'admin' }
];

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, email: user.email, role: user.role });
});

app.post('/api/auth/register', (req, res) => {
  const { email, password, role } = req.body;
  const exists = users.find(u => u.email === email);
  if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });
  const user = { id: users.length + 1, email, password, role: role || 'client' };
  users.push(user);
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, email: user.email, role: user.role });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
