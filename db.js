const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const bcrypt = require('bcryptjs');

const adapter = new FileSync('db.json');
const db = low(adapter);

db.defaults({
  users: [],
  machines: [],
  components: [],
  sensor_data: [],
  alerts: [],
  projects: [],
  project_steps: [],
  interventions: [],
  quotes: [],
  invoices: [],
  messages: []
}).write();

// Créer admin par défaut
const adminExists = db.get('users').find({ email: 'admin@flowpack.fr' }).value();
if (!adminExists) {
  db.get('users').push({
    id: 1,
    email: 'admin@flowpack.fr',
    password: bcrypt.hashSync('admin123', 10),
    full_name: 'Admin Flowpack',
    role: 'admin',
    created_at: new Date().toISOString()
  }).write();
}

module.exports = db;
