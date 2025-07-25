const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // ✅ for form data

const db = mysql.createPool({
  host: "crossover.proxy.rlwy.net",
  user: "root",
  password: "QfWUKwdGuSWIubQqaVxByCCEooVfwcKl",
  database: "mp_employees",
  port:16007
});

const SECRET = 'your_secret_key'; // Replace with env var

app.get('/', (req, res) => {
  console.log("i ma in ")
  res.send('API is working ✅');
});

// === Auth Routes ===
app.post('/register', async (req, res) => {
  const { mobile, password, name, district_id, designation_id, email } = req.body;

  if (!mobile || !password || !name || !district_id || !designation_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Check for duplicate mobile number
    const [existingMobile] = await db.execute(
      'SELECT id FROM employees WHERE mobile = ?',
      [mobile]
    );
    if (existingMobile.length > 0) {
      return res.status(409).json({ error: 'Employee with this mobile number already exists' });
    }

    // Check for existing employee with same district and designation
    const [existingCombo] = await db.execute(
      'SELECT id FROM employees WHERE district_id = ? AND designation_id = ?',
      [district_id, designation_id]
    );
    if (existingCombo.length > 0) {
      return res.status(409).json({ error: 'Employee with same district and designation already exists' });
    }

    // Proceed to insert
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      'INSERT INTO employees (mobile, password, name, district_id, designation_id, email) VALUES (?, ?, ?, ?, ?, ?)',
      [mobile, hashedPassword, name, district_id, designation_id, email]
    );

    res.json({ message: 'Registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { mobile, password } = req.body;
  const [rows] = await db.execute('SELECT * FROM employees WHERE mobile = ?', [mobile]);
  if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
  const isMatch = await bcrypt.compare(password, rows[0].password);
  if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, SECRET);
  res.json({ token, role: rows[0].role, name: rows[0].name });
});

app.get('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, SECRET);
    const [rows] = await db.execute(
      `SELECT e.id, e.mobile, e.name, e.email,
              d.name AS district, g.name AS designation
       FROM employees e
       JOIN districts d ON e.district_id = d.id
       JOIN designations g ON e.designation_id = g.id
       WHERE e.id = ?`,
      [decoded.id]
    );
    res.json(rows[0]);
  } catch {
    res.sendStatus(401);
  }
});

app.put('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, SECRET);

    const { name, email, district_id, designation_id, mobile } = req.body;

    // Build fields dynamically
    const fields = [];
    const values = [];

    if (name !== undefined) {
      fields.push('name = ?');
      values.push(name);
    }
    if (email !== undefined) {
      fields.push('email = ?');
      values.push(email);
    }
    if (mobile !== undefined) {
      fields.push('mobile = ?');
      values.push(mobile);
    }
    if (district_id !== undefined) {
      fields.push('district_id = ?');
      values.push(district_id);
    }
    if (designation_id !== undefined) {
      fields.push('designation_id = ?');
      values.push(designation_id);
    }

    // Ensure at least one field to update
    if (fields.length === 0) {
      return res.status(400).json({ message: 'No fields to update' });
    }

    values.push(decoded.id); // for WHERE clause

    const sql = `UPDATE employees SET ${fields.join(', ')} WHERE id = ?`;
    await db.execute(sql, values);

    res.json({ message: 'Profile updated' });
  } catch (err) {
    console.log("err",err)
    res.status(500).json({ error: err.message });
  }
});

// === Admin Route ===
app.get('/admin/employees', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== 'admin') return res.sendStatus(403);

    const { district_id, designation_id } = req.query;

    let query = `
      SELECT e.id, e.name, e.mobile, e.email,
             d.name AS district, g.name AS designation
      FROM employees e
      JOIN districts d ON e.district_id = d.id
      JOIN designations g ON e.designation_id = g.id
      WHERE 1=1
    `;

    const params = [];

    if (district_id) {
      query += ' AND e.district_id = ?';
      params.push(district_id);
    }

    if (designation_id) {
      query += ' AND e.designation_id = ?';
      params.push(designation_id);
    }

    const [rows] = await db.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.sendStatus(401);
  }
});


app.get('/admin/dashboard', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== 'admin') return res.sendStatus(403);

    const [[{ count }]] = await db.execute('SELECT COUNT(*) AS count FROM employees');
    const [districtCounts] = await db.execute(`
      SELECT d.name AS district, COUNT(*) AS count
      FROM employees e
      JOIN districts d ON e.district_id = d.id
      GROUP BY e.district_id
    `);

    const [designationCounts] = await db.execute(`
      SELECT g.name AS designation, COUNT(*) AS count
      FROM employees e
      JOIN designations g ON e.designation_id = g.id
      GROUP BY e.designation_id
    `);
    res.json({
      totalEmployees: count,
      employeesPerDistrict: districtCounts,
      employeesByDesignation: designationCounts
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === Master APIs ===
app.get('/districts', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, name FROM districts');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/designations', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id, name FROM designations');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/admin/employees/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, mobile, district_id, designation_id } = req.body;

  try {
    const fields = ['name = ?', 'email = ?', 'mobile = ?'];
    const values = [name, email, mobile];

    if (district_id !== undefined) {
      fields.push('district_id = ?');
      values.push(district_id);
    }

    if (designation_id !== undefined) {
      fields.push('designation_id = ?');
      values.push(designation_id);
    }

    values.push(id); // For WHERE clause
    const query = `UPDATE employees SET ${fields.join(', ')} WHERE id = ?`;
    await db.execute(query, values);

    res.json({ message: 'Employee updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
