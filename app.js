require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;

// SQLite connection
const db = new sqlite3.Database('cityplus.db', (err) => {
  if (err) {
    console.error('❌ SQLite connection error:', err.message);
    return;
  }
  console.log('✅ Connected to SQLite');
  // Create complaints table
  db.run(`
    CREATE TABLE IF NOT EXISTS complaints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      location TEXT,
      image_url TEXT,
      status TEXT DEFAULT 'Pending',
      solution TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      submitted_by TEXT NOT NULL
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating complaints table:', err.message);
    } else {
      console.log('✅ Complaints table created or already exists');
    }
  });
  // Create users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      userType TEXT NOT NULL CHECK(userType IN ('resident', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating users table:', err.message);
    } else {
      console.log('✅ Users table created or already exists');
    }
  });
  // Create EventNews table
  db.run(`
    CREATE TABLE IF NOT EXISTS EventNews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      type TEXT NOT NULL,
      date TEXT NOT NULL,
      time TEXT,
      location TEXT,
      image_url TEXT,
      description TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating EventNews table:', err.message);
    } else {
      console.log('✅ EventNews table created or already exists');
    }
  });
  // Create Volunteers table
  db.run(`
    CREATE TABLE IF NOT EXISTS Volunteers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      event_id INTEGER NOT NULL,
      role TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (event_id) REFERENCES EventNews(id)
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating Volunteers table:', err.message);
    } else {
      console.log('✅ Volunteers table created or already exists');
    }
  });
});

// Multer setup with limits
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, path) => {
    if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
  }
}));

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Ensure API routes always return JSON
app.use('/api/*', (req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  next();
});

// Log requests for debugging
app.use('/api/*', (req, res, next) => {
  console.log(`API Request: ${req.method} ${req.url} - Headers:`, req.headers);
  next();
});

// Admin restriction middleware
const restrictToAdmin = (req, res, next) => {
  if (!req.user || req.user.userType !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/complaints', (req, res) => res.sendFile(path.join(__dirname, 'views', 'complaints.html')));
app.get('/submit', (req, res) => res.sendFile(path.join(__dirname, 'views', 'submit.html')));
app.get('/map', (req, res) => res.sendFile(path.join(__dirname, 'views', 'map.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'views', 'contact.html')));
app.get('/thankyou', (req, res) => res.sendFile(path.join(__dirname, 'views', 'thankyou.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'views', 'register.html')));
app.get('/events-news', (req, res) => res.sendFile(path.join(__dirname, 'views', 'events-news.html')));
app.get('/event-details', (req, res) => res.sendFile(path.join(__dirname, 'views', 'event-details.html')));

// API Routes
// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, userType } = req.body;
    if (!email || !password || !userType) {
      return res.status(400).json({ success: false, message: 'Email, password, and user type are required' });
    }
    if (!['resident', 'admin'].includes(userType)) {
      return res.status(400).json({ success: false, message: 'Invalid user type' });
    }

    // Check for existing admin
    if (userType === 'admin') {
      const adminCountQuery = 'SELECT COUNT(*) as count FROM users WHERE userType = ?';
      db.get(adminCountQuery, ['admin'], (err, row) => {
        if (err) throw err;
        if (row.count > 0) {
          return res.status(400).json({ success: false, message: 'Only one admin user is allowed' });
        }
        registerUser();
      });
    } else {
      registerUser();
    }

    async function registerUser() {
      const emailQuery = 'SELECT id FROM users WHERE email = ?';
      db.get(emailQuery, [email], async (err, row) => {
        if (err) throw err;
        if (row) {
          return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO users (email, password, userType) VALUES (?, ?, ?)';
        db.run(insertQuery, [email, hashedPassword, userType], function (err) {
          if (err) throw err;
          res.json({ success: true, message: 'Registration successful' });
        });
      });
    }
  } catch (error) {
    console.error('Error registering user:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, userType } = req.body;
    if (!email || !password || !userType) {
      return res.status(400).json({ success: false, message: 'Email, password, and user type are required' });
    }

    const query = 'SELECT * FROM users WHERE email = ? AND userType = ?';
    db.get(query, [email, userType], async (err, user) => {
      if (err) throw err;
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid email or user type' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Invalid password' });
      }

      const token = jwt.sign(
        { email: user.email, userType: user.userType },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      res.json({ success: true, token, userType });
    });
  } catch (error) {
    console.error('Error logging in:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// User logout
app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// Submit complaint (authenticated users only)
app.post('/api/complaints', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { title, description, address, lat, lng } = req.body || {};

    // Validate required fields
    const trimmedTitle = (title || '').trim();
    const trimmedDescription = (description || '').trim();
    const trimmedAddress = (address || '').trim();
    if (!trimmedTitle || !trimmedDescription || !trimmedAddress) {
      return res.status(400).json({ success: false, message: 'Title, description, and address are required and cannot be empty' });
    }

    // Validate lat and lng if provided
    const parsedLat = lat ? parseFloat(lat.trim()) : null;
    const parsedLng = lng ? parseFloat(lng.trim()) : null;
    if ((lat && isNaN(parsedLat)) || (lng && isNaN(parsedLng))) {
      return res.status(400).json({ success: false, message: 'Latitude and longitude must be valid numbers' });
    }

    // Construct location object
    const location = lat && lng ? JSON.stringify({ address: trimmedAddress, lat: parsedLat, lng: parsedLng }) : JSON.stringify({ address: trimmedAddress });

    // Handle image upload
    let image_url = null;
    if (req.file) {
      image_url = `/uploads/${req.file.filename}`;
      if (!image_url) {
        return res.status(500).json({ success: false, message: 'Failed to process uploaded image filename' });
      }
      console.log('Uploaded image:', req.file.originalname, '->', image_url);
    } else {
      console.log('No image uploaded');
    }

    const submittedBy = req.user?.email;
    if (!submittedBy) {
      return res.status(401).json({ success: false, message: 'User authentication failed' });
    }

    // Insert into database
    const insertQuery = 'INSERT INTO complaints (title, description, location, image_url, status, submitted_by) VALUES (?, ?, ?, ?, ?, ?)';
    db.run(insertQuery, [trimmedTitle, trimmedDescription, location, image_url, 'Pending', submittedBy], function(err) {
      if (err) {
        console.error('Database error:', {
          error: err.stack,
          query: insertQuery,
          params: [trimmedTitle, trimmedDescription, location, image_url, 'Pending', submittedBy]
        });
        return res.status(500).json({ success: false, message: `Database error: ${err.message}. Please try again.` });
      }
      console.log('Complaint submitted successfully, ID:', this.lastID);
      res.json({ success: true, message: 'Complaint submitted successfully' });
    });
  } catch (error) {
    console.error('Error submitting complaint:', {
      error: error.stack,
      body: req.body,
      file: req.file ? req.file.originalname : 'none'
    });
    res.status(500).json({ success: false, message: 'An unexpected server error occurred. Please try again.' });
  }
});

// Get all complaints (authenticated users only)
app.get('/api/complaints', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT * FROM complaints ORDER BY created_at DESC';
    db.all(query, [], (err, rows) => {
      if (err) throw err;
      res.json({ success: true, complaints: rows });
    });
  } catch (error) {
    console.error('Error fetching complaints:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get a single complaint by ID
app.get('/api/complaints/:id', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT * FROM complaints WHERE id = ?';
    db.get(query, [req.params.id], (err, row) => {
      if (err) throw err;
      if (!row) {
        return res.status(404).json({ success: false, message: 'Complaint not found' });
      }
      res.json({ success: true, complaint: row });
    });
  } catch (error) {
    console.error('Error fetching complaint:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get complaints by authenticated user
app.get('/api/my-complaints', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT * FROM complaints WHERE submitted_by = ? ORDER BY created_at DESC';
    db.all(query, [req.user.email], (err, rows) => {
      if (err) throw err;
      res.json({ success: true, complaints: rows });
    });
  } catch (error) {
    console.error('Error fetching user complaints:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get complaints by status
app.get('/api/complaints/status/:status', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT * FROM complaints WHERE status = ? ORDER BY created_at DESC';
    db.all(query, [req.params.status], (err, rows) => {
      if (err) throw err;
      res.json({ success: true, complaints: rows });
    });
  } catch (error) {
    console.error('Error fetching complaints by status:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get user details (authenticated user)
app.get('/api/user', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT id, email, userType, created_at FROM users WHERE email = ?';
    db.get(query, [req.user.email], (err, row) => {
      if (err) throw err;
      if (!row) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      res.json({ success: true, user: row });
    });
  } catch (error) {
    console.error('Error fetching user:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get all users (admin only)
app.get('/api/users', authenticateToken, restrictToAdmin, (req, res) => {
  try {
    const query = 'SELECT id, email, userType, created_at FROM users ORDER BY created_at DESC';
    db.all(query, [], (err, rows) => {
      if (err) throw err;
      res.json({ success: true, users: rows });
    });
  } catch (error) {
    console.error('Error fetching users:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get complaint summary (count by status)
app.get('/api/complaints/summary', authenticateToken, (req, res) => {
  try {
    const query = 'SELECT status, COUNT(*) as count FROM complaints GROUP BY status';
    db.all(query, [], (err, rows) => {
      if (err) throw err;
      res.json({ success: true, summary: rows });
    });
  } catch (error) {
    console.error('Error fetching summary:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Update complaint status and solution (admin only for status)
app.put('/api/complaints/:id', authenticateToken, (req, res) => {
  try {
    const { status, solution } = req.body;
    if (!status && !solution) {
      return res.status(400).json({ success: false, message: 'At least status or solution is required' });
    }

    if (status && req.user.userType !== 'admin') {
      return res.status(403).json({ success: false, message: 'Only admins can update the status' });
    }

    const query = `
      UPDATE complaints
      SET status = COALESCE(?, status), solution = COALESCE(?, solution)
      WHERE id = ?
    `;
    db.run(query, [status, solution, req.params.id], function (err) {
      if (err) {
        console.error('Database error updating complaint:', err.stack);
        throw err;
      }
      if (this.changes === 0) {
        return res.status(404).json({ success: false, message: 'Complaint not found' });
      }
      db.get('SELECT * FROM complaints WHERE id = ?', [req.params.id], (err, row) => {
        if (err) {
          console.error('Error fetching updated complaint:', err.stack);
          throw err;
        }
        res.json({ success: true, complaint: row });
      });
    });
  } catch (error) {
    console.error('Error updating complaint:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get all events (public access)
app.get('/api/events-news', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const query = 'SELECT * FROM EventNews WHERE type = ? ORDER BY date DESC LIMIT ?';
    db.all(query, ['event', limit], (err, rows) => {
      if (err) {
        console.error('Error fetching events:', err.stack);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, items: rows });
    });
  } catch (error) {
    console.error('Error in /api/events-news:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get a single event by ID (public access)
app.get('/api/event/:id', (req, res) => {
  try {
    const query = 'SELECT * FROM EventNews WHERE id = ?';
    db.get(query, [req.params.id], (err, row) => {
      if (err) {
        console.error('Error fetching event:', err.stack);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ success: false, message: 'Event not found' });
      }
      res.json({ success: true, event: row });
    });
  } catch (error) {
    console.error('Error in /api/event/:id:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Add new event (admin only)
app.post('/api/events-news', authenticateToken, restrictToAdmin, upload.single('image'), (req, res) => {
  try {
    console.log('Request Body:', req.body);
    console.log('Uploaded File:', req.file);
    const { title, type, date, time, location, description } = req.body;

    // Validate required fields
    const missingFields = [];
    if (!title) missingFields.push('title');
    if (!type) missingFields.push('type');
    if (!date) missingFields.push('date');
    if (!description) missingFields.push('description');
    if (missingFields.length > 0) {
      console.log('Missing fields:', missingFields);
      return res.status(400).json({ success: false, message: `Title, type, date, and description are required. Missing: ${missingFields.join(', ')}` });
    }

    if (type !== 'event') {
      return res.status(400).json({ success: false, message: 'Type must be "event"' });
    }

    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    if (req.file) {
      console.log('Uploaded image:', req.file.originalname, '->', image_url);
    } else {
      console.log('No image uploaded');
    }

    const query = `
      INSERT INTO EventNews (title, type, date, time, location, image_url, description)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    db.run(query, [title, type, date, time, location, image_url, description], function (err) {
      if (err) {
        console.error('Error adding event:', err.stack);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, id: this.lastID, message: 'Event added successfully' });
    });
  } catch (error) {
    console.error('Error in /api/events-news POST:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Submit volunteer form (authenticated residents only)
app.post('/api/volunteers', authenticateToken, (req, res) => {
  try {
    const { name, email, event_id, role } = req.body;

    // Validate required fields
    if (!name || !email || !event_id) {
      return res.status(400).json({ success: false, message: 'Name, email, and event ID are required' });
    }

    // Verify the event exists
    db.get('SELECT id FROM EventNews WHERE id = ?', [event_id], (err, row) => {
      if (err) {
        console.error('Error checking event:', err.stack);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ success: false, message: 'Event not found' });
      }

      // Restrict to residents
      if (req.user.userType !== 'resident') {
        return res.status(403).json({ success: false, message: 'Only residents can volunteer' });
      }

      // Insert volunteer data
      const query = 'INSERT INTO Volunteers (name, email, event_id, role) VALUES (?, ?, ?, ?)';
      db.run(query, [name, email, event_id, role], function (err) {
        if (err) {
          console.error('Error adding volunteer:', err.stack);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        res.json({ success: true, message: 'Volunteer signup successful' });
      });
    });
  } catch (error) {
    console.error('Error in /api/volunteers POST:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Get all volunteers (admin only)
app.get('/api/volunteers', authenticateToken, restrictToAdmin, (req, res) => {
  try {
    const query = 'SELECT * FROM Volunteers ORDER BY created_at DESC';
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Error fetching volunteers:', err.stack);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, volunteers: rows });
    });
  } catch (error) {
    console.error('Error in /api/volunteers GET:', error.stack);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
});

// Create uploads directory
const dir = './public/uploads';
if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
  console.log('✅ Created public/uploads directory');
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  if (err.message === 'Only image files are allowed!') {
    return res.status(400).json({ success: false, message: err.message });
  }
  res.status(500).json({ success: false, message: 'Something went wrong on the server' });
});

// Uncaught exception handler
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.stack);
  process.exit(1);
});

// Close database connection on app termination
process.on('SIGINT', () => {
  db.close(() => {
    console.log('SQLite database connection closed');
    process.exit(0);
  });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));