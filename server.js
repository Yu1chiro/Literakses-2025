require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.raw({ type: 'application/pdf', limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function generateAccessCode() {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
}

const protectAdmin = (req, res, next) => {
    const token = req.cookies.admin_token;
    if (!token) {
        return res.status(401).redirect('/login');
    }
    try {
        const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET);
        if (decoded.role === 'admin') {
            req.admin = decoded;
            next();
        } else {
            throw new Error('Not an admin');
        }
    } catch (error) {
        res.clearCookie('admin_token');
        return res.status(403).redirect('/login');
    }
};

async function setupDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS books (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                title TEXT NOT NULL,
                synopsis TEXT,
                thumbnail_url TEXT,
                file_url TEXT NOT NULL,
                uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS loan_requests (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_name TEXT NOT NULL,
                email TEXT NOT NULL,
                class TEXT,
                book_id UUID REFERENCES books(id) ON DELETE CASCADE,
                duration_days INT DEFAULT 3,
                status TEXT CHECK (status IN ('pending', 'approved', 'rejected', 'renewed', 'expired')) DEFAULT 'pending',
                access_token TEXT,
                access_code TEXT UNIQUE,
                ip_lock TEXT,
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                approved_at TIMESTAMP WITH TIME ZONE,
                renewed_at TIMESTAMP WITH TIME ZONE
            );
        `);
        console.log('Database tables are ready.');
    } catch (err) {
        console.error('Error setting up database:', err);
    } finally {
        client.release();
    }
}

app.post('/api/upload', protectAdmin, async (req, res) => {
    const { title, synopsis, thumbnail_url, filename } = req.query;
    const fileBuffer = req.body;
    if (!title || !filename || !fileBuffer || fileBuffer.length === 0) {
        return res.status(400).json({ error: 'Judul, nama file, dan file wajib diisi' });
    }
    try {
        const uniqueFileName = `${Date.now()}-${filename.replace(/\s/g, '_')}`;
        const bucketName = 'librarry-asset';
        const { error: uploadError } = await supabase.storage
            .from(bucketName)
            .upload(uniqueFileName, fileBuffer, {
                contentType: 'application/pdf',
                cacheControl: '3600',
                upsert: false,
            });
        if (uploadError) throw uploadError;
        const { data: { publicUrl } } = supabase.storage
            .from(bucketName)
            .getPublicUrl(uniqueFileName);
        await pool.query(
            'INSERT INTO books (title, synopsis, thumbnail_url, file_url) VALUES ($1, $2, $3, $4)',
            [title, synopsis, thumbnail_url, publicUrl]
        );
        res.status(201).json({ success: true, message: 'Buku berhasil diunggah' });
    } catch (error) {
        console.error('Error uploading book:', error);
        res.status(500).json({ error: 'Gagal mengunggah buku ke Supabase' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        const token = jwt.sign({ role: 'admin' }, process.env.ADMIN_JWT_SECRET, { expiresIn: '3d' });
        res.cookie('admin_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 3 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, message: 'Login successful' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true, message: 'Logged out' });
});

app.get('/api/books', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, title, synopsis, thumbnail_url, uploaded_at FROM books ORDER BY uploaded_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/my-books', async (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    try {
        const result = await pool.query(`
            SELECT lr.id as loan_id, lr.status, b.title, b.thumbnail_url
            FROM loan_requests lr JOIN books b ON lr.book_id = b.id
            WHERE lr.email = $1 ORDER BY lr.created_at DESC
        `, [email]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching user books:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/loan-request', async (req, res) => {
    const { name, email, className, bookId, duration } = req.body;
    if (!name || !email || !bookId || !duration) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        await pool.query(
            'INSERT INTO loan_requests (user_name, email, class, book_id, duration_days) VALUES ($1, $2, $3, $4, $5)',
            [name, email, className, bookId, parseInt(duration, 10)]
        );
        res.status(201).json({ success: true, message: 'Permintaan peminjaman berhasil dikirim.' });
    } catch (error) {
        console.error('Error creating loan request:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/loan-requests', protectAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT lr.id, lr.user_name, lr.email, lr.status, b.title AS book_title
            FROM loan_requests lr JOIN books b ON lr.book_id = b.id
            ORDER BY lr.created_at DESC
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching loan requests:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/approve-loan/:id', protectAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const loanReqResult = await client.query('SELECT * FROM loan_requests WHERE id = $1', [id]);
        if (loanReqResult.rows.length === 0) return res.status(404).json({ error: 'Loan request not found' });
        
        const loanReq = loanReqResult.rows[0];
        const expiresIn = `${loanReq.duration_days}d`;
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + loanReq.duration_days);

        const bookAccessToken = jwt.sign({ loan_id: loanReq.id, book_id: loanReq.book_id, email: loanReq.email }, process.env.JWT_SECRET, { expiresIn });
        const accessCode = generateAccessCode();

        await client.query(`
            UPDATE loan_requests 
            SET status = 'approved', 
                approved_at = CURRENT_TIMESTAMP, 
                access_token = $1, 
                expires_at = $2,
                access_code = $3
            WHERE id = $4`, 
            [bookAccessToken, expiresAt, accessCode, id]
        );

        const bookResult = await client.query('SELECT title FROM books WHERE id = $1', [loanReq.book_id]);
        const bookTitle = bookResult.rows[0].title;
        
        const mailOptions = {
            from: `"Perpustakaan Digital" <${process.env.EMAIL_USER}>`,
            to: loanReq.email,
            subject: `✓ Peminjaman Buku "${bookTitle}" Telah Disetujui`,
               html: `
                <!DOCTYPE html>
                <html lang="id">
                <head>
                    <meta charset="UTF-8">
                    <title>Peminjaman Disetujui</title>
                </head>
                <body style="margin: 0; padding: 20px; background-color: #f4f7fa; font-family: 'Segoe UI', sans-serif;">
                    <table role="presentation" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                        <tr>
                            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 28px;">Peminjaman Disetujui</h1>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 40px 30px 30px;">
                                <h2 style="margin: 0 0 20px 0; color: #1f2937; font-size: 24px;">Halo ${loanReq.user_name}!</h2>
                                <p style="margin: 0 0 20px 0; color: #4b5563; font-size: 16px; line-height: 1.6;">
                                    Kabar baik! Peminjaman buku <strong>"${bookTitle}"</strong> Anda telah disetujui.
                                </p>
                                <p style="margin: 0 0 25px 0; color: #4b5563; font-size: 16px;">
                                    Silakan salin token akses di bawah ini dan masukkan di halaman <a href="http://${req.get('host')}/listbook" style="color: #667eea;">daftar pinjaman</a> Anda untuk mulai membaca.
                                </p>
                                <div style="background-color: #f0f9ff; border: 2px dashed #93c5fd; padding: 20px; border-radius: 8px; text-align: center; margin: 25px 0;">
                                    <p style="margin: 0 0 10px 0; color: #1e40af; font-size: 14px; font-weight: 600;">TOKEN AKSES BUKU ANDA</p>
                                    <p style="background-color: #dbeafe; color: #1e3a8a; padding: 12px; border-radius: 6px; font-family: 'Courier New', Courier, monospace; font-size: 15px; font-weight: bold; word-break: break-all;">
                                        ${accessCode}
                                    </p>
                                </div>
                                <div style="background-color: #fef3c7; border-radius: 8px; padding: 16px; margin-top: 25px;">
                                    <p style="margin: 0; color: #78350f; font-size: 14px; line-height: 1.5;">
                                        <strong>Penting:</strong> Jangan bagikan token ini kepada siapa pun. Token ini bersifat rahasia dan hanya untuk Anda.
                                    </p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td style="background-color: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="margin: 0; color: #6b7280; font-size: 14px;">© ${new Date().getFullYear()} Perpustakaan Digital</p>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
            `,
        };
        
        await transporter.sendMail(mailOptions);
        await client.query('COMMIT');
        res.json({ success: true, message: 'Loan approved and email sent.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error approving loan:', error);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.post('/api/get-read-token', async (req, res) => {
    const { access_code } = req.body;
    if (!access_code) return res.status(400).json({ error: 'Kode akses wajib diisi.' });

    try {
        const result = await pool.query(
            "SELECT access_token, expires_at FROM loan_requests WHERE access_code = $1 AND status = 'approved'",
            [access_code.toUpperCase()]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Kode akses tidak valid.' });
        }

        const loan = result.rows[0];
        if (new Date(loan.expires_at) < new Date()) {
            return res.status(401).json({ success: false, error: 'Kode akses sudah kedaluwarsa.' });
        }
        
        res.json({ success: true, token: loan.access_token });
    } catch (error) {
        console.error('Error redeeming access code:', error);
        res.status(500).json({ success: false, error: 'Terjadi kesalahan pada server.' });
    }
});

app.get('/api/read-book', async (req, res) => {
    const { token: queryToken } = req.query;
    if (!queryToken) return res.status(401).json({ error: 'Token tidak ditemukan.' });
    try {
        const decoded = jwt.verify(queryToken, process.env.JWT_SECRET);
        const { loan_id } = decoded;
        const loanResult = await pool.query('SELECT * FROM loan_requests WHERE id = $1 AND status = \'approved\'', [loan_id]);
        if (loanResult.rows.length === 0) return res.status(403).json({ error: 'Akses tidak valid.' });
        
        const loan = loanResult.rows[0];
        const bookResult = await pool.query('SELECT title, file_url FROM books WHERE id = $1', [loan.book_id]);
        if (bookResult.rows.length === 0) return res.status(404).json({ error: 'Buku tidak ditemukan.' });
        
        res.json(bookResult.rows[0]);
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
             return res.status(403).json({ error: 'Sesi membaca Anda telah kedaluwarsa.' });
        }
        res.status(403).json({ error: 'Token tidak valid.' });
    }
});

app.get('/dashboard', protectAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/listbook', (req, res) => res.sendFile(path.join(__dirname, 'public', 'listbook.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/read', (req, res) => {
    const { token } = req.query;
    if (token) {
        try {
            const decoded = jwt.decode(token);
            if (decoded && decoded.exp) {
                res.cookie('read_session_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', expires: new Date(decoded.exp * 1000), sameSite: 'Strict' });
            }
        } catch (err) {
            console.error("Gagal decode token:", err.message);
        }
    }
    res.sendFile(path.join(__dirname, 'public', 'read.html'));
});

app.listen(PORT, async () => {
    await setupDatabase();
    console.log(`Server is running on http://localhost:${PORT}`);
});