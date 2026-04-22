import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import pkg from 'pg';
import cors from 'cors';
import bcrypt from 'bcryptjs'; // <--- Añadido para seguridad
import crypto from 'crypto'; // Viene con Node
import nodemailer from 'nodemailer';

const { Pool } = pkg;
const PORT = process.env.PORT || 5000; // Usa el del .env o 5000 por defecto


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173'
}));
app.use(express.json({ limit: '50mb' }));
// Crea esta variable al inicio de tu server.js
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://tu-app-en-render.onrender.com' 
  : `http://localhost:${PORT}`;

// Y dentro de la ruta de registro, cambia la URL:

const pool = new Pool({
  user: process.env.USER_POSTGRES,
  host: process.env.HOST_POSTGRES,
  database: process.env.DATABASE_POSTGRES,
  password: process.env.PASSWORD_POSTGRES,
  port: process.env.PORT_POSTGRES,
});

// Test de conexión
pool.query('SELECT NOW()', (err, res) => {
    if (err) console.error("❌ Error de conexión a Postgres:", err.message);
    else console.log("✅ Postgres conectado para Sesiones y Usuarios.");
});

// --- CONFIGURAR TRANSPORTE DE EMAIL ---
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // <--- CAMBIO: Debe ser el host SMTP (ej: smtp.gmail.com)
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465, // true para 465, false para otros
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// --- RUTA DE REGISTRO CON LOGS ---
// --- RUTA DE REGISTRO CORREGIDA ---
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const client = await pool.connect(); // Usamos cliente para la transacción

  try {
    await client.query('BEGIN'); // Iniciamos la transacción

    // 1. Verificar si el usuario ya existe
    const userCheck = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: "Email already registered." });
    }

    // 2. Preparar datos
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // 3. Insertar en la base de datos (is_verified = false por defecto)
    await client.query(
      'INSERT INTO users (username, email, password, verification_token, is_verified) VALUES ($1, $2, $3, $4, $5)',
      [username, email, hashedPassword, verificationToken, false]
    );

    // 4. Enviar el correo bonito
const url = `${API_BASE_URL}/api/auth/verify/${verificationToken}`;
    // En server.js

    
    await transporter.sendMail({
      from: `"Kawatek Bionics" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verifica tu cuenta Kawatek",
      html: `
        <div style="font-family: sans-serif; border: 1px solid #eee; padding: 40px; border-radius: 15px; max-width: 500px; margin: auto;">
          <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #0f172a; margin-top: 0;">Welcome, ${username}!</h2>
          </div>
          <p style="color: #475569; line-height: 1.6;">Thanks for joining the Kawatek rehabilitation platform. You are one step away from starting EMG monitoring and patient management.</p>
          <p style="color: #475569; line-height: 1.6;">To activate your account, click the button below :</p>
          <div style="text-align: center; margin-top: 30px; margin-bottom: 30px;">
            <a href="${url}" style="background-color: #6d28d9; color: white; padding: 14px 30px; text-decoration: none; border-radius: 10px; font-weight: bold; display: inline-block; box-shadow: 0 4px 6px rgba(109, 40, 217, 0.2);">VERIFY YOUR ACCOUNT</a>
          </div>
          <p style="font-size: 12px; color: #94a3b8; text-align: center;">If the button doesn't work, copy this link into your browser:<br/> 
          <span style="color: #6d28d9;">${url}</span></p>
          <hr style="border: 0; border-top: 1px solid #f1f5f9; margin-top: 30px;"/>
          <p style="font-size: 11px; color: #cbd5e1; text-align: center;">Rehabilitation software - Kawatek 2026</p>
        </div>
      `
    });

    // 5. Si el correo se envió, confirmamos los cambios en la DB
    await client.query('COMMIT');
    console.log(`📧 Registro exitoso y correo enviado a: ${email}`);
    res.status(201).json({ success: true, message: "Check your email to verify your account." });

  } catch (err) {
    // 6. Si algo falló (DB o Correo), deshacemos todo
    await client.query('ROLLBACK');
    console.error("❌ Error en el proceso de registro:", err);
    res.status(500).json({ success: false, message: "The registration failed. Please try again." });
  } finally {
    client.release(); // Liberamos la conexión al pool
  }
});
// --- NUEVA RUTA: VERIFICAR EMAIL ---
// En server.js
app.get('/api/auth/verify/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query(
      'UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = $1 RETURNING *', 
      [token]
    );
    
    if (result.rowCount === 0) return res.status(400).send("Token inválido o expirado.");
    
    // CAMBIO AQUÍ: Redirigir a la nueva pantalla de éxito, no al login directamente
    res.redirect('http://localhost:5173/verify-success'); 

  } catch (err) {
    console.error("Error al verificar:", err);
    res.status(500).send("Error al verificar la cuenta.");
  }
});

// --- MODIFICAR LOGIN PARA BLOQUEAR NO VERIFICADOS ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) return res.status(404).json({ success: false, message: "Usuario no encontrado." });
    
    // VALIDACIÓN: ¿Está verificado?
    if (!user.is_verified) {
      return res.status(401).json({ success: false, message: "Por favor, verifica tu email primero." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Contraseña incorrecta." });

    res.json({ success: true, message: "Bienvenido de nuevo.", user: { id: user.id, username: user.username } });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error." });
  }
});

// Crear nuevo paciente
// --- RUTAS DE PACIENTES ---

// 1. Crear un nuevo paciente vinculado al doctor logueado
app.post('/api/patients', async (req, res) => {
  const { name, id_number, age, affected_side, condition, doctor_id } = req.body;

  // Validación de campos obligatorios
  if (!name || !id_number || !age || !doctor_id) {
    return res.status(400).json({ 
      success: false, 
      message: "Faltan campos obligatorios para el registro médico." 
    });
  }

  // Validación de tipos de datos
  if (isNaN(age)) {
    return res.status(400).json({ 
      success: false, 
      message: "La edad debe ser un valor numérico." 
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO patients (name, id_number, age, affected_side, condition, doctor_id) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, id_number, age, affected_side, condition, doctor_id]
    );

    res.status(201).json({ 
      success: true, 
      patient: result.rows[0] 
    });
  } catch (err) {
    // Manejo de error si la cédula/ID ya existe (Unique Constraint)
    if (err.code === '23505') {
      return res.status(400).json({ 
        success: false, 
        message: "Ya existe un paciente registrado con ese ID." 
      });
    }
    console.error(err);
    res.status(500).json({ success: false, message: "Error interno del servidor." });
  }
});
// 2. Obtener todos los pacientes de un doctor específico
app.get('/api/patients/doctor/:doctor_id', async (req, res) => {
    const { doctor_id } = req.params;
    try {
        const result = await pool.query(
            'SELECT * FROM patients WHERE doctor_id = $1 ORDER BY created_at DESC', 
            [doctor_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Error al obtener lista de pacientes." });
    }
});

// 3. Obtener datos de un solo paciente (para cargar en el juego EMG)
app.get('/api/patients/:id', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM patients WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).send("Paciente no encontrado.");
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).send("Error de servidor.");
    }
});

// AGREGA ESTO EN server.js
app.delete('/api/patients/:id', async (req, res) => {
  try {
    const { id } = req.params;
   
    const result = await pool.query('DELETE FROM patients WHERE id = $1', [id]);

    if (result.rowCount > 0 || result > 0) {
      res.json({ success: true, message: "Paciente eliminado correctamente" });
    } else {
      res.status(404).json({ success: false, message: "Paciente no encontrado" });
    }
  } catch (error) {
    console.error("Error al eliminar:", error);
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});
// --- TU RUTA EXISTENTE DE SESIONES ---
app.post('/api/save-session', async (req, res) => {
  const { patient_id, mode, score, samples, metrics } = req.body; 
  console.log("📥 Datos recibidos en el servidor:", { patient_id, mode, score, samplesCount: samples?.length });

  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');

    // 1. Insertar la cabecera de la sesión
    const sessionQuery = `
      INSERT INTO emg_sessions 
      (game_mode, score, selectivity_index, coactivation_ratio, fatigue_trend, control_efficiency, patient_id) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`;
    
    console.log("📝 Intentando insertar sesión...");
    const sessionRes = await client.query(sessionQuery, [
      mode, score, metrics.si, metrics.cr, metrics.fatigue, metrics.ce, patient_id
    ]);
    
    const sessionId = sessionRes.rows[0].id;
    console.log(`🆔 Sesión creada con ID: ${sessionId}`);

    // 2. Insertar los samples con tus nombres de columna: val_a y val_b
    if (samples && samples.length > 0) {
      console.log(`📊 Insertando ${samples.length} muestras...`);
      const sampleValues = [];
      const placeholders = [];
      
      samples.forEach((sample, index) => {
        const offset = index * 4;
        sampleValues.push(sessionId, sample.t, sample.a, sample.b);
        placeholders.push(`($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4})`);
      });

      const insertSamplesQuery = `
        INSERT INTO emg_samples (session_id, timestamp, val_a, val_b) 
        VALUES ${placeholders.join(', ')}`;
      
      await client.query(insertSamplesQuery, sampleValues);
    }

    await client.query('COMMIT');
    console.log(`✅ TODO GUARDADO: Sesión ${sessionId}`);
    res.json({ success: true, sessionId });

  } catch (err) {
    if (client) await client.query('ROLLBACK');
    console.error('❌ ERROR FATAL EN BD:', err.message); // Mira tu consola de Node para ver este error
    res.status(500).json({ error: err.message, stack: err.stack });
  } finally {
    if (client) client.release();
  }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor Kawatek activo en puerto ${PORT}`));