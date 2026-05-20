// Importa dotenv para cargar variables de entorno desde un archivo .env.
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import pkg from 'pg';
import cors from 'cors';
import bcrypt from 'bcryptjs'; // <--- Añadido para seguridad
import crypto from 'crypto'; // Viene con Node
import nodemailer from 'nodemailer';
import dns from 'dns';

dns.setDefaultResultOrder('ipv4first');
const { Pool } = pkg;
const PORT = process.env.PORT || 5000; // Usa el del .env o 5000 por defecto
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Carga las variables de entorno desde el archivo .env ubicado en ../backk/.env.
dotenv.config({ path: path.resolve(__dirname, '../backk/.env') }); // Asegura que cargue el .env correcto

const app = express();
const allowedOrigins = [
  // Dominio del frontend desplegado en Netlify.
  'https://flexfly.netlify.app',

  // Entorno local de Vite.
  'http://localhost:5173', // Tu entorno local de Vite

  // Otro puerto local permitido por si el frontend corre en 3000.
  'http://localhost:3000'  // Por si acaso usas otros puertos
];

// Aplica middleware de CORS con configuración personalizada.
app.use(cors({
  // Función que decide si un origen está permitido o no.
  origin: function (origin, callback) {
    // permitir peticiones sin origen (como Postman o apps móviles)
    // Si la petición no tiene origin, se permite.
    if (!origin) return callback(null, true);
    
    // Si el origen no está en la lista de permitidos, se rechaza.
    if (allowedOrigins.indexOf(origin) === -1) {
      // Mensaje de error para orígenes no permitidos.
      const msg = 'El policy de CORS para este sitio no permite acceso desde el origen especificado.';

      // Devuelve error y bloquea la petición.
      return callback(new Error(msg), false);
    }

    // Si el origen está permitido, continúa normalmente.
    return callback(null, true);
  },

  // Permite enviar credenciales como cookies o headers de autenticación.
  credentials: true
}));

// Permite que Express lea cuerpos JSON grandes, hasta 50 MB.
app.use(express.json({ limit: '50mb' }));

const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://flex-fly-back.onrender.com'
  : `http://localhost:${PORT}`;

// Crea el pool de conexiones a PostgreSQL usando variables de entorno.
const pool = new Pool({
  // Usuario de PostgreSQL.
  user: process.env.USER_POSTGRES,

  // Host del servidor PostgreSQL.
  host: process.env.HOST_POSTGRES,

  // Nombre de la base de datos.
  database: process.env.DATABASE_POSTGRES,

  // Contraseña de PostgreSQL.
  password: process.env.PASSWORD_POSTGRES,

  // Puerto de PostgreSQL.
  port: process.env.PORT_POSTGRES,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false

});


// Ejecuta una consulta simple para verificar que PostgreSQL responde.
pool.query('SELECT NOW()', (err, res) => {
    // Si hay error, lo muestra en consola.
    if (err) console.error("❌ Error de conexión a Postgres:", err.message);

    // Si no hay error, confirma la conexión.
    else console.log("✅ Postgres conectado para Sesiones y Usuarios.");
});

// --- CONFIGURAR TRANSPORTE DE EMAIL ---
// Configura el transporte SMTP para poder enviar correos.
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  requireTLS: true,
  family: 4,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  logger: true,
  debug: true,
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000
});

// --- RUTA DE REGISTRO CON LOGS ---
// --- RUTA DE REGISTRO CORREGIDA ---
// Ruta POST para registrar un usuario nuevo.
// --- RUTA DE REGISTRO DE DOCTORES CON APROBACIÓN ADMIN ---
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const client = await pool.connect();

  if (!username || !email || !password) {
    client.release();

    return res.status(400).json({
      success: false,
      message: "Username, email and password are required."
    });
  }

  try {
    await client.query('BEGIN');

    const userCheck = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (userCheck.rows.length > 0) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        message: "Email already registered."
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // This token is not for the doctor.
    // It is for the administrator approval link.
    const approvalToken = crypto.randomBytes(32).toString('hex');

    const result = await client.query(
      `INSERT INTO users 
       (username, email, password, verification_token, is_verified) 
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, email, is_verified`,
      [username, email, hashedPassword, approvalToken, false]
    );

    const approveUrl = `${API_BASE_URL}/api/auth/approve-doctor/${approvalToken}`;

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: "Doctor account created. It is pending administrator approval.",
      user: result.rows[0]
    });

    transporter.verify()
      .then(() => {
        console.log("✅ SMTP ready for doctor admin approval");

        return transporter.sendMail({
          from: `"Kawatek Bionics" <${process.env.EMAIL_USER}>`,
          to: process.env.ADMIN_APPROVAL_EMAIL,
          subject: "New doctor account pending approval",
          html: `
            <!DOCTYPE html>
            <html>
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
              </head>

              <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif;">
                <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f7fb; padding:40px 0;">
                  <tr>
                    <td align="center">

                      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:14px; overflow:hidden; border:1px solid #e5e7eb;">
                        
                        <tr>
                          <td align="center" style="padding:40px 40px 20px 40px;">
                            <h1 style="margin:0; color:#0f172a; font-size:26px; font-weight:800;">
                              New doctor approval request
                            </h1>
                          </td>
                        </tr>

                        <tr>
                          <td style="padding:10px 40px 0 40px; color:#334155; font-size:16px; line-height:1.6;">
                            <p style="margin:0 0 18px 0;">
                              A new doctor has registered on the Kawatek rehabilitation platform and is waiting for administrator approval.
                            </p>

                            <p style="margin:0 0 10px 0;">
                              <strong style="color:#0f172a;">Doctor name:</strong> ${username}
                            </p>

                            <p style="margin:0 0 18px 0;">
                              <strong style="color:#0f172a;">Doctor email:</strong> ${email}
                            </p>

                            <p style="margin:0;">
                              To approve this doctor account, click the button below:
                            </p>
                          </td>
                        </tr>

                        <tr>
                          <td align="center" style="padding:35px 40px 25px 40px;">
                            <a href="${approveUrl}"
                               style="display:inline-block; background:#6d28d9; color:#ffffff; text-decoration:none; font-size:15px; font-weight:700; padding:16px 34px; border-radius:10px; letter-spacing:0.4px;">
                              APPROVE DOCTOR
                            </a>
                          </td>
                        </tr>

                        <tr>
                          <td align="center" style="padding:0 40px 35px 40px; color:#94a3b8; font-size:13px; line-height:1.5;">
                            <p style="margin:0 0 8px 0;">
                              If the button doesn't work, copy this link into your browser:
                            </p>

                            <a href="${approveUrl}" style="color:#2563eb; word-break:break-all;">
                              ${approveUrl}
                            </a>
                          </td>
                        </tr>

                        <tr>
                          <td style="padding:0 40px;">
                            <hr style="border:none; border-top:1px solid #e5e7eb; margin:0;" />
                          </td>
                        </tr>

                        <tr>
                          <td align="center" style="padding:22px 40px 30px 40px; color:#cbd5e1; font-size:12px;">
                            Rehabilitation software - Kawatek 2026
                          </td>
                        </tr>

                      </table>

                    </td>
                  </tr>
                </table>
              </body>
            </html>
          `
        });
      })
      .then((info) => {
        console.log("✅ Doctor approval email sent to admin");
        console.log("MESSAGE ID:", info.messageId);
        console.log("ACCEPTED:", info.accepted);
        console.log("REJECTED:", info.rejected);
        console.log("RESPONSE:", info.response);
      })
      .catch((mailError) => {
        console.error("❌ DOCTOR ADMIN APPROVAL SMTP ERROR:", mailError.message);
        console.error("❌ SMTP ERROR CODE:", mailError.code);
        console.error("❌ SMTP ERROR COMMAND:", mailError.command);
        console.error("❌ SMTP ERROR RESPONSE:", mailError.response);
        console.error("❌ SMTP FULL ERROR:", mailError);
      });

  } catch (err) {
    await client.query('ROLLBACK');

    console.error("❌ Error en el registro de doctor:", err);

    res.status(500).json({
      success: false,
      message: "The doctor registration failed. Please try again."
    });

  } finally {
    client.release();
  }
});

// --- RUTA: APROBAR DOCTOR POR ADMIN ---
app.get('/api/auth/approve-doctor/:token', async (req, res) => {
  const { token } = req.params;

  const FRONTEND_URL = process.env.NODE_ENV === 'production'
    ? 'https://flexfly.netlify.app'
    : 'http://localhost:5173';

  try {
    const result = await pool.query(
      `UPDATE users 
       SET is_verified = true, verification_token = NULL 
       WHERE verification_token = $1 
       RETURNING id, username, email`,
      [token]
    );

    if (result.rowCount === 0) {
      return res.status(400).send("Invalid or expired doctor approval token.");
    }

    res.redirect(`${FRONTEND_URL}/verify-success`);

  } catch (err) {
    console.error("❌ Error approving doctor:", err);
    res.status(500).send("Error approving doctor account.");
  }
});

// --- NUEVA RUTA: VERIFICAR EMAIL ---
// En server.js
// Ruta GET que verifica la cuenta usando el token recibido por email.
app.get('/api/auth/verify/:token', async (req, res) => {
  // Extrae el token desde la URL.
  const { token } = req.params;

  // Define la URL del frontend según entorno.
  const FRONTEND_URL = process.env.NODE_ENV === 'production'
  // En producción redirige al frontend de Netlify.
  ? 'https://flexfly.netlify.app'
  // En local redirige al frontend local de Vite.
  : 'http://localhost:5173';


  try {
    // Busca un usuario con ese verification_token y lo marca como verificado.
    const result = await pool.query(
      'UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = $1 RETURNING *', 
      [token]
    );
    
    // Si no encontró usuario/token, responde token inválido o expirado.
    if (result.rowCount === 0) return res.status(400).send("Token inválido o expirado.");
    
    // CAMBIO AQUÍ: Redirigir a la nueva pantalla de éxito, no al login directamente
    // Redirige al frontend a una pantalla de verificación exitosa.
  res.redirect(`${FRONTEND_URL}/verify-success`);

  } catch (err) {
    // Muestra error en consola si falla la verificación.
    console.error("Error al verificar:", err);

    // Responde error 500 si hubo problema interno.
    res.status(500).send("Error al verificar la cuenta.");
  }
});

// --- MODIFICAR LOGIN PARA BLOQUEAR NO VERIFICADOS ---
// Ruta POST para iniciar sesión.
app.post('/api/auth/login', async (req, res) => {
  // Extrae email y password enviados desde el frontend.
  const { email, password } = req.body;

  try {
    // Busca el usuario por email.
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    // Toma el primer usuario encontrado.
    const user = result.rows[0];

    // Si no existe usuario, responde 404.
    if (!user) return res.status(404).json({ success: false, message: "Usuario no encontrado." });
    
    // VALIDACIÓN: ¿Está verificado?
    // Si el usuario no verificó su email, bloquea el login.
   if (!user.is_verified) {
  return res.status(401).json({
    success: false,
    message: "Your doctor account is pending administrator approval."
  });
}

    // Compara la contraseña enviada con el hash guardado en base de datos.
    const isMatch = await bcrypt.compare(password, user.password);

    // Si la contraseña no coincide, responde error.
    if (!isMatch) return res.status(400).json({ success: false, message: "Contraseña incorrecta." });

    // Si todo está bien, responde éxito y devuelve datos básicos del usuario.
    res.json({ success: true, message: "Bienvenido de nuevo.", user: { id: user.id, username: user.username } });
  } catch (err) {
    // Si ocurre un error inesperado, responde error genérico.
    res.status(500).json({ success: false, message: "Error." });
  }
});

// Crear nuevo paciente
// --- RUTAS DE PACIENTES ---

// 1. Crear un nuevo paciente vinculado al doctor logueado
// Ruta POST para crear un paciente nuevo.
app.post('/api/patients', async (req, res) => {
  // Extrae los datos del paciente enviados desde el frontend.
  const { name, id_number, age, affected_side, condition, doctor_id } = req.body;

  // Validación de campos obligatorios
  // Si falta nombre, identificación, edad o doctor_id, no permite crear el paciente.
  if (!name || !id_number || !age || !doctor_id) {
    return res.status(400).json({ 
      success: false, 
      message: "Faltan campos obligatorios para el registro médico." 
    });
  }

  // Validación de tipos de datos
  // Verifica que age sea un número.
  if (isNaN(age)) {
    return res.status(400).json({ 
      success: false, 
      message: "La edad debe ser un valor numérico." 
    });
  }

  try {
    // Inserta el paciente en la base de datos y devuelve el registro creado.
    const result = await pool.query(
      `INSERT INTO patients (name, id_number, age, affected_side, condition, doctor_id) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, id_number, age, affected_side, condition, doctor_id]
    );

    // Responde éxito con el paciente creado.
    res.status(201).json({ 
      success: true, 
      patient: result.rows[0] 
    });
  } catch (err) {
    // Manejo de error si la cédula/ID ya existe (Unique Constraint)
    // Código 23505 en PostgreSQL significa violación de clave única.
    if (err.code === '23505') {
      return res.status(400).json({ 
        success: false, 
        message: "Ya existe un paciente registrado con ese ID." 
      });
    }

    // Muestra otros errores en consola.
    console.error(err);

    // Responde error interno.
    res.status(500).json({ success: false, message: "Error interno del servidor." });
  }
});

// 2. Obtener todos los pacientes de un doctor específico
// Ruta GET para listar los pacientes asociados a un doctor.
app.get('/api/patients/doctor/:doctor_id', async (req, res) => {
  const { doctor_id } = req.params;

  try {
    const result = await pool.query(
      `SELECT *
       FROM patients
       WHERE doctor_id = $1
          OR patient_user_id IS NOT NULL
       ORDER BY created_at DESC`,
      [doctor_id]
    );

    res.json(result.rows);

  } catch (err) {
    console.error("❌ Error getting patients:", err);
    res.status(500).json({ error: "Error al obtener lista de pacientes." });
  }
});

// 3. Obtener datos de un solo paciente (para cargar en el juego EMG)
// Ruta GET para obtener un paciente por ID.
app.get('/api/patients/:id', async (req, res) => {
    try {
        // Busca el paciente usando el ID recibido en la URL.
        const result = await pool.query('SELECT * FROM patients WHERE id = $1', [req.params.id]);

        // Si no encuentra paciente, responde 404.
        if (result.rows.length === 0) return res.status(404).send("Paciente no encontrado.");

        // Devuelve los datos del paciente encontrado.
        res.json(result.rows[0]);
    } catch (err) {
        // Responde error si falla el servidor o la base.
        res.status(500).send("Error de servidor.");
    }
});

// AGREGA ESTO EN server.js
// Ruta DELETE para eliminar un paciente por ID.
app.delete('/api/patients/:id', async (req, res) => {
  try {
    // Extrae el ID del paciente desde la URL.
    const { id } = req.params;
   
    // Elimina el paciente de la base de datos.
    const result = await pool.query('DELETE FROM patients WHERE id = $1', [id]);

    // Si rowCount indica que se eliminó al menos una fila, responde éxito.
    if (result.rowCount > 0 || result > 0) {
      res.json({ success: true, message: "Paciente eliminado correctamente" });
    } else {
      // Si no se eliminó nada, el paciente no existía.
      res.status(404).json({ success: false, message: "Paciente no encontrado" });
    }
  } catch (error) {
    // Muestra error en consola si falla la eliminación.
    console.error("Error al eliminar:", error);

    // Responde error interno.
    res.status(500).json({ success: false, message: "Error interno del servidor" });
  }
});

// --- TU RUTA EXISTENTE DE SESIONES ---
// Ruta POST para guardar una sesión de juego/EMG.
app.post('/api/save-session', async (req, res) => {
  // Extrae datos enviados desde el frontend.
  const { patient_id, mode, score, samples, metrics } = req.body; 

  // Log para revisar qué datos llegaron al servidor.
  console.log("📥 Datos recibidos en el servidor:", { patient_id, mode, score, samplesCount: samples?.length });

  // Declara client fuera del try para poder usarlo también en catch/finally.
  let client;

  try {
    // Toma una conexión del pool.
    client = await pool.connect();

    // Inicia una transacción.
    await client.query('BEGIN');

    // 1. Insertar la cabecera de la sesión
    // Query para insertar datos generales de la sesión en emg_sessions.
    const sessionQuery = `
      INSERT INTO emg_sessions 
      (game_mode, score, selectivity_index, coactivation_ratio, fatigue_trend, control_efficiency, patient_id) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`;
    
    // Log antes de insertar la sesión.
    console.log("📝 Intentando insertar sesión...");

    // Ejecuta la inserción de la sesión usando parámetros seguros.
    const sessionRes = await client.query(sessionQuery, [
      mode, score, metrics.si, metrics.cr, metrics.fatigue, metrics.ce, patient_id
    ]);
    
    // Obtiene el ID de la sesión recién creada.
    const sessionId = sessionRes.rows[0].id;

    // Log con el ID de la nueva sesión.
    console.log(`🆔 Sesión creada con ID: ${sessionId}`);

    // 2. Insertar los samples con tus nombres de columna: val_a y val_b
    // ... dentro de app.post('/api/save-session', ...)

    // 2. Insertar los samples con tus nombres de columna: val_a y val_b
    // Si samples existe y tiene elementos, inserta las muestras en emg_samples.
    if (samples && samples.length > 0) {
      // Log de cantidad de muestras a insertar.
      console.log(`📊 Insertando ${samples.length} muestras...`);

      // Array con todos los valores que se pasarán a PostgreSQL.
      const sampleValues = [];

      // Array con los placeholders SQL: ($1,$2,$3,$4), etc.
      const placeholders = [];
      
      // Recorre cada muestra recibida desde el frontend.
 samples.forEach((sample, index) => {
    // Calcula el desplazamiento de parámetros SQL.
    // Cada muestra usa 4 valores: session_id, timestamp, val_a, val_b.
    const offset = index * 4;
    
    // Probamos diferentes nombres comunes (a o valA) para asegurar que no sea 0
    // Obtiene el valor A buscando diferentes nombres posibles.
    const rawA = sample.a ?? sample.valA ?? sample.val_a ?? 0;

    // Obtiene el valor B buscando diferentes nombres posibles.
    const rawB = sample.b ?? sample.valB ?? sample.val_b ?? 0;
    
    // Si rawA no es numérico, usa 0; si es válido, usa rawA.
    const valA = isNaN(rawA) ? 0 : rawA;

    // Si rawB no es numérico, usa 0; si es válido, usa rawB.
    const valB = isNaN(rawB) ? 0 : rawB;
    
    // Aseguramos la fecha
    // Si la muestra trae t, la convierte a Date; si no, usa la fecha actual.
    const dbTimestamp = sample.t ? new Date(sample.t) : new Date();

    // Agrega los 4 valores correspondientes a esta muestra.
    sampleValues.push(sessionId, dbTimestamp, valA, valB);

    // Agrega los placeholders correspondientes a esta muestra.
    placeholders.push(`($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4})`);

      });

      // Construye la query final para insertar todas las muestras juntas.
      const insertSamplesQuery = `
        INSERT INTO emg_samples (session_id, timestamp, val_a, val_b) 
        VALUES ${placeholders.join(', ')}`;
      
      // Ejecuta la inserción masiva de muestras.
      await client.query(insertSamplesQuery, sampleValues);
    }

    // Confirma todos los cambios de la transacción.
    await client.query('COMMIT');

    // ... resto del código
    // Log de éxito total.
    console.log(`✅ TODO GUARDADO: Sesión ${sessionId}`);

    // Responde al frontend con éxito y el ID de sesión.
    res.json({ success: true, sessionId });

  }  catch (err) {
    // Si hubo error y existe client, revierte la transacción.
    if (client) await client.query('ROLLBACK');

    // Muestra mensaje principal del error de base de datos.
    console.error('❌ ERROR EN BD:', err.message); 

    // Muestra detalle del error de PostgreSQL, si existe.
    console.error('Detalle:', err.detail); // <--- ESTO ES CLAVE

    // Responde al frontend con error y detalle.
    res.status(500).json({ error: err.message, detail: err.detail });
} finally {
    // Libera la conexión al pool si fue tomada.
    if (client) client.release();
  }
});

// --- RUTA: REGISTRAR PACIENTE COMO USUARIO CON VERIFICACIÓN EMAIL ---
app.post('/api/patient-users/register', async (req, res) => {
  const { username, email, password, serial_number } = req.body;
  const client = await pool.connect();

  if (!username || !email || !password || !serial_number) {
    client.release();

    return res.status(400).json({
      success: false,
      message: "Username, email, password and serial number are required."
    });
  }

  try {
    await client.query('BEGIN');

    const patientCheck = await client.query(
      'SELECT id FROM patient_users WHERE email = $1',
      [email]
    );

    if (patientCheck.rows.length > 0) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        message: "Patient email already registered."
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const result = await client.query(
      `INSERT INTO patient_users 
       (username, email, password, serial_number, verification_token, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, serial_number, is_verified, created_at`,
      [username, email, hashedPassword, serial_number, verificationToken, false]
    );

    const url = `${API_BASE_URL}/api/patient-users/verify/${verificationToken}`;

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: "Patient registered successfully. Check your email to verify your account.",
      patient: result.rows[0]
    });

    transporter.verify()
      .then(() => {
        console.log("✅ SMTP listo para paciente");

        return transporter.sendMail({
  from: `"Kawatek Bionics" <${process.env.EMAIL_USER}>`,
  to: email,
  subject: "Verify your Kawatek patient account",
  html: `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </head>

      <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f7fb; padding:40px 0;">
          <tr>
            <td align="center">

              <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:14px; overflow:hidden; border:1px solid #e5e7eb;">
                
                <tr>
                  <td align="center" style="padding:40px 40px 20px 40px;">
                    <h1 style="margin:0; color:#0f172a; font-size:26px; font-weight:800;">
                      Welcome, ${username}!
                    </h1>
                  </td>
                </tr>

                <tr>
                  <td style="padding:10px 40px 0 40px; color:#334155; font-size:16px; line-height:1.6;">
                    <p style="margin:0 0 18px 0;">
                      Thanks for joining the Kawatek rehabilitation platform. You are one step away from starting EMG monitoring and patient management.
                    </p>

                    <p style="margin:0 0 18px 0;">
                      Your bionic hand serial number is:
                      <strong style="color:#0f172a;">${serial_number}</strong>
                    </p>

                    <p style="margin:0;">
                      To activate your account, click the button below:
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="center" style="padding:35px 40px 25px 40px;">
                    <a href="${url}"
                       style="display:inline-block; background:#6d28d9; color:#ffffff; text-decoration:none; font-size:15px; font-weight:700; padding:16px 34px; border-radius:10px; letter-spacing:0.4px;">
                      VERIFY YOUR ACCOUNT
                    </a>
                  </td>
                </tr>

                <tr>
                  <td align="center" style="padding:0 40px 35px 40px; color:#94a3b8; font-size:13px; line-height:1.5;">
                    <p style="margin:0 0 8px 0;">
                      If the button doesn't work, copy this link into your browser:
                    </p>

                    <a href="${url}" style="color:#2563eb; word-break:break-all;">
                      ${url}
                    </a>
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 40px;">
                    <hr style="border:none; border-top:1px solid #e5e7eb; margin:0;" />
                  </td>
                </tr>

                <tr>
                  <td align="center" style="padding:22px 40px 30px 40px; color:#cbd5e1; font-size:12px;">
                    Rehabilitation software - Kawatek 2026
                  </td>
                </tr>

              </table>

            </td>
          </tr>
        </table>
      </body>
    </html>
  `
});
      })
      .then((info) => {
        console.log("✅ Patient verification email sent");
        console.log("MESSAGE ID:", info.messageId);
        console.log("ACCEPTED:", info.accepted);
        console.log("REJECTED:", info.rejected);
        console.log("RESPONSE:", info.response);
      })
      .catch((mailError) => {
        console.error("❌ PATIENT SMTP ERROR MESSAGE:", mailError.message);
        console.error("❌ PATIENT SMTP ERROR CODE:", mailError.code);
        console.error("❌ PATIENT SMTP ERROR COMMAND:", mailError.command);
        console.error("❌ PATIENT SMTP ERROR RESPONSE:", mailError.response);
        console.error("❌ PATIENT SMTP FULL ERROR:", mailError);
      });

  } catch (err) {
    await client.query('ROLLBACK');

    console.error("❌ Error registering patient user:", err);

    if (err.code === '23505') {
      return res.status(400).json({
        success: false,
        message: "Patient email already registered."
      });
    }

    res.status(500).json({
      success: false,
      message: "Error registering patient user."
    });

  } finally {
    client.release();
  }
});

// --- RUTA: VERIFICAR EMAIL DE PACIENTE ---
// --- VERIFY PATIENT EMAIL AND CREATE BASIC PATIENT PROFILE ---
app.get('/api/patient-users/verify/:token', async (req, res) => {
  const { token } = req.params;
  const client = await pool.connect();

  const FRONTEND_URL = process.env.NODE_ENV === 'production'
    ? 'https://flexfly.netlify.app'
    : 'http://localhost:5173';

  try {
    await client.query('BEGIN');

    const verifiedPatient = await client.query(
      `UPDATE patient_users
       SET is_verified = true,
           verification_token = NULL
       WHERE verification_token = $1
       RETURNING id, username, email, serial_number`,
      [token]
    );

    if (verifiedPatient.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(400).send("Invalid or expired patient verification token.");
    }

    const patientUser = verifiedPatient.rows[0];

    const existingPatient = await client.query(
      `SELECT id
       FROM patients
       WHERE patient_user_id = $1`,
      [patientUser.id]
    );

    if (existingPatient.rows.length === 0) {
      await client.query(
        `INSERT INTO patients
         (name, id_number, age, affected_side, condition, doctor_id, patient_user_id, email, serial_number, profile_completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          patientUser.username,
          null,
          null,
          null,
          null,
          null,
          patientUser.id,
          patientUser.email,
          patientUser.serial_number,
          false
        ]
      );
    }

    await client.query('COMMIT');

    res.redirect(`${FRONTEND_URL}/verify-success`);

  } catch (err) {
    await client.query('ROLLBACK');

    console.error("❌ Error verifying patient and creating patient profile:", err);

    res.status(500).send("Error verifying patient account.");

  } finally {
    client.release();
  }
});
// --- RUTA: LOGIN PACIENTE ---
// --- PATIENT LOGIN ---
app.post('/api/patient-users/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required."
    });
  }

  try {
    const result = await pool.query(
      `SELECT 
        pu.*,
        p.id AS clinical_patient_id,
        p.name AS clinical_patient_name,
        p.age,
        p.affected_side,
        p.condition,
        p.profile_completed
       FROM patient_users pu
       LEFT JOIN patients p ON p.patient_user_id = pu.id
       WHERE pu.email = $1`,
      [email]
    );

    const patient = result.rows[0];

    if (!patient) {
      return res.status(404).json({
        success: false,
        message: "Patient not found."
      });
    }

    if (!patient.is_verified) {
      return res.status(401).json({
        success: false,
        message: "Please verify your email before logging in."
      });
    }

    const isMatch = await bcrypt.compare(password, patient.password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Incorrect password."
      });
    }

    let clinicalPatientId = patient.clinical_patient_id;

    // Safety fallback: if profile was not created during verification, create it now.
    if (!clinicalPatientId) {
      const createdProfile = await pool.query(
        `INSERT INTO patients
         (name, id_number, age, affected_side, condition, doctor_id, patient_user_id, email, serial_number, profile_completed)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id`,
        [
          patient.username,
          null,
          null,
          null,
          null,
          null,
          patient.id,
          patient.email,
          patient.serial_number,
          false
        ]
      );

      clinicalPatientId = createdProfile.rows[0].id;
    }

    res.json({
      success: true,
      message: "Patient login successful.",
      patient: {
        id: patient.id,
        patient_user_id: patient.id,
        clinical_patient_id: clinicalPatientId,
        username: patient.username,
        name: patient.clinical_patient_name || patient.username,
        email: patient.email,
        serial_number: patient.serial_number,
        age: patient.age,
        affected_side: patient.affected_side,
        condition: patient.condition,
        profile_completed: patient.profile_completed === true
      }
    });

  } catch (err) {
    console.error("❌ Error logging patient user:", err);

    res.status(500).json({
      success: false,
      message: "Error logging patient user."
    });
  }
});

// --- DOCTOR: REQUEST PASSWORD RESET ---

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email is required."
    });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, email FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "This email is not associated with any account."
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(
      `UPDATE users
       SET reset_password_token = $1,
           reset_password_expires = $2
       WHERE id = $3`,
      [resetToken, resetExpires, user.id]
    );

    const FRONTEND_URL = process.env.NODE_ENV === 'production'
      ? 'https://flexfly.netlify.app'
      : 'http://localhost:5173';

    const resetUrl = `${FRONTEND_URL}/reset-password/doctor/${resetToken}`;

    await transporter.verify();

    const info = await transporter.sendMail({
      from: `"Kawatek Bionics" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Reset your Kawatek doctor password",
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          </head>

          <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f7fb; padding:40px 0;">
              <tr>
                <td align="center">
                  <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:14px; overflow:hidden; border:1px solid #e5e7eb;">
                    
                    <tr>
                      <td align="center" style="padding:40px 40px 20px 40px;">
                        <h1 style="margin:0; color:#0f172a; font-size:26px; font-weight:800;">
                          Reset your password
                        </h1>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding:10px 40px 0 40px; color:#334155; font-size:16px; line-height:1.6;">
                        <p style="margin:0 0 18px 0;">
                          Hi ${user.username}, we received a request to reset your Kawatek doctor account password.
                        </p>

                        <p style="margin:0;">
                          Click the button below to create a new password. This link expires in 1 hour.
                        </p>
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:35px 40px 25px 40px;">
                        <a href="${resetUrl}"
                           style="display:inline-block; background:#6d28d9; color:#ffffff; text-decoration:none; font-size:15px; font-weight:700; padding:16px 34px; border-radius:10px; letter-spacing:0.4px;">
                          RESET PASSWORD
                        </a>
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:0 40px 35px 40px; color:#94a3b8; font-size:13px; line-height:1.5;">
                        <p style="margin:0 0 8px 0;">
                          If the button doesn't work, copy this link into your browser:
                        </p>

                        <a href="${resetUrl}" style="color:#2563eb; word-break:break-all;">
                          ${resetUrl}
                        </a>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding:0 40px;">
                        <hr style="border:none; border-top:1px solid #e5e7eb; margin:0;" />
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:22px 40px 30px 40px; color:#cbd5e1; font-size:12px;">
                        Rehabilitation software - Kawatek 2026
                      </td>
                    </tr>

                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
      `
    });

    console.log("✅ Doctor reset password email sent");
    console.log("MESSAGE ID:", info.messageId);
    console.log("ACCEPTED:", info.accepted);
    console.log("REJECTED:", info.rejected);
    console.log("RESPONSE:", info.response);

    res.json({
      success: true,
      message: "Password reset email sent successfully."
    });

  } catch (err) {
    console.error("❌ Doctor forgot password error:", err.message);
    console.error("❌ Full error:", err);

    res.status(500).json({
      success: false,
      message: "Error sending password reset email."
    });
  }
});
// --- DOCTOR: RESET PASSWORD ---
app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      success: false,
      message: "New password is required."
    });
  }

  try {
    const result = await pool.query(
      `SELECT id FROM users
       WHERE reset_password_token = $1
       AND reset_password_expires > NOW()`,
      [token]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token."
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(
      `UPDATE users
       SET password = $1,
           reset_password_token = NULL,
           reset_password_expires = NULL
       WHERE id = $2`,
      [hashedPassword, user.id]
    );

    res.json({
      success: true,
      message: "Password updated successfully."
    });

  } catch (err) {
    console.error("❌ Doctor reset password error:", err);

    res.status(500).json({
      success: false,
      message: "Error resetting password."
    });
  }
});

// --- PATIENT: REQUEST PASSWORD RESET ---
app.post('/api/patient-users/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email is required."
    });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, email FROM patient_users WHERE email = $1',
      [email]
    );

    const patient = result.rows[0];

    if (!patient) {
      return res.status(404).json({
        success: false,
        message: "This email is not associated with any account."
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(
      `UPDATE patient_users
       SET reset_password_token = $1,
           reset_password_expires = $2
       WHERE id = $3`,
      [resetToken, resetExpires, patient.id]
    );

    const FRONTEND_URL = process.env.NODE_ENV === 'production'
      ? 'https://flexfly.netlify.app'
      : 'http://localhost:5173';

    const resetUrl = `${FRONTEND_URL}/reset-password/patient/${resetToken}`;

    await transporter.verify();

    const info = await transporter.sendMail({
      from: `"Kawatek Bionics" <${process.env.EMAIL_USER}>`,
      to: patient.email,
      subject: "Reset your Kawatek patient password",
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          </head>

          <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f7fb; padding:40px 0;">
              <tr>
                <td align="center">
                  <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:14px; overflow:hidden; border:1px solid #e5e7eb;">
                    
                    <tr>
                      <td align="center" style="padding:40px 40px 20px 40px;">
                        <h1 style="margin:0; color:#0f172a; font-size:26px; font-weight:800;">
                          Reset your password
                        </h1>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding:10px 40px 0 40px; color:#334155; font-size:16px; line-height:1.6;">
                        <p style="margin:0 0 18px 0;">
                          Hi ${patient.username}, we received a request to reset your Kawatek patient account password.
                        </p>

                        <p style="margin:0;">
                          Click the button below to create a new password. This link expires in 1 hour.
                        </p>
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:35px 40px 25px 40px;">
                        <a href="${resetUrl}"
                           style="display:inline-block; background:#6d28d9; color:#ffffff; text-decoration:none; font-size:15px; font-weight:700; padding:16px 34px; border-radius:10px; letter-spacing:0.4px;">
                          RESET PASSWORD
                        </a>
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:0 40px 35px 40px; color:#94a3b8; font-size:13px; line-height:1.5;">
                        <p style="margin:0 0 8px 0;">
                          If the button doesn't work, copy this link into your browser:
                        </p>

                        <a href="${resetUrl}" style="color:#2563eb; word-break:break-all;">
                          ${resetUrl}
                        </a>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding:0 40px;">
                        <hr style="border:none; border-top:1px solid #e5e7eb; margin:0;" />
                      </td>
                    </tr>

                    <tr>
                      <td align="center" style="padding:22px 40px 30px 40px; color:#cbd5e1; font-size:12px;">
                        Rehabilitation software - Kawatek 2026
                      </td>
                    </tr>

                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
      `
    });

    console.log("✅ Patient reset password email sent");
    console.log("MESSAGE ID:", info.messageId);
    console.log("ACCEPTED:", info.accepted);
    console.log("REJECTED:", info.rejected);
    console.log("RESPONSE:", info.response);

    res.json({
      success: true,
      message: "Password reset email sent successfully."
    });

  } catch (err) {
    console.error("❌ Patient forgot password error:", err.message);
    console.error("❌ Full error:", err);

    res.status(500).json({
      success: false,
      message: "Error sending password reset email."
    });
  }
});
// --- PATIENT: RESET PASSWORD ---
app.post('/api/patient-users/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      success: false,
      message: "New password is required."
    });
  }

  try {
    const result = await pool.query(
      `SELECT id FROM patient_users
       WHERE reset_password_token = $1
       AND reset_password_expires > NOW()`,
      [token]
    );

    const patient = result.rows[0];

    if (!patient) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token."
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(
      `UPDATE patient_users
       SET password = $1,
           reset_password_token = NULL,
           reset_password_expires = NULL
       WHERE id = $2`,
      [hashedPassword, patient.id]
    );

    res.json({
      success: true,
      message: "Password updated successfully."
    });

  } catch (err) {
    console.error("❌ Patient reset password error:", err);

    res.status(500).json({
      success: false,
      message: "Error resetting password."
    });
  }
});
// --- COMPLETE PATIENT PROFILE ---
app.put('/api/patient-users/complete-profile/:patient_user_id', async (req, res) => {
  const { patient_user_id } = req.params;
  const { name, age, affected_side, condition } = req.body;

  if (!name || !age || !affected_side || !condition) {
    return res.status(400).json({
      success: false,
      message: "Name, age, affected side and condition are required."
    });
  }

  if (isNaN(age)) {
    return res.status(400).json({
      success: false,
      message: "Age must be a valid number."
    });
  }

  try {
    const result = await pool.query(
      `UPDATE patients
       SET name = $1,
           age = $2,
           affected_side = $3,
           condition = $4,
           profile_completed = true
       WHERE patient_user_id = $5
       RETURNING *`,
      [name, age, affected_side, condition, patient_user_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Patient profile not found."
      });
    }

    res.json({
      success: true,
      message: "Patient profile completed successfully.",
      patient: result.rows[0]
    });

  } catch (err) {
    console.error("❌ Error completing patient profile:", err);

    res.status(500).json({
      success: false,
      message: "Error completing patient profile."
    });
  }
});
// Inicia el servidor escuchando en todas las interfaces de red.
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor Kawatek activo en puerto ${PORT}`));
