// Importa dotenv para cargar variables de entorno desde un archivo .env.
import dotenv from 'dotenv';

// Importa path para trabajar con rutas de archivos y carpetas.
import path from 'path';

// Importa fileURLToPath para convertir la URL del módulo actual en una ruta de archivo.
import { fileURLToPath } from 'url';

// Importa Express, el framework usado para crear el servidor backend.
import express from 'express';

// Importa el paquete pg, que permite conectarse a PostgreSQL.
import pkg from 'pg';

// Importa cors para permitir o bloquear peticiones desde otros dominios.
import cors from 'cors';

// Importa bcrypt para encriptar y comparar contraseñas de forma segura.
import bcrypt from 'bcryptjs'; // <--- Añadido para seguridad

// Importa crypto, módulo nativo de Node usado para generar tokens seguros.
import crypto from 'crypto'; // Viene con Node

// Importa nodemailer para enviar emails desde el backend.
import nodemailer from 'nodemailer';

// Extrae Pool desde el paquete pg.
// Pool permite manejar varias conexiones a PostgreSQL de forma eficiente.
const { Pool } = pkg;

// Define el puerto del servidor.
// Usa process.env.PORT si existe; si no, usa 5000 por defecto.
const PORT = process.env.PORT || 5000; // Usa el del .env o 5000 por defecto

// Convierte la URL del archivo actual en una ruta de archivo real.
const __filename = fileURLToPath(import.meta.url);

// Obtiene el directorio donde está este archivo.
const __dirname = path.dirname(__filename);

// Carga las variables de entorno desde el archivo .env ubicado en ../backk/.env.
dotenv.config({ path: path.resolve(__dirname, '../backk/.env') }); // Asegura que cargue el .env correcto

// Crea una instancia de la aplicación Express.
const app = express();

// CAMBIO 3: Actualiza el origen de CORS
// En tu archivo server.js o index.js del BACKEND:
// Lista de dominios que tienen permitido hacer peticiones al backend.
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

// Crea esta variable al inicio de tu server.js
// Define la URL base del backend según el entorno.
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  // Si está en producción, usa la URL pública de Render.
  ? 'https://flex-fly-back.onrender.com'
  // Si está en local, usa localhost con el puerto definido.
  : `http://localhost:${PORT}`;

// Usa la variable de entorno, o la de Render por defecto si no existe


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

// Test de conexión
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
  host: "smtp.resend.com",
  port: 587,
  secure: false,
  auth: {
    user: "resend",
    pass: process.env.RESEND_API_KEY
  }
});

// --- RUTA DE REGISTRO CON LOGS ---
// --- RUTA DE REGISTRO CORREGIDA ---
// Ruta POST para registrar un usuario nuevo.
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const userCheck = await client.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: "Email already registered." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    await client.query(
      'INSERT INTO users (username, email, password, verification_token, is_verified) VALUES ($1, $2, $3, $4, $5)',
      [username, email, hashedPassword, verificationToken, false]
    );

    const url = `${API_BASE_URL}/api/auth/verify/${verificationToken}`;

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: "Check your email to verify your account."
    });

   fetch("https://api.resend.com/emails", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    from: "Kawatek <onboarding@resend.dev>",
    to: [email],
    subject: "Verifica tu cuenta Kawatek",
    html: `
      <p>Welcome ${username}</p>
      <p>Verify your account:</p>
      <a href="${url}">${url}</a>
    `
  })
}).then(() => {
  console.log("✅ Email enviado");
}).catch((err) => {
  console.error("❌ Error mail:", err.message);
});

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ Error en el proceso de registro:", err);

    res.status(500).json({
      success: false,
      message: "The registration failed. Please try again."
    });
  } finally {
    client.release();
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
      return res.status(401).json({ success: false, message: "Por favor, verifica tu email primero." });
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
    // Extrae doctor_id desde la URL.
    const { doctor_id } = req.params;

    try {
        // Consulta todos los pacientes de ese doctor, ordenados por fecha de creación descendente.
        const result = await pool.query(
            'SELECT * FROM patients WHERE doctor_id = $1 ORDER BY created_at DESC', 
            [doctor_id]
        );

        // Devuelve la lista de pacientes como JSON.
        res.json(result.rows);
    } catch (err) {
        // Responde error si falla la consulta.
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

// Inicia el servidor escuchando en todas las interfaces de red.
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor Kawatek activo en puerto ${PORT}`));
