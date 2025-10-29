const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const axios = require("axios");
const validator = require('validator');
const multer = require('multer');

// ===================================
// CONFIGURACIÓN INICIAL DE EXPRESS Y FIREBASE
// ===================================

const app = express();
// Enhanced CORS configuration
const corsOptions = {
    origin: '*', // In production, replace with your frontend URL
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Rol'],
    credentials: false
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CONFIGURACIÓN DE MULTER
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Límite de 5MB
});

// Variables de entorno
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;
const FIREBASE_KEY = process.env.FIREBASE_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID; // 💡 ASUME ESTA VARIABLE
const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL; // 💡 ASUME ESTA VARIABLE
const FIREBASE_STORAGE_BUCKET = process.env.FIREBASE_STORAGE_BUCKET; // 💡 ASUME ESTA VARIABLE
const FIREBASE_SENDER_ID = process.env.FIREBASE_SENDER_ID; // 💡 ASUME ESTA VARIABLE
const FIREBASE_APP_ID = process.env.FIREBASE_APP_ID; // 💡 ASUME ESTA VARIABLE


if (!FIREBASE_WEB_API_KEY) {
    throw new Error("❌ La variable de entorno FIREBASE_WEB_API_KEY no está configurada");
}
if (!FIREBASE_KEY) {
    throw new Error("❌ La variable de entorno FIREBASE_KEY (clave privada) no está configurada");
}

try {
    const serviceAccount = JSON.parse(FIREBASE_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        // Puedes configurar la URL de la Realtime Database aquí si la usas con Admin SDK
        databaseURL: FIREBASE_DATABASE_URL, 
    });
} catch (e) {
    console.error("Error al parsear FIREBASE_KEY. Asegúrate de que el JSON sea válido.", e);
    throw new Error("❌ Error en la inicialización de Firebase Admin.");
}

const db = admin.firestore();
const realtimeDb = admin.database(); // Inicializa Realtime Database Admin SDK

// Almacenamiento temporal para el bloqueo de sesiones (Rate Limiting)
const loginAttempts = {}; // { email: { count: 0, time: Date } }
const MAX_ATTEMPTS = 3;
const LOCKOUT_TIME_MS = 10 * 60 * 1000;

// ===================================
// FUNCIONES DE VALIDACIÓN DE SEGURIDAD (Sin cambios)
// ===================================

function validateNombre(nombre) {
    if (!nombre) return "El nombre es obligatorio.";
    if (nombre.length > 30) return "El nombre no puede exceder los 30 caracteres.";
    // Solo se permiten letras, números, espacios y tildes/ñ
    if (/[^a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ]/.test(nombre)) {
        return "El nombre contiene caracteres especiales no permitidos.";
    }
    return null; 
}

async function validateEmail(email) {
    // Verificación de formato estándar estricto (sin display name, requiere TLD)
    if (!validator.isEmail(email, { allow_display_name: false, require_tld: true, allow_utf8_local_part: false })) {
        return "El formato del correo electrónico es inválido.";
    }
    return null; 
}

function validatePassword(password) {
    // Al menos 8 caracteres, mayúscula, minúscula, número, y especial (sin espacio en blanco)
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9\s]).{8,}$/;
    
    if (password.length < 8) return "La contraseña debe tener al menos 8 caracteres.";
    if (!passwordPattern.test(password)) {
          return "La contraseña debe incluir mayúsculas, minúsculas, números y al menos un carácter especial.";
    }
    return null;
}
// Middleware de Verificación de Administrador
function verificaradmin(req, res, next) {
    // HTTP headers are case-insensitive, check for both variations
    const rolUsuario = req.headers['x-user-rol'] || req.headers['X-User-Rol'];
    
    console.log(`verificaradmin - Received role: ${rolUsuario}`);
    
    // Verificamos si el rol, en minúsculas, es 'administrador'
    if (rolUsuario && rolUsuario.toLowerCase() === 'administrador') {
        console.log('Admin access granted');
        next();
    } else {
        console.error(`Access denied. Role: ${rolUsuario}, Headers:`, req.headers);
        res.status(403).json({ ok: false, mensaje: "Acceso denegado. Se requiere rol de Administrador." });
    }
}


// ===================================
// ⚙️ NUEVA RUTA: OBTENER CONFIGURACIÓN FIREBASE WEB
// ===================================

/**
 * Provee la configuración de Firebase SDK (Web/Frontend) sin exponer secretos de Admin.
 */
app.get("/api/firebase/config", (req, res) => {
    // Asegúrate de que estas variables de entorno existan
    if (!FIREBASE_PROJECT_ID || !FIREBASE_DATABASE_URL || !FIREBASE_STORAGE_BUCKET || !FIREBASE_SENDER_ID || !FIREBASE_APP_ID) {
        console.error("Faltan variables de entorno de configuración pública de Firebase.");
        return res.status(500).json({ ok: false, mensaje: "Configuración de Firebase incompleta en el servidor." });
    }

    const firebaseConfig = {
        apiKey: FIREBASE_WEB_API_KEY, // Esta API Key es segura para exponer
        authDomain: `${FIREBASE_PROJECT_ID}.firebaseapp.com`,
        databaseURL: FIREBASE_DATABASE_URL,
        projectId: FIREBASE_PROJECT_ID,
        storageBucket: FIREBASE_STORAGE_BUCKET,
        messagingSenderId: FIREBASE_SENDER_ID,
        appId: FIREBASE_APP_ID
    };

    res.json({ ok: true, firebaseConfig });
});

// ===================================
// RUTAS DE AUTENTICACIÓN (Sin cambios funcionales)
// ===================================

// 📌 Ruta: REGISTRO
app.post("/api/registro", async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    // 1. Validaciones de Seguridad
    const validaciones = [validateNombre(nombre), await validateEmail(email), validatePassword(password)];
    for (const error of validaciones) {
        if (error) return res.status(400).json({ ok: false, mensaje: error });
    }
    if (!rol) return res.status(400).json({ ok: false, mensaje: "El rol es obligatorio." });

    try {
        // PASO 1: CREAR USUARIO EN FIREBASE AUTH
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: nombre,
        });

        const uid = userRecord.uid;

        // PASO 2: GUARDAR PERFIL EN FIRESTORE
        await db.collection("usuarios").doc(uid).set({
            nombre: nombre,
            email: email,
            rol: rol,
        });

        res.json({ ok: true, mensaje: "Usuario registrado y perfil creado correctamente" });

    } catch (error) {
        console.error("Error en registro:", error);
        let mensajeError = "Error en el servidor.";
        if (error.code === 'auth/email-already-in-use') {
            mensajeError = "El correo electrónico ya está registrado.";
            return res.status(409).json({ ok: false, mensaje: mensajeError });
        }
        res.status(500).json({ ok: false, mensaje: mensajeError });
    }
});


// 📌 Ruta: LOGIN
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) return res.status(400).json({ ok: false, mensaje: "Faltan datos." });
        
        // 1. Validación de Email
        const emailError = await validateEmail(email);
        if (emailError) return res.status(400).json({ ok: false, mensaje: emailError });

        // 2. Bloqueo por Intentos Fallidos
        const now = Date.now();
        const attempts = loginAttempts[email];

        if (attempts) {
            if (attempts.count >= MAX_ATTEMPTS && now - attempts.time < LOCKOUT_TIME_MS) {
                const remainingTime = Math.ceil((LOCKOUT_TIME_MS - (now - attempts.time)) / 60000); // en minutos
                return res.status(429).json({ 
                    ok: false, 
                    mensaje: `Demasiados intentos de inicio de sesión. Intente de nuevo en ${remainingTime} minutos.` 
                });
            } else if (now - attempts.time >= LOCKOUT_TIME_MS) {
                delete loginAttempts[email]; // Reset
            }
        }
        
        let uid;

        // --- PASO 3: AUTENTICAR CON FIREBASE REST API ---
        try {
            const loginUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
            const authResponse = await axios.post(loginUrl, { email, password, returnSecureToken: true });
            
            delete loginAttempts[email]; // Éxito: borramos intentos fallidos
            uid = authResponse.data.localId;
            
        } catch (authError) {
            // Fallo: Incrementar contador
            loginAttempts[email] = { count: (loginAttempts[email]?.count || 0) + 1, time: now };
            return res.status(401).json({ ok: false, mensaje: "Credenciales incorrectas o usuario no encontrado." });
        }
        
        // --- PASO 4: OBTENER EL PERFIL DE FIRESTORE ---
        const doc = await db.collection("usuarios").doc(uid).get();

        if (!doc.exists) {
            return res.status(404).json({ ok: false, mensaje: "Perfil de usuario no encontrado." });
        }

        const usuario = doc.data();

        // --- PASO 5: RESPUESTA EXITOSA ---
        res.json({ 
            ok: true, 
            mensaje: "Sesión iniciada", 
            usuario: { 
                id: uid, // Include UID for frontend to use as identifier
                email: usuario.email, 
                nombre: usuario.nombre, 
                rol: usuario.rol 
            } 
        });
        
    } catch (error) {
        console.error("Error general en login:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor." });
    }
});

// ... (El resto de tus rutas como /api/arboles/registrar, /api/admin/validacion, etc.
// se mantienen igual, ya que usan Firebase Admin SDK, no el Web SDK.)
// ... (Tus otras rutas aquí)

// ===================================
// 📅 GESTIÓN DE EVENTOS (Uso de Realtime Database Admin SDK para lectura de sensores - EJEMPLO)
// ===================================

/**
 * Endpoint para obtener datos de un sensor específico desde Realtime Database.
 * Idealmente usarías esto para que el backend filtre o procese los datos.
 */
app.get('/api/sensores/:arbolId', async (req, res) => {
    const arbolId = req.params.arbolId;
    const path = `/sensores/arbol_${arbolId}`;

    try {
        const snapshot = await realtimeDb.ref(path).once('value');
        const data = snapshot.val();

        if (!data) {
            return res.status(404).json({ ok: false, mensaje: `No se encontraron datos para el árbol ID: ${arbolId}` });
        }

        res.status(200).json({ ok: true, datosSensor: data });
    } catch (error) {
        console.error(`Error al leer sensor ${arbolId} de Realtime DB:`, error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener datos del sensor." });
    }
});


// ... (El resto de tus rutas aquí: /api/arboles/registrar, /api/admin/validacion, /api/voluntario/retos, etc.)

// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
