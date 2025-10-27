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
    });
} catch (e) {
    console.error("Error al parsear FIREBASE_KEY. Asegúrate de que el JSON sea válido.", e);
    throw new Error("❌ Error en la inicialización de Firebase Admin.");
}

const db = admin.firestore();

// Almacenamiento temporal para el bloqueo de sesiones (Rate Limiting)
const loginAttempts = {}; // { email: { count: 0, time: Date } }
const MAX_ATTEMPTS = 3;
const LOCKOUT_TIME_MS = 10 * 60 * 1000;

// ===================================
// FUNCIONES DE VALIDACIÓN DE SEGURIDAD
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
// Compara el rol con la mayúscula inicial definida
// Servidor.js (FUNCIÓN DE VERIFICACIÓN DE ADMINISTRADOR)

function verificaradmin(req, res, next) {
    // HTTP headers are case-insensitive, check for both variations
    const rolUsuario = req.headers['x-user-rol'] || req.headers['X-User-Rol'];
    
    // Verificamos si el rol, en minúsculas, es 'administrador'
    if (rolUsuario && rolUsuario.toLowerCase() === 'administrador') {
        next();
    } else {
        console.error(`Access denied. Role: ${rolUsuario}, Headers:`, req.headers);
        res.status(403).json({ ok: false, mensaje: "Acceso denegado. Se requiere rol de Administrador." });
    }
}


// ===================================
// RUTAS DE AUTENTICACIÓN
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

// ===================================
// 🌳 RUTAS DEL VOLUNTARIO (Colección 'arboles')
// ===================================

/**
 * Endpoint para registrar un árbol plantado.
 */
app.post('/api/arboles/registrar', upload.single('evidenciaFoto'), async (req, res) => {
    // Todos los campos en minúsculas
    const { voluntarioid, tipoarbol, ubicaciongps } = req.body; 
    const fotofile = req.file; 

    // 1. Validaciones
    if (!voluntarioid || !tipoarbol || !ubicaciongps || !fotofile) {
        return res.status(400).json({ mensaje: "Faltan datos obligatorios (ID, Tipo, GPS o Foto)." });
    }

    try {
        // SIMULACIÓN DE SUBIDA A FIREBASE STORAGE
        const simulatedfilename = `${voluntarioid}_${Date.now()}.jpg`;
        const fotourl = `https://storage.firebase.com/v0/b/greenroots.appspot.com/o/${simulatedfilename}`; 

        // 2. Guardar en Firestore en la colección 'arboles'
        const nuevoregistro = {
            voluntarioid: voluntarioid,
            tipodearbol: tipoarbol, // minúsculas
            ubicacion: ubicaciongps, // minúsculas
            fotourl: fotourl, 
            fecharegistro: new Date(),
            estadovalidacion: 'Pendiente' // Usa Mayúscula inicial por la query del Admin
        };

        const docref = await db.collection('arboles').add(nuevoregistro);
        
        res.status(201).json({ 
            ok: true,
            mensaje: "Árbol registrado. Pendiente de validación.", 
            id: docref.id 
        });

    } catch (error) {
        console.error("Error al registrar el árbol:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al registrar árbol." });
    }
});

/**
 * Endpoint para simular la obtención de retos.
 */
app.get('/api/voluntario/retos', async (req, res) => {
    const retosactivos = [
        { id: 1, titulo: "Maratón de Riego", descripcion: "Riega 10 árboles en la Zona Norte.", completado: false },
        { id: 2, titulo: "Especie Rara", descripcion: "Planta al menos 3 Cedros.", completado: true },
    ];
    const reconocimientos = ["Voluntario del Mes (Octubre)", "Experto en Reforestación"];
    
    res.status(200).json({ retosactivos, reconocimientos });
});

// ===================================
// ⚙️ RUTAS DEL ADMINISTRADOR
// ===================================

/**
 * Endpoint para obtener todos los registros de árboles pendientes de validación.
 * Protegido por verificaradmin.
 */
app.get('/api/admin/validacion/pendientes', verificaradmin, async (req, res) => {
    try {
        // La query debe coincidir con el campo guardado en el registro: estadovalidacion
        const snapshot = await db.collection('arboles')
                                 .where('estadovalidacion', '==', 'Pendiente')
                                 .orderBy('fecharegistro', 'asc')
                                 .get();

        const registros = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.status(200).json({ ok: true, registros });

    } catch (error) {
        console.error("Error al obtener registros pendientes:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor." });
    }
});

/**
 * Endpoint para actualizar el estado de validación (Aprobar/Rechazar).
 * Protegido por verificaradmin.
 */
app.patch('/api/admin/validacion/:id', verificaradmin, async (req, res) => {
    const registroid = req.params.id;
    const { nuevoestado, motivorechazo } = req.body; 

    if (nuevoestado !== 'Aprobado' && nuevoestado !== 'Rechazado') {
        return res.status(400).json({ mensaje: "Estado de validación inválido." });
    }
    
    const dataactualizar = {
        estadovalidacion: nuevoestado,
        fechavalidacion: new Date()
    };

    if (nuevoestado === 'Rechazado' && motivorechazo) {
        dataactualizar.motivorechazo = motivorechazo; // minúsculas
    }

    try {
        await db.collection('arboles').doc(registroid).update(dataactualizar);
        
        res.status(200).json({ 
            ok: true,
            mensaje: `Registro ${registroid} actualizado a ${nuevoestado}.` 
        });

    } catch (error) {
        console.error(`Error al validar registro ${registroid}:`, error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor." });
    }
});

/**
 * Endpoint para Gestión de Usuarios y Roles (Simulación).
 * Protegido por verificaradmin.
 */
app.patch('/api/admin/gestion/usuario/:uid', verificaradmin, async (req, res) => {
    const uid = req.params.uid;
    const { nuevorol, estado } = req.body;

    if (!nuevorol && !estado) {
        return res.status(400).json({ mensaje: "Debe especificar un nuevo rol o estado." });
    }

    try {
        const dataactualizar = {};
        if (nuevorol) {
            dataactualizar.rol = nuevorol;
        }
        if (estado === 'activo' || estado === 'inactivo') {
            await admin.auth().updateUser(uid, { disabled: estado === 'inactivo' });
        }

        await db.collection('usuarios').doc(uid).update(dataactualizar);

        res.status(200).json({ ok: true, mensaje: `Usuario ${uid} actualizado.` });
        
    } catch (error) {
        console.error("Error al gestionar usuario:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno al gestionar usuario." });
    }
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
