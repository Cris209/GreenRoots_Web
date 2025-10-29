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
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Rol'], // 'Authorization' es ahora esencial
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
// FUNCIONES DE UTILIDAD PARA AUTHENTICACIÓN
// ===================================

/**
 * Obtiene el rol del usuario desde Firestore
 * @param {string} uid El UID del usuario
 * @returns {Promise<string|null>} El rol del usuario o null
 */
async function obtenerRolDeUsuario(uid) {
    try {
        const doc = await db.collection("usuarios").doc(uid).get();
        return doc.exists ? doc.data().rol : null;
    } catch (e) {
        console.error("Error fetching user role:", e);
        return null;
    }
}

// ===================================
// MIDDLEWARE DE SEGURIDAD (OPCIÓN 1 IMPLEMENTADA)
// ===================================

/**
 * Middleware para verificar el token de Firebase.
 * Adjunta el ID Token decodificado a req.user.
 */
async function autenticarToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ ok: false, mensaje: "Acceso denegado. Se requiere token." });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
        // Verifica y decodifica el token usando Firebase Admin SDK
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken; // El token verificado contiene el uid, email, etc.
        req.uid = decodedToken.uid; // Alias para fácil acceso
        
        // Opcionalmente, adjunta el rol desde Firestore para simplificar las verificaciones posteriores
        const rol = await obtenerRolDeUsuario(req.uid);
        if (rol) {
            req.user.rol = rol;
        } else {
            console.warn(`Rol no encontrado para UID: ${req.uid}`);
        }

        next();
    } catch (error) {
        console.error("Error al verificar token:", error);
        // Firebase Auth errors: auth/id-token-expired, auth/invalid-id-token
        return res.status(401).json({ ok: false, mensaje: "Token inválido o expirado." });
    }
}


/**
 * Middleware de Verificación de Administrador.
 * Debe ejecutarse *después* de autenticarToken.
 */
function verificaradmin(req, res, next) {
    // El rol ya está adjunto a req.user si autenticarToken se ejecutó correctamente
    const rolUsuario = req.user?.rol; 
    
    console.log(`verificaradmin - Verified role from token claims/firestore: ${rolUsuario}`);
    
    // Verificamos si el rol, en minúsculas, es 'administrador'
    if (rolUsuario && rolUsuario.toLowerCase() === 'administrador') {
        console.log('Admin access granted');
        next();
    } else {
        console.error(`Access denied. UID: ${req.uid}, Role: ${rolUsuario}`);
        // Utilizamos 403 Forbidden ya que el usuario está autenticado, pero no autorizado.
        res.status(403).json({ ok: false, mensaje: "Acceso denegado. Se requiere rol de Administrador." });
    }
}


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

// ===================================
// ⚙️ RUTA: OBTENER CONFIGURACIÓN FIREBASE WEB
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
        let idToken; // Almacenará el token de autenticación

        // --- PASO 3: AUTENTICAR CON FIREBASE REST API ---
        try {
            const loginUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
            const authResponse = await axios.post(loginUrl, { email, password, returnSecureToken: true });
            
            delete loginAttempts[email]; // Éxito: borramos intentos fallidos
            uid = authResponse.data.localId;
            idToken = authResponse.data.idToken; // Captura el ID Token
            
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
            token: idToken, // ¡Devuelve el token!
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
 * 💡 RUTA PROTEGIDA
 */
app.post('/api/arboles/registrar', autenticarToken, upload.single('evidenciaFoto'), async (req, res) => {
    // Todos los campos en minúsculas
    // Usamos req.uid del token para asegurarnos de la identidad
    const { tipoarbol, ubicaciongps } = req.body; 
    const voluntarioid = req.uid; // Usamos el ID verificado del token
    const fotofile = req.file; 

    // 1. Validaciones
    if (!voluntarioid || !tipoarbol || !ubicaciongps || !fotofile) {
        return res.status(400).json({ mensaje: "Faltan datos obligatorios (Tipo, GPS o Foto)." });
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
        
        console.log(`Tree registered successfully:`, {
            id: docref.id,
            voluntarioid: voluntarioid,
            tipodearbol: tipoarbol,
            estadovalidacion: nuevoregistro.estadovalidacion
        });
        
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
 * Endpoint para simular la obtención de retos. (Ruta pública, no requiere token)
 */
/**
 * @deprecated - Use /api/campanas/activas instead
 * Get active challenges for volunteers (legacy endpoint)
 */
app.get('/api/voluntario/retos', async (req, res) => {
    try {
        // Get active campaigns from database
        const snapshot = await db.collection('campanas')
            .where('activa', '==', true)
            .limit(10)
            .get();
        
        const retosactivos = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        // For now, return empty recognitions (can be extended with real data)
        const reconocimientos = [];
        
        res.status(200).json({ retosactivos, reconocimientos });
    } catch (error) {
        console.error("Error al obtener retos:", error);
        // Fallback to default data
        const retosactivos = [
            { id: 1, titulo: "Maratón de Riego", descripcion: "Riega 10 árboles en la Zona Norte.", completado: false },
        ];
        res.status(200).json({ retosactivos, reconocimientos: [] });
    }
});

// ===================================
// ⚙️ RUTAS DEL ADMINISTRADOR
// ===================================

/**
 * Endpoint para obtener todos los registros de árboles pendientes de validación.
 * 💡 RUTA PROTEGIDA con autenticarToken y verificaradmin.
 */
/**
 * Endpoint para diagnosticar - obtener TODOS los registros sin filtrar
 */
app.get('/api/admin/validacion/all', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const snapshot = await db.collection('arboles').get();
        const registros = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        console.log(`Total records in database: ${registros.length}`);
        console.log('Records:', registros);
        
        res.status(200).json({ ok: true, total: registros.length, registros });
    } catch (error) {
        console.error("Error al obtener todos los registros:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor." });
    }
});

/**
 * Obtener pendientes de validación.
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/admin/validacion/pendientes', autenticarToken, verificaradmin, async (req, res) => {
    try {
        console.log('Fetching pending validations...');
        
        // Query without orderBy to avoid index issues
        const snapshot = await db.collection('arboles')
            .where('estadovalidacion', '==', 'Pendiente')
            .get();

        const registros = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        console.log(`Found ${registros.length} pending registrations`);
        
        // If no records found, get diagnostic info
        if (registros.length === 0) {
            console.warn("No records found with 'Pendiente' status");
            
            // Get all records for diagnostic
            const allSnapshot = await db.collection('arboles').limit(100).get();
            const allRecords = allSnapshot.docs.map(doc => doc.data());
            
            // Count status distribution
            const statusCount = {};
            allRecords.forEach(r => {
                const status = (r.estadovalidacion || 'undefined').toLowerCase();
                statusCount[status] = (statusCount[status] || 0) + 1;
            });
            
            console.log('Total records in arboles collection:', allRecords.length);
            console.log('Status distribution:', statusCount);
        }
        
        res.status(200).json({ 
            ok: true, 
            registros,
            total: registros.length 
        });

    } catch (error) {
        console.error("Error al obtener registros pendientes:", error);
        console.error("Error details:", error.message, error.stack);
        
        // Try to provide helpful error message
        let errorMessage = "Error interno del servidor.";
        if (error.code) {
            errorMessage += ` Código: ${error.code}`;
        }
        if (error.message) {
            errorMessage += ` Mensaje: ${error.message}`;
        }
        
        res.status(500).json({ ok: false, mensaje: errorMessage });
    }
});

/**
 * Endpoint para actualizar el estado de validación (Aprobar/Rechazar).
 * 💡 RUTA PROTEGIDA
 */
app.patch('/api/admin/validacion/:id', autenticarToken, verificaradmin, async (req, res) => {
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

// ===================================
// 👥 GESTIÓN DE USUARIOS Y ROLES
// ===================================

/**
 * Obtener todos los usuarios
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/admin/usuarios', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const snapshot = await db.collection('usuarios').get();
        
        const usuarios = await Promise.all(snapshot.docs.map(async (doc) => {
            const userData = doc.data();
            
            // Get additional info from Firebase Auth
            let authInfo = { disabled: false };
            try {
                const authUser = await admin.auth().getUser(doc.id);
                authInfo = { disabled: authUser.disabled };
            } catch (authError) {
                console.warn(`Could not get auth info for ${doc.id}`);
            }
            
            return {
                uid: doc.id,
                ...userData,
                activo: !authInfo.disabled
            };
        }));
        
        res.status(200).json({ ok: true, usuarios });
    } catch (error) {
        console.error("Error al obtener usuarios:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener usuarios." });
    }
});

/**
 * Actualizar usuario (rol y/o estado)
 * 💡 RUTA PROTEGIDA
 */
app.patch('/api/admin/usuarios/:uid', autenticarToken, verificaradmin, async (req, res) => {
    const uid = req.params.uid;
    const { nuevorol, estado } = req.body;

    if (!nuevorol && !estado) {
        return res.status(400).json({ mensaje: "Debe especificar un nuevo rol o estado." });
    }

    try {
        const dataactualizar = {};
        
        if (nuevorol) {
            // Validate role
            const rolesValidos = ['Voluntario', 'Administrador', 'Gobierno'];
            if (!rolesValidos.includes(nuevorol)) {
                return res.status(400).json({ mensaje: "Rol inválido. Roles válidos: Voluntario, Administrador, Gobierno" });
            }
            dataactualizar.rol = nuevorol;
        }
        
        if (estado === 'activo' || estado === 'inactivo') {
            await admin.auth().updateUser(uid, { disabled: estado === 'inactivo' });
        }

        await db.collection('usuarios').doc(uid).update(dataactualizar);

        res.status(200).json({ ok: true, mensaje: `Usuario ${uid} actualizado correctamente.` });
        
    } catch (error) {
        console.error("Error al actualizar usuario:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno al gestionar usuario." });
    }
});

/**
 * Eliminar usuario
 * 💡 RUTA PROTEGIDA
 */
app.delete('/api/admin/usuarios/:uid', autenticarToken, verificaradmin, async (req, res) => {
    const uid = req.params.uid;
    
    try {
        // Delete from Firestore
        await db.collection('usuarios').doc(uid).delete();
        
        // Delete from Firebase Auth
        try {
            await admin.auth().deleteUser(uid);
        } catch (authError) {
            console.warn(`Could not delete from auth: ${authError.message}`);
        }
        
        res.status(200).json({ ok: true, mensaje: `Usuario ${uid} eliminado correctamente.` });
    } catch (error) {
        console.error("Error al eliminar usuario:", error);
        res.status(500).json({ ok: false, mensaje: "Error al eliminar usuario." });
    }
});


// ===================================
// 🎯 GESTIÓN DE CAMPANAS Y RETOS
// ===================================

/**
 * Crear una nueva campaña/reto
 * 💡 RUTA PROTEGIDA
 */
app.post('/api/admin/campanas', autenticarToken, verificaradmin, async (req, res) => {
    const { titulo, descripcion, tipo, objetivos, fechaInicio, fechaFin, criterios } = req.body;
    
    // Validaciones básicas
    if (!titulo || !descripcion) {
        return res.status(400).json({ mensaje: "Título y descripción son obligatorios." });
    }
    
    try {
        const nuevaCampana = {
            titulo,
            descripcion,
            tipo: tipo || 'Reto',
            objetivos: objetivos || [],
            fechaInicio: fechaInicio ? new Date(fechaInicio) : new Date(),
            fechaFin: fechaFin ? new Date(fechaFin) : null,
            criterios: criterios || {},
            activa: true,
            fechaCreacion: new Date(),
            fechaActualizacion: new Date()
        };
        
        const docRef = await db.collection('campanas').add(nuevaCampana);
        
        console.log(`Campaña creada: ${docRef.id}`);
        
        res.status(201).json({ 
            ok: true, 
            mensaje: "Campaña creada exitosamente.",
            id: docRef.id 
        });
    } catch (error) {
        console.error("Error al crear campaña:", error);
        res.status(500).json({ ok: false, mensaje: "Error al crear campaña." });
    }
});

/**
 * Obtener todas las campañas
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/admin/campanas', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const snapshot = await db.collection('campanas')
            .orderBy('fechaCreacion', 'desc')
            .get();
        
        const campanas = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        res.status(200).json({ ok: true, campanas });
    } catch (error) {
        console.error("Error al obtener campañas:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener campañas." });
    }
});

/**
 * Obtener campañas activas para voluntarios (Ruta pública, no requiere token)
 */
app.get('/api/campanas/activas', async (req, res) => {
    try {
        const snapshot = await db.collection('campanas')
            .where('activa', '==', true)
            .orderBy('fechaCreacion', 'desc')
            .get();
        
        const campanas = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        res.status(200).json({ ok: true, campanas });
    } catch (error) {
        console.error("Error al obtener campañas activas:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener campañas." });
    }
});

/**
 * Actualizar campaña
 * 💡 RUTA PROTEGIDA
 */
app.patch('/api/admin/campanas/:id', autenticarToken, verificaradmin, async (req, res) => {
    const campañaId = req.params.id;
    const updates = req.body;
    
    if (!updates || Object.keys(updates).length === 0) {
        return res.status(400).json({ mensaje: "No se proporcionaron datos para actualizar." });
    }
    
    try {
        updates.fechaActualizacion = new Date();
        
        await db.collection('campanas').doc(campañaId).update(updates);
        
        res.status(200).json({ ok: true, mensaje: "Campaña actualizada correctamente." });
    } catch (error) {
        console.error("Error al actualizar campaña:", error);
        res.status(500).json({ ok: false, mensaje: "Error al actualizar campaña." });
    }
});

/**
 * Eliminar campaña
 * 💡 RUTA PROTEGIDA
 */
app.delete('/api/admin/campanas/:id', autenticarToken, verificaradmin, async (req, res) => {
    const campañaId = req.params.id;
    
    try {
        await db.collection('campanas').doc(campañaId).delete();
        
        res.status(200).json({ ok: true, mensaje: "Campaña eliminada correctamente." });
    } catch (error) {
        console.error("Error al eliminar campaña:", error);
        res.status(500).json({ ok: false, mensaje: "Error al eliminar campaña." });
    }
});

/**
 * Registrar progreso de reto por voluntario
 * 💡 RUTA PROTEGIDA
 */
app.post('/api/voluntario/progreso', autenticarToken, async (req, res) => {
    // Usamos el ID verificado del token
    const voluntarioId = req.uid; 
    const { campanaId, progreso, observaciones } = req.body;
    
    if (!voluntarioId || !campanaId || progreso === undefined) {
        return res.status(400).json({ mensaje: "Datos incompletos." });
    }
    
    try {
        const progresoData = {
            voluntarioId,
            campanaId,
            progreso,
            observaciones: observaciones || '',
            fechaRegistro: new Date()
        };
        
        const docRef = await db.collection('progresoRetos').add(progresoData);
        
        res.status(201).json({ 
            ok: true, 
            mensaje: "Progreso registrado correctamente.",
            id: docRef.id 
        });
    } catch (error) {
        console.error("Error al registrar progreso:", error);
        res.status(500).json({ ok: false, mensaje: "Error al registrar progreso." });
    }
});

/**
 * Obtener progreso de voluntarios en una campaña
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/admin/campanas/:id/progreso', autenticarToken, verificaradmin, async (req, res) => {
    const campanaId = req.params.id;
    
    try {
        const snapshot = await db.collection('progresoRetos')
            .where('campanaId', '==', campanaId)
            .get();
        
        const progresoData = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        res.status(200).json({ ok: true, progreso: progresoData });
    } catch (error) {
        console.error("Error al obtener progreso:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener progreso." });
    }
});

/**
 * Obtener retos y reconocimientos de un voluntario
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/voluntario/mis-reto', autenticarToken, async (req, res) => {
    // Usamos el ID verificado del token
    const voluntarioId = req.uid; 
    
    if (!voluntarioId) {
        // Esto no debería suceder si autenticarToken funciona, pero es un buen fallback
        return res.status(400).json({ mensaje: "voluntarioId es requerido." });
    }
    
    try {
        // Get progress records for this volunteer
        const snapshot = await db.collection('progresoRetos')
            .where('voluntarioId', '==', voluntarioId)
            .get();
        
        const misProgresos = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        // Get active campaigns
        const campanasSnapshot = await db.collection('campanas')
            .where('activa', '==', true)
            .get();
        
        const campanas = campanasSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        res.status(200).json({ 
            ok: true, 
            campanas,
            misProgresos 
        });
    } catch (error) {
        console.error("Error al obtener mis retos:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener retos." });
    }
});


// ===================================
// 📅 GESTIÓN DE EVENTOS
// ===================================

/**
 * Crear un nuevo evento
 * 💡 RUTA PROTEGIDA
 */
app.post('/api/admin/eventos', autenticarToken, verificaradmin, async (req, res) => {
    const { titulo, descripcion, fecha, hora, ubicacion, activo } = req.body;
    
    if (!titulo || !descripcion) {
        return res.status(400).json({ mensaje: "Título y descripción son obligatorios." });
    }
    
    try {
        const nuevoEvento = {
            titulo,
            descripcion,
            fecha: fecha || null,
            hora: hora || null,
            ubicacion: ubicacion || '',
            activo: activo !== undefined ? activo : true,
            fechaCreacion: new Date(),
            fechaActualizacion: new Date()
        };
        
        const docRef = await db.collection('eventos').add(nuevoEvento);
        
        console.log(`Evento creado: ${docRef.id}`);
        
        res.status(201).json({ 
            ok: true, 
            mensaje: "Evento creado exitosamente.",
            id: docRef.id 
        });
    } catch (error) {
        console.error("Error al crear evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error al crear evento." });
    }
});

/**
 * Obtener todos los eventos
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/admin/eventos', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const snapshot = await db.collection('eventos')
            .orderBy('fechaCreacion', 'desc')
            .get();
        
        const eventos = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        res.status(200).json({ ok: true, eventos });
    } catch (error) {
        console.error("Error al obtener eventos:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener eventos." });
    }
});

/**
 * Obtener eventos activos para voluntarios (Ruta pública, no requiere token)
 */
app.get('/api/eventos/activos', async (req, res) => {
    try {
        console.log('Fetching active events...');
        
        // Try with orderBy first, but handle missing index
        let snapshot;
        try {
            snapshot = await db.collection('eventos')
                .where('activo', '==', true)
                .orderBy('fecha', 'asc')
                .get();
        } catch (orderError) {
            // If orderBy fails due to missing index, query without ordering
            console.warn("Index missing for fecha, querying without order:", orderError.message);
            snapshot = await db.collection('eventos')
                .where('activo', '==', true)
                .get();
        }
        
        const eventos = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        
        // Sort manually if no orderBy was used
        if (snapshot.docs.length > 0 && !snapshot.docs[0].data().fecha?.seconds) {
            eventos.sort((a, b) => {
                const fechaA = a.fecha || '';
                const fechaB = b.fecha || '';
                return fechaA.localeCompare(fechaB);
            });
        }
        
        console.log(`Found ${eventos.length} active events`);
        res.status(200).json({ ok: true, eventos });
        
    } catch (error) {
        console.error("Error al obtener eventos activos:", error);
        console.error("Error details:", error.message, error.stack);
        
        let errorMessage = "Error al obtener eventos.";
        if (error.message) {
            errorMessage += ` ${error.message}`;
        }
        
        res.status(500).json({ ok: false, mensaje: errorMessage });
    }
});

/**
 * Eliminar evento
 * 💡 RUTA PROTEGIDA
 */
app.delete('/api/admin/eventos/:id', autenticarToken, verificaradmin, async (req, res) => {
    const eventoId = req.params.id;
    
    try {
        await db.collection('eventos').doc(eventoId).delete();
        
        res.status(200).json({ ok: true, mensaje: "Evento eliminado correctamente." });
    } catch (error) {
        console.error("Error al eliminar evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error al eliminar evento." });
    }
});

/**
 * Actualizar evento
 * 💡 RUTA PROTEGIDA
 */
app.patch('/api/admin/eventos/:id', autenticarToken, verificaradmin, async (req, res) => {
    const eventoId = req.params.id;
    const updates = req.body;
    
    if (!updates || Object.keys(updates).length === 0) {
        return res.status(400).json({ mensaje: "No se proporcionaron datos para actualizar." });
    }
    
    try {
        updates.fechaActualizacion = new Date();
        
        await db.collection('eventos').doc(eventoId).update(updates);
        
        res.status(200).json({ ok: true, mensaje: "Evento actualizado correctamente." });
    } catch (error) {
        console.error("Error al actualizar evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error al actualizar evento." });
    }
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
