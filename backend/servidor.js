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
app.use(cors());
app.use(express.json());

// 🚨 CONFIGURACIÓN DE MULTER
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Límite de 5MB por archivo
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

// ... (Bloqueo de sesiones y Funciones de Validación de Seguridad sin cambios) ...

// 🚨 Middleware de Verificación de Administrador (Simulación)
function checkAdmin(req, res, next) {
    // Simulamos que el rol viene del token o una cabecera de prueba
    const userRole = req.headers['x-user-role']?.toLowerCase();
    if (userRole === 'administrador') {
        next();
    } else {
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
// 🌳 RUTAS DEL VOLUNTARIO (Colección 'arboles' [MINÚSCULA])
// ===================================

/**
 * Endpoint para registrar un árbol plantado.
 */
app.post('/api/arboles/registrar', upload.single('evidenciaFoto'), async (req, res) => {
    const { voluntarioId, tipoArbol, ubicacionGps } = req.body; 
    const fotoFile = req.file;

    // 1. Validaciones
    if (!voluntarioId || !tipoArbol || !ubicacionGps || !fotoFile) {
        return res.status(400).json({ mensaje: "Faltan datos obligatorios (ID, Tipo, GPS o Foto)." });
    }

    try {
        // SIMULACIÓN DE SUBIDA A FIREBASE STORAGE
        const simulatedFileName = `${voluntarioId}_${Date.now()}.jpg`;
        const fotoUrl = `https://storage.firebase.com/v0/b/greenroots.appspot.com/o/${simulatedFileName}`; 

        // 2. Guardar en Firestore en la colección 'arboles'
        const nuevoRegistro = {
            voluntarioId: voluntarioId,
            tipoDeArbol: tipoArbol,
            ubicacion: ubicacionGps,
            fotoUrl: fotoUrl, 
            fechaRegistro: new Date(),
            estadoValidacion: 'Pendiente'
        };

        // 🚨 CAMBIO: Colección 'arboles'
        const docRef = await db.collection('arboles').add(nuevoRegistro);
        
        res.status(201).json({ 
            ok: true,
            mensaje: "Árbol registrado. Pendiente de validación.", 
            id: docRef.id 
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
    // ... (Lógica de retos simulada sin cambios) ...
});

// ===================================
// ⚙️ RUTAS DEL ADMINISTRADOR (Colección 'arboles' [MINÚSCULA])
// ===================================

/**
 * Endpoint para obtener todos los registros de árboles pendientes de validación.
 * Protegido por checkAdmin.
 */
app.get('/api/admin/validacion/pendientes', checkAdmin, async (req, res) => {
    try {
        // 🚨 CAMBIO: Colección 'arboles'
        const snapshot = await db.collection('arboles')
                                 .where('estadoValidacion', '==', 'Pendiente')
                                 .orderBy('fechaRegistro', 'asc')
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
 * Protegido por checkAdmin.
 */
app.patch('/api/admin/validacion/:id', checkAdmin, async (req, res) => {
    const registroId = req.params.id;
    const { nuevoEstado, motivoRechazo } = req.body; 

    if (nuevoEstado !== 'Aprobado' && nuevoEstado !== 'Rechazado') {
        return res.status(400).json({ mensaje: "Estado de validación inválido." });
    }
    
    const updateData = {
        estadoValidacion: nuevoEstado,
        fechaValidacion: new Date()
    };

    if (nuevoEstado === 'Rechazado' && motivoRechazo) {
        updateData.motivoRechazo = motivoRechazo;
    }

    try {
        // 🚨 CAMBIO: Colección 'arboles'
        await db.collection('arboles').doc(registroId).update(updateData);
        
        res.status(200).json({ 
            ok: true,
            mensaje: `Registro ${registroId} actualizado a ${nuevoEstado}.` 
        });

    } catch (error) {
        console.error(`Error al validar registro ${registroId}:`, error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor." });
    }
});

/**
 * Endpoint para Gestión de Usuarios y Roles (Simulación).
 * Protegido por checkAdmin.
 */
app.patch('/api/admin/gestion/usuario/:uid', checkAdmin, async (req, res) => {
    // ... (Lógica de gestión de usuario sin cambios) ...
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
