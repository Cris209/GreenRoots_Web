const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const axios = require("axios");
const validator = require('validator'); // Requiere 'npm install validator'
const multer = require('multer'); // 🚨 NUEVO: Para manejar archivos (fotos)

// ===================================
// CONFIGURACIÓN INICIAL DE EXPRESS Y FIREBASE
// ===================================

const app = express();
app.use(cors());
app.use(express.json());

// 🚨 CONFIGURACIÓN DE MULTER: Almacenamiento en memoria para simular
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

// 🚨 Almacenamiento temporal para el bloqueo de sesiones (Rate Limiting)
const loginAttempts = {}; // { email: { count: 0, time: Date } }
const MAX_ATTEMPTS = 3;
const LOCKOUT_TIME_MS = 10 * 60 * 1000; // Bloqueo de 10 minutos (AJUSTAR AQUÍ SI ES NECESARIO)

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

// 🚨 NUEVA FUNCIÓN: Middleware de Verificación de Administrador (Simulación)
// En producción, esto debería validar el JWT o el token de sesión.
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
// RUTAS DE AUTENTICACIÓN (Sin Modificaciones)
// ===================================
// ... (Tus rutas de /api/registro y /api/login permanecen sin cambios) ...

// 📌 Ruta: REGISTRO
app.post("/api/registro", async (req, res) => {
    const { nombre, email, password, rol } = req.body;
    // ... (Tu código de registro existente) ...
});


// 📌 Ruta: LOGIN
app.post("/api/login", async (req, res) => {
    // ... (Tu código de login existente) ...
});

// ===================================
// 🌳 RUTAS DEL VOLUNTARIO (Colección 'Arboles')
// ===================================

/**
 * Endpoint para registrar un árbol plantado, con foto y GPS.
 * Usa multer.single('evidenciaFoto') para procesar el archivo.
 */
app.post('/api/arboles/registrar', upload.single('evidenciaFoto'), async (req, res) => {
    // NOTA: req.body ahora contiene solo los campos de texto
    const { voluntarioId, tipoArbol, ubicacionGps } = req.body; 
    const fotoFile = req.file; // Contiene el archivo subido

    // 1. Validaciones
    if (!voluntarioId || !tipoArbol || !ubicacionGps || !fotoFile) {
        return res.status(400).json({ mensaje: "Faltan datos obligatorios (ID, Tipo, GPS o Foto)." });
    }

    try {
        // 🚨 SIMULACIÓN DE SUBIDA A FIREBASE STORAGE
        // En producción: Aquí subirías req.file.buffer a Firebase Storage
        const simulatedFileName = `${voluntarioId}_${Date.now()}.jpg`;
        const fotoUrl = `https://storage.firebase.com/v0/b/greenroots.appspot.com/o/${simulatedFileName}`; 

        // 2. Guardar en Firestore
        const nuevoRegistro = {
            voluntarioId: voluntarioId, // ID del voluntario
            tipoDeArbol: tipoArbol,
            ubicacion: ubicacionGps, // Formato: "Lat, Lon"
            fotoUrl: fotoUrl, 
            fechaRegistro: new Date(),
            estadoValidacion: 'Pendiente' // Estado inicial para el Administrador
        };

        const docRef = await db.collection('Arboles').add(nuevoRegistro);
        
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
    // 🚨 NOTA: Se devolverían los retos desde una colección 'Retos' y el progreso del usuario.
    const retosActivos = [
        { id: 1, titulo: "Maratón de Riego", descripcion: "Riega 10 árboles en la Zona Norte.", completado: false },
        { id: 2, titulo: "Especie Rara", descripcion: "Planta al menos 3 Cedros.", completado: true },
    ];
    const reconocimientos = ["Voluntario del Mes (Octubre)", "Experto en Reforestación"];
    
    res.status(200).json({ retosActivos, reconocimientos });
});

// ===================================
// ⚙️ RUTAS DEL ADMINISTRADOR
// ===================================

/**
 * Endpoint para obtener todos los registros de árboles pendientes de validación.
 * Protegido por checkAdmin.
 */
app.get('/api/admin/validacion/pendientes', checkAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('Arboles')
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
        await db.collection('Arboles').doc(registroId).update(updateData);
        
        // 🚨 Opcional: Lógica para enviar notificación al voluntario (ej. email)
        
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
    const uid = req.params.uid;
    const { nuevoRol, estado } = req.body;

    if (!nuevoRol && !estado) {
        return res.status(400).json({ mensaje: "Debe especificar un nuevo rol o estado." });
    }

    try {
        const updateData = {};
        if (nuevoRol) {
            updateData.rol = nuevoRol;
            // Opcional: Actualizar el custom claim en Firebase Auth si fuera necesario
            // await admin.auth().setCustomUserClaims(uid, { rol: nuevoRol });
        }
        if (estado === 'activo' || estado === 'inactivo') {
            // Suponemos que 'estado' controla la cuenta
            await admin.auth().updateUser(uid, { disabled: estado === 'inactivo' });
        }

        await db.collection('usuarios').doc(uid).update(updateData);

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
