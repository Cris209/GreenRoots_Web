const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const axios = require("axios");
const validator = require('validator');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken'); // Para la generación interna de IDs de sensor simulados

// ===================================
// CONFIGURACIÓN INICIAL DE EXPRESS Y FIREBASE
// ===================================

const app = express();
const PORT = process.env.PORT || 3000;

// Variables de entorno (ASUMIMOS que están disponibles en el entorno de ejecución)
// **NOTA:** En un entorno real (como Heroku o Google Cloud), estas deben ser cargadas de forma segura.
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY || "TU_FIREBASE_WEB_API_KEY_AQUI"; // Usado para login/registro REST
const FIREBASE_KEY = process.env.FIREBASE_KEY; // Objeto JSON de credenciales de Firebase Admin (requerido para admin)
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || "tu_cloud_name";
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || "tu_api_key";
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || "tu_api_secret";
const SECRET_JWT_KEY = process.env.SECRET_JWT_KEY || "clave_secreta_para_sensores";

// Inicialización de Firebase Admin
try {
    // Si FIREBASE_KEY es una cadena JSON, la parseamos. Si no, asumimos que fallará la inicialización.
    const serviceAccount = JSON.parse(FIREBASE_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log("Firebase Admin SDK inicializado exitosamente.");
} catch (error) {
    console.error("Error al inicializar Firebase Admin SDK. Asegúrate de que FIREBASE_KEY contenga el JSON de credenciales:", error.message);
    // En producción, esto debería ser un error fatal. Para el sandbox, mostramos la advertencia.
    // process.exit(1); 
}

const db = admin.firestore(); // Referencia a Firestore

// Inicialización de Cloudinary
cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
});
console.log("Cloudinary configurado.");

// Configuración de CORS
const corsOptions = {
    origin: '*', 
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Rol'], 
    credentials: false
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CONFIGURACIÓN DE MULTER para subir archivos en memoria
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Límite de 5MB
});


// ===================================
// MIDDLEWARE DE AUTENTICACIÓN Y AUTORIZACIÓN
// ===================================

/**
 * Middleware para autenticar el token de Firebase.
 */
const autenticarToken = async (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) {
        return res.status(401).json({ ok: false, mensaje: "Se requiere token de autenticación." });
    }

    const token = header.split(" ")[1];
    if (!token) {
        return res.status(401).json({ ok: false, mensaje: "Formato de token inválido." });
    }

    try {
        // Verificar y decodificar el ID token de Firebase
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;

        // Opcional: Cargar el rol desde Firestore si no está en el token (aunque se recomienda usar Custom Claims)
        if (!req.user.role) {
            const userDoc = await db.collection('usuarios').doc(decodedToken.uid).get();
            if (userDoc.exists) {
                req.user.role = userDoc.data().role;
            }
        }
        
        next();
    } catch (error) {
        console.error("Error al verificar token:", error.message);
        return res.status(403).json({ ok: false, mensaje: "Token inválido o expirado." });
    }
};

/**
 * Middleware para verificar si el usuario es Administrador.
 */
const verificarAdmin = (req, res, next) => {
    // Intentar obtener el rol del token (Custom Claim) o del objeto user cargado
    const userRole = req.user.role; 
    
    if (userRole && userRole === 'Administrador') {
        next();
    } else {
        return res.status(403).json({ ok: false, mensaje: "Acceso denegado. Se requiere rol de Administrador." });
    }
};


// ===================================
// HELPERS (Funciones de Soporte)
// ===================================

/**
 * Sube un buffer de imagen a Cloudinary.
 * @param {Buffer} buffer - Buffer de la imagen.
 * @param {string} folder - Carpeta en Cloudinary.
 * @returns {Promise<string>} URL segura de la imagen.
 */
function uploadImageToCloudinary(buffer, folder) {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            { 
                folder: `greenroots/${folder}`,
                tags: [folder, 'greenroots'],
                // Usar 'webp' o 'jpg' para optimización web
                format: 'webp' 
            },
            (error, result) => {
                if (error) {
                    console.error("Cloudinary Error:", error);
                    return reject(new Error("Error al subir imagen a Cloudinary."));
                }
                resolve(result.secure_url);
            }
        );
        uploadStream.end(buffer);
    });
}

/**
 * Simula la obtención de datos de un sensor IoT.
 * @param {string} sensorId - El ID del sensor.
 * @returns {Object} Datos simulados.
 */
function simulateSensorData(sensorId) {
    // Generar datos aleatorios consistentes basados en el sensorId para simular un historial
    // Usamos el hash del sensorId para crear una semilla pseudo-aleatoria
    let hash = 0;
    for (let i = 0; i < sensorId.length; i++) {
        hash = sensorId.charCodeAt(i) + ((hash << 5) - hash);
    }
    const seed = Math.abs(hash % 100) / 100;

    // Valores base para una planta saludable
    const baseHumedad = 70;
    const baseTemperatura = 22;
    const baseLuz = 800;
    const basePH = 6.5;

    // Aplicar fluctuaciones basadas en la semilla
    const humedad = (baseHumedad + (Math.sin(seed * 10) * 10 + Math.random() * 5)).toFixed(2) + '%'; 
    const temperatura = (baseTemperatura + (Math.cos(seed * 8) * 3 + Math.random() * 2)).toFixed(1) + '°C'; 
    const luz = (baseLuz + (Math.sin(seed * 12) * 300 + Math.random() * 200)).toFixed(0) + ' Lux'; 
    const pH = (basePH + (Math.random() * 0.5 - 0.25)).toFixed(1);

    return {
        humedad: humedad,
        temperatura: temperatura,
        luz: luz,
        ph: pH,
        timestamp: new Date().toISOString()
    };
}


// ===================================
// RUTAS DE AUTENTICACIÓN
// ===================================

/**
 * Registro de nuevo usuario (Voluntario por defecto).
 */
app.post('/api/auth/register', async (req, res) => {
    const { email, password, nombre } = req.body;

    if (!email || !password || !nombre || !validator.isEmail(email)) {
        return res.status(400).json({ mensaje: "Datos de registro incompletos o inválidos." });
    }

    try {
        // 1. Crear usuario en Firebase Auth
        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName: nombre,
        });

        // 2. Establecer el rol por defecto (Voluntario) como Custom Claim
        await admin.auth().setCustomUserClaims(userRecord.uid, { role: 'Voluntario' });

        // 3. Crear documento de usuario en Firestore
        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            email: email,
            nombre: nombre,
            role: 'Voluntario',
            creadoEn: admin.firestore.FieldValue.serverTimestamp(),
        });

        res.status(201).json({ ok: true, mensaje: "Usuario registrado exitosamente como Voluntario." });

    } catch (error) {
        console.error("Error en el registro:", error.code, error.message);
        let mensaje = "Error al registrar usuario.";
        if (error.code === 'auth/email-already-in-use') {
            mensaje = "El correo electrónico ya está en uso.";
        }
        res.status(400).json({ ok: false, mensaje });
    }
});

/**
 * Inicio de sesión. Utiliza la REST API de Firebase para obtener el ID Token.
 */
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ mensaje: "Faltan credenciales." });
    }

    try {
        // 1. Autenticar usando la REST API de Firebase (requiere FIREBASE_WEB_API_KEY)
        const firebaseAuthUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
        const authResponse = await axios.post(firebaseAuthUrl, {
            email,
            password,
            returnSecureToken: true,
        });

        const idToken = authResponse.data.idToken;
        const refreshToken = authResponse.data.refreshToken;
        
        // 2. Obtener información del usuario y rol desde el ID Token para garantizar el Claim más reciente
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const userDoc = await db.collection('usuarios').doc(decodedToken.uid).get();
        
        if (!userDoc.exists) {
            return res.status(404).json({ mensaje: "Datos de usuario no encontrados en Firestore." });
        }
        
        const userData = userDoc.data();
        const role = userData.role || 'Voluntario'; 

        res.status(200).json({
            ok: true,
            mensaje: "Inicio de sesión exitoso.",
            token: idToken,
            email: userData.email,
            nombre: userData.nombre,
            role: role,
            uid: decodedToken.uid,
            refreshToken: refreshToken 
        });

    } catch (error) {
        // Manejo de errores de autenticación de Firebase
        const errorMessage = error.response?.data?.error?.message || error.message;
        console.error("Error en el inicio de sesión:", errorMessage);
        let mensaje = "Credenciales incorrectas o usuario no encontrado.";
        res.status(401).json({ ok: false, mensaje });
    }
});


// ===================================
// RUTAS DE GESTIÓN DE USUARIOS (ADMINISTRADOR)
// ===================================

/**
 * Listar todos los usuarios.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.get('/api/admin/usuarios', autenticarToken, verificarAdmin, async (req, res) => {
    try {
        // Obtener todos los documentos de la colección 'usuarios'
        const usersSnapshot = await db.collection('usuarios').get();
        const users = usersSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.status(200).json({ ok: true, usuarios: users });

    } catch (error) {
        console.error("Error al listar usuarios:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al listar usuarios." });
    }
});

/**
 * Actualizar el rol o estado de un usuario.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.patch('/api/admin/usuarios/:uid', autenticarToken, verificarAdmin, async (req, res) => {
    const { uid } = req.params;
    const { role } = req.body;

    if (!role || (role !== 'Voluntario' && role !== 'Administrador')) {
        return res.status(400).json({ mensaje: "Rol inválido proporcionado. Debe ser 'Voluntario' o 'Administrador'." });
    }

    try {
        // 1. Actualizar Custom Claims en Firebase Auth (fuerza la actualización del token en el próximo login)
        await admin.auth().setCustomUserClaims(uid, { role });

        // 2. Actualizar documento en Firestore
        await db.collection('usuarios').doc(uid).update({ 
            role: role,
            fechaActualizacion: admin.firestore.FieldValue.serverTimestamp()
        });
        
        // 3. Opcional: Revocar tokens de sesión actuales para forzar re-login y obtención de nuevo token con el claim actualizado
        await admin.auth().revokeRefreshTokens(uid);
        console.log(`Tokens de sesión revocados para el usuario ${uid}.`);

        res.status(200).json({ ok: true, mensaje: `Rol de usuario ${uid} actualizado a ${role}. Los usuarios deberán volver a iniciar sesión.` });

    } catch (error) {
        console.error("Error al actualizar rol:", error);
        res.status(500).json({ ok: false, mensaje: "Error al actualizar el rol del usuario." });
    }
});


// ===================================
// RUTAS DE GESTIÓN DE ÁRBOLES
// ===================================

/**
 * Ruta para que el Voluntario registre un nuevo árbol (Pendiente).
 * 💡 RUTA PROTEGIDA (VOLUNTARIO)
 */
app.post('/api/arboles', autenticarToken, upload.single('imagen'), async (req, res) => {
    const { especie, descripcion, latitud, longitud } = req.body;
    const userId = req.user.uid;
    const file = req.file;

    if (!especie || !descripcion || !latitud || !longitud || !file) {
        return res.status(400).json({ mensaje: "Datos incompletos para el registro del árbol." });
    }
    
    const lat = parseFloat(latitud);
    const lng = parseFloat(longitud);
    if (isNaN(lat) || isNaN(lng)) {
        return res.status(400).json({ mensaje: "Latitud o Longitud inválida." });
    }

    try {
        // 1. Verificar si el usuario ya tiene un árbol pendiente/aprobado
        const existingTreeSnapshot = await db.collection('arboles')
            .where('uid', '==', userId)
            .where('estado', 'in', ['pendiente', 'aprobado']) // Solo permitimos 1 árbol activo
            .get();

        if (!existingTreeSnapshot.empty) {
            return res.status(400).json({ mensaje: "Ya tienes un árbol registrado (pendiente o aprobado). Espera la validación o elimina el anterior." });
        }
        
        // 2. Subir imagen a Cloudinary
        const imageUrl = await uploadImageToCloudinary(file.buffer, 'arboles');
        
        // 3. Crear registro del árbol en Firestore
        const newTreeRef = await db.collection('arboles').add({
            uid: userId,
            especie,
            descripcion,
            latitud: lat,
            longitud: lng,
            imagenUrl: imageUrl,
            estado: 'pendiente', // Por defecto
            fechaRegistro: admin.firestore.FieldValue.serverTimestamp(),
            fechaValidacion: null,
            sensorId: null,
            validadoPor: null
        });

        res.status(201).json({ ok: true, mensaje: "Árbol registrado exitosamente. Pendiente de validación.", id: newTreeRef.id });

    } catch (error) {
        console.error("Error al registrar árbol:", error.message);
        // Si el error es por tamaño de archivo, se puede atrapar aquí
        if (error.code === 'LIMIT_FILE_SIZE') {
             res.status(400).json({ ok: false, mensaje: "El archivo es demasiado grande (máx 5MB)." });
        } else {
             res.status(500).json({ ok: false, mensaje: "Error interno del servidor al registrar el árbol." });
        }
    }
});

/**
 * Obtener mi árbol (para Voluntario). Incluye datos simulados del sensor si está aprobado.
 * 💡 RUTA PROTEGIDA (VOLUNTARIO)
 */
app.get('/api/arboles/mi-arbol', autenticarToken, async (req, res) => {
    const userId = req.user.uid;

    try {
        const snapshot = await db.collection('arboles')
            .where('uid', '==', userId)
            .where('estado', 'in', ['pendiente', 'aprobado']) // Buscamos el árbol activo
            .orderBy('fechaRegistro', 'desc')
            .limit(1)
            .get();

        if (snapshot.empty) {
            return res.status(200).json({ ok: true, arbol: null, datosSensor: null }); // No hay árbol registrado
        }

        const arbolDoc = snapshot.docs[0];
        const arbol = { id: arbolDoc.id, ...arbolDoc.data() };
        let datosSensor = null;

        if (arbol.estado === 'aprobado' && arbol.sensorId) {
            // Obtener datos simulados del sensor
            datosSensor = simulateSensorData(arbol.sensorId);
        }

        res.status(200).json({ ok: true, arbol: arbol, datosSensor: datosSensor });

    } catch (error) {
        console.error("Error al obtener el árbol del usuario:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener el estado del árbol." });
    }
});

/**
 * Obtener todos los árboles pendientes de validación.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.get('/api/admin/arboles/pendientes', autenticarToken, verificarAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('arboles')
            .where('estado', '==', 'pendiente')
            .orderBy('fechaRegistro', 'asc')
            .get();

        const arbolesPendientes = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            // Formatear la fecha para facilitar el uso en el frontend
            fechaRegistro: doc.data().fechaRegistro ? doc.data().fechaRegistro.toDate().toISOString() : null
        }));

        res.status(200).json({ ok: true, arboles: arbolesPendientes });

    } catch (error) {
        console.error("Error al obtener árboles pendientes:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener la lista de árboles pendientes." });
    }
});

/**
 * Validar o rechazar un árbol (Admin). Asigna un ID de sensor simulado al validar.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.patch('/api/admin/arboles/validar/:id', autenticarToken, verificarAdmin, async (req, res) => {
    const treeId = req.params.id;
    const { estado } = req.body; // Debe ser 'aprobado' o 'rechazado'
    const adminId = req.user.uid;

    if (estado !== 'aprobado' && estado !== 'rechazado') {
        return res.status(400).json({ mensaje: "Estado de validación inválido. Debe ser 'aprobado' o 'rechazado'." });
    }

    try {
        const treeRef = db.collection('arboles').doc(treeId);
        const treeDoc = await treeRef.get();

        if (!treeDoc.exists || treeDoc.data().estado !== 'pendiente') {
            return res.status(404).json({ mensaje: "Árbol no encontrado o ya validado." });
        }

        let updateData = {
            estado: estado,
            fechaValidacion: admin.firestore.FieldValue.serverTimestamp(),
            validadoPor: adminId
        };
        
        // Si es aprobado, generar un ID de sensor único (simulado)
        if (estado === 'aprobado') {
            // Generamos un ID de sensor único y fácil de reconocer.
            const sensorId = jwt.sign({ treeId: treeId, iat: Date.now() }, SECRET_JWT_KEY, { algorithm: 'HS256' });
            // Tomamos una parte para hacerlo legible/corto (ej: GR-20A5B7C8D9)
            updateData.sensorId = `GR-${sensorId.substring(0, 10).toUpperCase()}`; 
        } else {
            // Si es rechazado, se elimina cualquier sensorId potencial (aunque no debería tenerlo)
            updateData.sensorId = null; 
        }

        await treeRef.update(updateData);

        res.status(200).json({ 
            ok: true, 
            mensaje: `Árbol ${treeId} marcado como ${estado}.`, 
            sensorId: updateData.sensorId || null 
        });

    } catch (error) {
        console.error("Error al validar árbol:", error);
        res.status(500).json({ ok: false, mensaje: "Error al procesar la validación del árbol." });
    }
});


// ===================================
// RUTAS DE GESTIÓN DE EVENTOS
// ===================================

/**
 * Listar todos los eventos (Público/Voluntario).
 */
app.get('/api/eventos', async (req, res) => {
    try {
        // Solo eventos futuros
        const snapshot = await db.collection('eventos')
            .where('fecha', '>=', new Date()) 
            .orderBy('fecha', 'asc')
            .get();

        const eventos = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            // Formatear la fecha para facilitar el uso en el frontend
            fecha: doc.data().fecha ? doc.data().fecha.toDate().toISOString() : null
        }));

        res.status(200).json({ ok: true, eventos });

    } catch (error) {
        console.error("Error al listar eventos:", error);
        res.status(500).json({ ok: false, mensaje: "Error al obtener la lista de eventos." });
    }
});

/**
 * Crear un nuevo evento.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.post('/api/admin/eventos', autenticarToken, verificarAdmin, async (req, res) => {
    const { titulo, descripcion, ubicacion, fecha } = req.body;

    if (!titulo || !descripcion || !ubicacion || !fecha || isNaN(new Date(fecha).getTime())) {
        return res.status(400).json({ mensaje: "Datos de evento incompletos o fecha inválida." });
    }
    
    try {
        const newEvent = {
            titulo,
            descripcion,
            ubicacion,
            fecha: new Date(fecha), // Guardar como timestamp de Firestore
            creadoPor: req.user.uid,
            fechaCreacion: admin.firestore.FieldValue.serverTimestamp(),
        };

        const eventRef = await db.collection('eventos').add(newEvent);

        res.status(201).json({ ok: true, mensaje: "Evento creado exitosamente.", id: eventRef.id });
    } catch (error) {
        console.error("Error al crear evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al crear evento." });
    }
});

/**
 * Eliminar evento.
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.delete('/api/admin/eventos/:id', autenticarToken, verificarAdmin, async (req, res) => {
    const eventoId = req.params.id;
    
    try {
        const docRef = db.collection('eventos').doc(eventoId);
        const doc = await docRef.get();
        
        if (!doc.exists) {
            return res.status(404).json({ ok: false, mensaje: "Evento no encontrado." });
        }
        
        await docRef.delete();
        
        res.status(200).json({ ok: true, mensaje: "Evento eliminado correctamente." });
    } catch (error) {
        console.error("Error al eliminar evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error al eliminar evento." });
    }
});

/**
 * Actualizar evento
 * 💡 RUTA PROTEGIDA (ADMIN)
 */
app.patch('/api/admin/eventos/:id', autenticarToken, verificarAdmin, async (req, res) => {
    const eventoId = req.params.id;
    const updates = req.body;
    
    if (!updates || Object.keys(updates).length === 0) {
        return res.status(400).json({ mensaje: "No se proporcionaron datos para actualizar." });
    }
    
    // Convertir la fecha si se está actualizando
    if (updates.fecha) {
        if (isNaN(new Date(updates.fecha).getTime())) {
            return res.status(400).json({ mensaje: "Fecha de evento inválida." });
        }
        updates.fecha = new Date(updates.fecha); // Guardar como timestamp
    }

    try {
        updates.fechaActualizacion = admin.firestore.FieldValue.serverTimestamp();
        
        await db.collection('eventos').doc(eventoId).update(updates);
        
        res.status(200).json({ ok: true, mensaje: "Evento actualizado correctamente." });
    } catch (error) {
        console.error("Error al actualizar evento:", error);
        res.status(500).json({ ok: false, mensaje: "Error al actualizar evento." });
    }
});


// ===================================
// RUTAS DE SIMULACIÓN DE SENSORES (PUBLIC ACCESS)
// ===================================

/**
 * Endpoint para obtener datos del sensor. Cualquier aplicación puede consultarlo.
 */
app.get('/api/sensores/data/:sensorId', async (req, res) => {
    const { sensorId } = req.params;

    if (!sensorId) {
        return res.status(400).json({ mensaje: "Se requiere un sensorId." });
    }

    try {
        // En un entorno real, aquí llamarías a la API del hardware IoT.
        // En esta simulación, generamos datos basados en el ID.
        const data = simulateSensorData(sensorId);
        res.status(200).json({ ok: true, sensorId: sensorId, data: data });
    } catch (error) {
        console.error("Error en la simulación del sensor:", error);
        res.status(500).json({ ok: false, mensaje: "Error en la simulación de datos del sensor." });
    }
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================

// Ruta de bienvenida básica
app.get('/', (req, res) => {
    res.send('Servidor Green Roots API en funcionamiento.');
});

// Manejo de rutas no encontradas (Middleware final)
app.use((req, res) => {
    res.status(404).json({ ok: false, mensaje: `Ruta no encontrada: ${req.method} ${req.originalUrl}` });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor Express escuchando en el puerto ${PORT}`);
});
