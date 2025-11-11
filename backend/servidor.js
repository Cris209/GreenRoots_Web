const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const axios = require("axios");
const validator = require('validator');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { FieldValue } = require('firebase-admin').firestore;

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

const isValidCoordinate = (coord, isLat) => {
    const min = isLat ? -90 : -180;
    const max = isLat ? 90 : 180;
    const num = parseFloat(coord);
    
    // Debe ser un número, no NaN, y estar dentro del rango
    return !isNaN(num) && num >= min && num <= max;
};

// Variables de entorno
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;
const FIREBASE_KEY = process.env.FIREBASE_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID; // 💡 ASUME ESTA VARIABLE
const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL; // 💡 ASUME ESTA VARIABLE
const FIREBASE_STORAGE_BUCKET = process.env.FIREBASE_STORAGE_BUCKET; // 💡 ASUME ESTA VARIABLE
const FIREBASE_SENDER_ID = process.env.FIREBASE_SENDER_ID; // 💡 ASUME ESTA VARIABLE
const FIREBASE_APP_ID = process.env.FIREBASE_APP_ID; // 💡 ASUME ESTA VARIABLE
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME; // 🚨 NUEVA
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;       // 🚨 NUEVA
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;
const OPENMETEO_SOIL_API = "https://api.open-meteo.com/v1/forecast";

cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET
});

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
    
    const rolLower = rolUsuario?.toLowerCase();

    // Verificamos si el rol, en minúsculas, es 'administrador' O 'gobierno'
    if (rolLower && (rolLower === 'administrador' || rolLower === 'gobierno')) { // <-- ¡ESTE ES EL CAMBIO CLAVE!
        console.log('Admin/Gobierno access granted');
        next();
    } else {
        console.error(`Access denied. UID: ${req.uid}, Role: ${rolUsuario}`);
        // Mensaje de error más descriptivo
        res.status(403).json({ ok: false, mensaje: "Acceso denegado. Se requiere rol de Administrador o Gobierno." });
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

    // 1. Validaciones de Seguridad (Asegurar que 'rol' sea válido)
    const validaciones = [validateNombre(nombre), await validateEmail(email), validatePassword(password)];
    for (const error of validaciones) {
        if (error) return res.status(400).json({ ok: false, mensaje: error });
    }
    
    if (!rol || !['Voluntario', 'Gobierno'].includes(rol)) {
        return res.status(400).json({ ok: false, mensaje: "Rol no permitido." });
    }

    // --- LÓGICA DE VALIDACIÓN DE ROL GOBIERNO ---
    let rolFinal = rol;
    let datosAdicionales = {};
    let mensajeExito = "Usuario registrado y perfil creado correctamente";

    if (rol === 'Gobierno') {
        // Si solicita rol 'Gobierno', le asignamos 'Voluntario' temporalmente
        // y guardamos la solicitud con estado 'Pendiente'.
        rolFinal = 'Voluntario'; 
        datosAdicionales.rolSolicitado = 'Gobierno';
        datosAdicionales.estadoValidacionRol = 'Pendiente';
        mensajeExito = "Solicitud de cuenta Gobierno recibida. Se te ha asignado el rol Voluntario temporalmente. Un administrador validará tu solicitud.";
    }
    // ---------------------------------------------

    try {
        // PASO 1: CREAR USUARIO EN FIREBASE AUTH
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: nombre,
        });

        const uid = userRecord.uid;

        // PASO 2: GUARDAR PERFIL EN FIRESTORE
        // Utilizamos rolFinal y añadimos los datos adicionales si existen
        await db.collection("usuarios").doc(uid).set({
            nombre: nombre,
            email: email,
            rol: rolFinal, 
            ...datosAdicionales
        });

        res.json({ ok: true, mensaje: mensajeExito });

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
// servidor.js

/**
 * Endpoint para registrar un árbol plantado, guardando la foto en Base64 en Firestore.
 * 💡 RUTA PROTEGIDA (NO USA FIREBASE STORAGE)
 */
/**
 * Endpoint para registrar un árbol plantado usando Cloudinary.
 */
app.post('/api/arboles/registrar', autenticarToken, upload.single('evidenciaFoto'), async (req, res) => {
    
    const { tipoarbol, ubicaciongps } = req.body; 
    const voluntarioid = req.uid; 
    const fotofile = req.file; 

    if (!voluntarioid || !tipoarbol || !ubicaciongps || !fotofile) {
        return res.status(400).json({ mensaje: "Faltan datos obligatorios (Tipo, GPS o Foto)." });
    }

    try {
        // --- 🚨 Lógica de Subida a Cloudinary ---
        
        // 1. Convertir el buffer de la imagen a un Data URI (formato que Cloudinary acepta)
        const b64 = Buffer.from(fotofile.buffer).toString("base64");
        let dataURI = "data:" + fotofile.mimetype + ";base64," + b64;
        
        // 2. Definir una ID única para la imagen
        const publicId = `greenroots/arboles/${voluntarioid}_${Date.now()}`;

        // 3. Subir el Data URI a Cloudinary
        const uploadResult = await cloudinary.uploader.upload(dataURI, {
            public_id: publicId,
            folder: "greenroots_arboles" // Opcional: Organiza las fotos en una carpeta
        });
        
        // La URL de acceso público que necesitamos para guardar en Firestore
        const fotourl = uploadResult.secure_url; 
        // ------------------------------------------

        // 4. Guardar en Firestore con la URL REAL de Cloudinary
        const nuevoregistro = {
            voluntarioid: voluntarioid,
            tipodearbol: tipoarbol,
            ubicacion: ubicaciongps,
            fotourl: fotourl, // ✅ URL PÚBLICA DE CLOUDINARY
            fecharegistro: new Date(),
            estadovalidacion: 'Pendiente'
        };

        const docref = await db.collection('arboles').add(nuevoregistro);
        
        res.status(201).json({ 
            ok: true,
            mensaje: "Árbol registrado y foto subida exitosamente. Pendiente de validación.", 
            id: docref.id 
        });

    } catch (error) {
        console.error("Error general en el registro del árbol (Cloudinary):", error);
        res.status(500).json({ ok: false, mensaje: error.message || "Error interno del servidor al registrar árbol." });
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
// servidor.js

/**
 * Obtener árboles por ID de Voluntario
 * Colección: 'arboles'
 * Campo de filtro: 'voluntarioId'
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/arboles/voluntario/:voluntarioId', autenticarToken, async (req, res) => {
    const voluntarioId = req.params.voluntarioId;
    
    // **VERIFICACIÓN DE SEGURIDAD CLAVE**
    if (req.user.uid !== voluntarioId) {
        return res.status(403).json({ mensaje: "Acceso denegado: No tienes permiso para ver estos árboles." });
    }

    try {
        const arbolesRef = db.collection('arboles');
        
        // 🚨 CORRECCIÓN: Usar 'voluntarioid' (todo minúscula) para que coincida con la clave usada en el registro.
        const snapshot = await arbolesRef.where('voluntarioid', '==', voluntarioId).get();

        const arboles = [];
        snapshot.forEach(doc => {
            // Incluye el ID del documento
            arboles.push({ id: doc.id, ...doc.data() }); 
        });

        res.status(200).json({ ok: true, arboles: arboles });

    } catch (error) {
        console.error("Error al obtener árboles del voluntario:", error);
        res.status(500).json({ mensaje: "Error interno del servidor al obtener árboles." });
    }
});

//endpoint para contar los arboles registrados
app.get('/api/voluntario/arboles/count', autenticarToken, async (req, res) => {
    const voluntarioId = req.uid; // Obtenido del token autenticado por el middleware

    try {
        if (!voluntarioId) {
            return res.status(400).json({ ok: false, mensaje: "ID de voluntario no encontrado en el token." });
        }
        
        // Consulta a Firestore para obtener el número de documentos
        const snapshot = await db.collection('arboles')
                                 .where('voluntarioid', '==', voluntarioId)
                                 .get();

        const totalArboles = snapshot.size;

        res.status(200).json({ 
            ok: true, 
            totalArboles: totalArboles, // El conteo que el frontend necesita
            mensaje: `Total de árboles registrados: ${totalArboles}`
        });
        
    } catch (error) {
        console.error("Error al obtener el conteo de árboles del voluntario:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al obtener el conteo." });
    }
});

app.get('/api/arboles/mi-impacto', autenticarToken, async (req, res) => {
    const voluntarioId = req.uid; // Obtenemos el ID del token verificado
    const today = new Date();
    const sixMonthsAgo = new Date();
    // Establecer la fecha hace 5 meses para incluir 6 meses en total (el actual y los 5 anteriores)
    sixMonthsAgo.setMonth(today.getMonth() - 5); 
    sixMonthsAgo.setDate(1); // Empezar desde el primer día del mes

    try {
        const arbolesRef = db.collection('arboles');
        
        // 1. Filtrar por ID del voluntario y solo aquellos con validación 'Aprobado'
        const snapshot = await arbolesRef
            .where('voluntarioid', '==', voluntarioId)
            .where('estadovalidacion', '==', 'Aprobado') // Solo los validados como impacto
            .get();

        const arboles = snapshot.docs.map(doc => doc.data());

        // Configuración para la agregación de los últimos 6 meses
        const monthlyData = {};
        const monthNames = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];

        // Inicializar los contadores para los últimos 6 meses (incluyendo el actual)
        for (let i = 0; i < 6; i++) {
            const date = new Date();
            date.setMonth(today.getMonth() - i);
            // Formato de etiqueta: Mes/Año (Ej: Oct/25)
            const monthKey = `${monthNames[date.getMonth()]}/${date.getFullYear() % 100}`;
            monthlyData[monthKey] = 0;
        }

        arboles.forEach(arbol => {
            // Asumimos 'fecharegistro' es un Firestore Timestamp con el Admin SDK
            let date;
            if (arbol.fecharegistro && typeof arbol.fecharegistro.toDate === 'function') {
                date = arbol.fecharegistro.toDate();
            } else if (arbol.fecharegistro instanceof Date) {
                date = arbol.fecharegistro;
            } else {
                return; 
            }

            // Solo contamos los que caen dentro de los últimos 6 meses
            if (date >= sixMonthsAgo) {
                const monthKey = `${monthNames[date.getMonth()]}/${date.getFullYear() % 100}`;
                if (monthlyData.hasOwnProperty(monthKey)) {
                     monthlyData[monthKey]++;
                }
            }
        });
        
        // Ordenar las claves (meses) cronológicamente
        const sortedKeys = Object.keys(monthlyData).sort((a, b) => {
            const getMonthIndex = (key) => {
                const [monthStr, yearStr] = key.split('/');
                const monthIndex = monthNames.indexOf(monthStr);
                const year = parseInt(yearStr, 10) + 2000;
                return year * 100 + monthIndex;
            };
            return getMonthIndex(a) - getMonthIndex(b);
        });

        // Preparar la respuesta JSON
        const labels = sortedKeys;
        const dataPoints = sortedKeys.map(key => monthlyData[key]);
        
        res.status(200).json({ 
            ok: true, 
            labels: labels, 
            data: dataPoints,
            totalArboles: arboles.length // Devolvemos el total para la tarjeta
        });
        
    } catch (error) {
        console.error("Error al obtener impacto ambiental:", error);
        res.status(500).json({ 
            ok: false, 
            mensaje: "Error interno al calcular el impacto." 
        });
    }
});

// ===================================
// 🤝 RUTA: UNIRSE A EVENTO
// ===================================

/**
 * Endpoint para que un voluntario se una a un evento.
 * Añade el ID del voluntario al array 'participantes' del evento.
 * 💡 RUTA PROTEGIDA
 */
app.patch('/api/eventos/unirse/:id', autenticarToken, async (req, res) => {
    const eventoId = req.params.id;
    const voluntarioId = req.uid; // ID del usuario obtenido del token

    if (!eventoId) {
        return res.status(400).json({ ok: false, mensaje: "ID del evento es requerido." });
    }
    
    try {
        const eventoRef = db.collection('eventos').doc(eventoId);

        // Usar arrayUnion para añadir el ID y evitar duplicados automáticamente
        await eventoRef.update({
            participantes: FieldValue.arrayUnion(voluntarioId)
        });

        res.status(200).json({ 
            ok: true, 
            mensaje: "Te has unido al evento correctamente." 
        });
        
    } catch (error) {
        console.error(`Error al unir voluntario ${voluntarioId} al evento ${eventoId}:`, error);
        res.status(500).json({ 
            ok: false, 
            mensaje: "Error interno al intentar unirse al evento." 
        });
    }
});


// ===================================
// RUTA DE DATOS DEL SUELO
// ===================================

/**
 * Obtener la calidad del suelo (Carbono Orgánico) por coordenadas.
 * 💡 RUTA PROTEGIDA (Asumiendo que se requiere autenticación)
 */
// servidor.js - Nuevo Endpoint para Open-Meteo
app.get('/api/soil-quality/:lat/:lon', autenticarToken, async (req, res) => {
    const { lat, lon } = req.params;
    const OPENMETEO_SOIL_API = "https://api.open-meteo.com/v1/forecast"; // Redefinido aquí para claridad

    // 1. Validación de coordenadas (Usando la función ya definida)
    // Se asume la existencia de isValidCoordinate del inicio del archivo
    if (!isValidCoordinate(lat, true) || !isValidCoordinate(lon, false)) {
        return res.status(400).json({ 
            ok: false, 
            mensaje: "Coordenadas GPS inválidas." 
        });
    }

    try {
        // 2. Definición de parámetros para Open-Meteo (buscando datos de suelo)
        const openMeteoParams = {
            latitude: lat,
            longitude: lon,
            // Solicitando datos de humedad y temperatura de suelo (0-7cm)
            daily: 'soil_temperature_0_to_7cm,soil_moisture_0_to_1cm', 
            timezone: 'auto',
            past_days: 1, 
        };
        
        // 3. Llamada a la API externa con Axios
        const response = await axios.get(OPENMETEO_SOIL_API, {
            params: openMeteoParams
        });
        
        // 4. Lógica de Mapeo y Respuesta (Simulación de OCD basada en humedad)
        const soilData = response.data.daily;
        
        if (!soilData || !soilData.soil_moisture_0_to_1cm || soilData.soil_moisture_0_to_1cm.length === 0) {
            // Error en los datos de la API externa
            return res.status(502).json({
                ok: false,
                mensaje: "Error al obtener o procesar datos de suelo de la fuente externa."
            });
        }
        
        const moisture = soilData.soil_moisture_0_to_1cm[0] * 100; // Convertir de fracción a porcentaje
        
        // Simulación de Calidad del Suelo (OCD)
        let valorOCD_g_kg = 'Simulado';
        let calidad = 'Desconocida';
        
        if (moisture >= 15.0 && moisture <= 35.0) {
            calidad = 'Óptima (Simulada)';
            valorOCD_g_kg = '4.5';
        } else if (moisture < 15.0) {
            calidad = 'Baja (Simulada - Seco)';
            valorOCD_g_kg = '2.1';
        } else {
            calidad = 'Media/Riesgo (Simulada - Húmedo)';
            valorOCD_g_kg = '3.0';
        }

        res.json({
            ok: true,
            valorOCD_g_kg: valorOCD_g_kg,
            calidad: calidad,
            unidad: 'g/kg',
            mensaje: "Datos de calidad del suelo obtenidos y simulados.",
            humedad: moisture.toFixed(1)
        });

    } catch (error) {
        // 5. Captura de errores (SOLUCIÓN AL 500)
        console.error("Error al obtener calidad del suelo:", error.message || error);
        // Devolver un 500 para indicar que el backend falló internamente
        res.status(500).json({
            ok: false,
            mensaje: "Error interno del servidor al procesar datos del suelo. (Verifique API Key o conexión)",
            detalle: error.message
        });
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
 * Nueva ruta para generar el Reporte Completo (Árboles, Sensores y Eventos)
 * 💡 RUTA PROTEGIDA para uso administrativo
 */
app.get('/api/reporte/completo', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const db = admin.firestore();
        const reporte = {};

        // 1. Obtener Datos de Árboles
        const arbolesSnapshot = await db.collection('arboles').get();
        reporte.arboles = arbolesSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // 2. Obtener Datos de Sensores (asumiendo que tienes una colección 'sensores')
        const sensoresSnapshot = await db.collection('sensores').get();
        reporte.sensores = sensoresSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // 3. Obtener Datos de Eventos
        const eventosSnapshot = await db.collection('eventos').get();
        reporte.eventos = eventosSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.status(200).json({ 
            ok: true, 
            mensaje: "Datos de reporte completo obtenidos.",
            ...reporte // Devuelve arboles, sensores y eventos
        });

    } catch (error) {
        console.error("Error al generar el reporte completo:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al obtener el reporte completo." });
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
        const eventosRef = db.collection('eventos');
        const snapshot = await eventosRef.get();

        const eventos = snapshot.docs.map(doc => {
            const data = doc.data();
            let eventDate = null;
            let parseSuccess = false;

            if (data.fecha) {
                if (typeof data.fecha.toDate === 'function') {
                    // Es un Timestamp de Firestore
                    eventDate = data.fecha.toDate();
                    parseSuccess = true;
                } else if (typeof data.fecha === 'string') {
                    // Es una cadena de texto (String)
                    eventDate = new Date(data.fecha);
                    if (!isNaN(eventDate.getTime())) {
                        parseSuccess = true;
                    }
                }
            }
            
            if (!parseSuccess) {
                 // Si la fecha es inválida o nula, devolvemos el evento para que el admin lo revise, pero marcamos la fecha como string
                 eventDate = data.fecha || 'Fecha inválida/no definida';
            } else {
                 // Si es válido, lo dejamos como objeto Date
                 eventDate = eventDate;
            }

            return {
                id: doc.id,
                titulo: data.titulo || 'Evento sin título',
                fecha: eventDate instanceof Date ? eventDate.toISOString() : eventDate, // ISO string si es Date, o el valor crudo si es string
                descripcion: data.descripcion || '',
                ubicacion: data.ubicacion || 'Ubicación pendiente',
                hora: data.hora || 'Hora pendiente',
                participantes: data.participantes || [],
                activo: data.activo !== undefined ? data.activo : true,
                creadorId: data.creadorId || 'N/A', // Es importante para el frontend
                ...data
            };
        });

        res.status(200).json({
            ok: true,
            eventos: eventos
        });

    } catch (error) {
        console.error("Error al obtener eventos de administración:", error);
        res.status(500).json({
            ok: false,
            mensaje: "Error interno al obtener eventos de administración."
        });
    }
});

/**
 * Obtener eventos activos para voluntarios (Ruta pública, no requiere token)
 */
// ===================================
// 🗓️ RUTA: OBTENER TODOS LOS EVENTOS ACTIVOS
// ===================================

/**
 * Endpoint para obtener TODOS los eventos cuya fecha no ha pasado,
 * estandarizando la estructura de datos para el frontend.
 */
app.get('/api/eventos/activos', autenticarToken, async (req, res) => {
    try {
        const eventosRef = db.collection('eventos');
        
        // Obtenemos todos los documentos sin filtro
        const snapshot = await eventosRef.get();

        const today = new Date();
        today.setHours(0, 0, 0, 0); 

        // 1. Mapeo, Estandarización y Logging
        let eventos = snapshot.docs.map((doc, index) => {
            const data = doc.data();
            
            let eventDate = null;
            let dateLog = 'N/A';
            let parseSuccess = false;

            if (data.fecha) {
                dateLog = data.fecha; // Guardamos el valor crudo para el log
                
                if (typeof data.fecha.toDate === 'function') {
                    // Es un Timestamp de Firestore
                    eventDate = data.fecha.toDate();
                    parseSuccess = true;
                } else if (typeof data.fecha === 'string') {
                    // Es una cadena de texto (String)
                    eventDate = new Date(data.fecha);
                    if (!isNaN(eventDate.getTime())) {
                        parseSuccess = true;
                    }
                }
            }

            // 🚨 LOG DE DIAGNÓSTICO PARA LOS PRIMEROS 5 EVENTOS 🚨
            if (index < 5) {
                console.log(`[DIAGNOSTICO ${doc.id}]`);
                console.log(`  > Fecha Cruda: ${dateLog}`);
                console.log(`  > Tipo de Fecha: ${typeof data.fecha} ${typeof data.fecha === 'object' && data.fecha.toDate ? '(Timestamp)' : ''}`);
                console.log(`  > Conversión OK: ${parseSuccess}`);
                console.log(`  > Fecha Parseada: ${eventDate instanceof Date && parseSuccess ? eventDate.toISOString() : 'Inválida'}`);
            }

            // 🚨 TEMPORAL: Solo descarta si NO se pudo obtener un objeto Date válido
            if (!parseSuccess) {
                 return null;
            }
            
            // 🚀 ESTANDARIZACIÓN DE LOS DATOS (Sin el filtro de fecha)
            const standardizedEvent = {
                id: doc.id,
                titulo: data.titulo || data.autor || 'Evento sin título',
                fecha: eventDate, // Objeto Date válido
                descripcion: data.descripcion || '',
                ubicacion: data.ubicacion || 'Ubicación pendiente',
                hora: data.hora || 'Hora pendiente',
                participantes: data.participantes || [], 
                // Añadimos una bandera de diagnóstico
                _isFuture: eventDate >= today,
                ...data 
            };
            
            return standardizedEvent;
        }).filter(evento => evento !== null); // Elimina eventos sin fecha o con fecha inválida

        // 🚨 TEMPORAL: NO FILTRAMOS NI ORDENAMOS (devolvemos todos los eventos válidos)
        // Ya no se filtran por fecha futura.

        console.log(`Found ${eventos.length} events with valid dates.`);
        
        res.status(200).json({ 
            ok: true, 
            eventos: eventos 
        });

    } catch (error) {
        console.error("Error al obtener todos los eventos (DIAGNÓSTICO):", error);
        res.status(500).json({ 
            ok: false, 
            mensaje: "Error interno al obtener eventos." 
        });
    }
});

// ===================================
// 🏆 RUTA: OBTENER RANKING POR EVENTOS UNIDOS
// ===================================

/**
 * Endpoint para obtener el ranking de voluntarios basado en el número de eventos unidos.
 * 💡 RUTA PROTEGIDA
 */
app.get('/api/ranking/eventos', autenticarToken, async (req, res) => {
    try {
        const eventosSnapshot = await db.collection('eventos').get();
        const rankingMap = {};
        const uidsToFetch = new Set();

        // 1. Agregación de Participaciones
        eventosSnapshot.forEach(doc => {
            const data = doc.data();
            const participantes = data.participantes || [];

            participantes.forEach(uid => {
                rankingMap[uid] = (rankingMap[uid] || 0) + 1;
                uidsToFetch.add(uid); // Recolecta todos los UIDs únicos
            });
        });

        // 2. Convertir el mapa en un array ordenable
        let rankingArray = Object.entries(rankingMap).map(([uid, count]) => ({ 
            uid, 
            count,
            nombre: 'Usuario Desconocido' // Valor por defecto
        }));

        // 3. Ordenar el ranking (de mayor a menor)
        rankingArray.sort((a, b) => b.count - a.count);

        // 4. Obtener nombres de usuario (Opcional, pero necesario para la presentación)
        if (uidsToFetch.size > 0) {
            // Firestore no soporta consultas 'in' en doc.id, por lo que usamos 'Promise.all'
            // para obtener los nombres de la colección 'usuarios' (asumiendo esa estructura).
            const uidPromises = Array.from(uidsToFetch).map(uid => 
                db.collection('usuarios').doc(uid).get()
            );

            const userDocs = await Promise.all(uidPromises);
            const userNames = {};

            userDocs.forEach(doc => {
                if (doc.exists) {
                    userNames[doc.id] = doc.data().nombre || doc.data().email.split('@')[0];
                }
            });

            // 5. Asignar nombres al ranking
            rankingArray = rankingArray.map(item => ({
                ...item,
                nombre: userNames[item.uid] || item.nombre
            }));
        }

        res.status(200).json({ 
            ok: true, 
            ranking: rankingArray 
        });

    } catch (error) {
        console.error("Error al obtener el ranking de eventos:", error);
        res.status(500).json({ 
            ok: false, 
            mensaje: "Error interno al calcular el ranking." 
        });
    }
});


/**
 * Obtener todos los árboles registrados para el dashboard histórico
 * 💡 RUTA PROTEGIDA (Se asume que verificaradmin comprueba el rol 'gobierno' o similar)
 */
app.get('/api/arboles/historico', autenticarToken, verificaradmin, async (req, res) => {
    try {
        const arbolesRef = db.collection('arboles');
        // Se obtiene la lista completa, el cálculo de las métricas históricas se hará en el frontend
        const snapshot = await arbolesRef.get();

        if (snapshot.empty) {
            return res.status(200).json({ ok: true, arboles: [], mensaje: "No se encontraron árboles registrados." });
        }

        const arboles = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            arboles.push({
                // Campos esenciales para el histórico: ID y la fecha de registro/creación
                id: doc.id,
                fechaRegistro: data.fechaRegistro || data.fechaCreacion // Usar el campo de fecha más relevante
            });
        });

        res.status(200).json({ ok: true, arboles });
    } catch (error) {
        console.error("Error al obtener histórico de árboles:", error);
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al obtener histórico." });
    }
});


/**
 * Eliminar evento
 * 💡 RUTA PROTEGIDA
 */
// =========================================================
// 2. RUTA DELETE: Eliminar un evento por ID
// =========================================================
app.delete('/api/admin/eventos/:id', autenticarToken, verificaradmin, async (req, res) => {
    const { id } = req.params;

    try {
        const eventoRef = db.collection('eventos').doc(id);
        const doc = await eventoRef.get();

        if (!doc.exists) {
            return res.status(404).json({ mensaje: "Evento no encontrado." });
        }

        // Se elimina el documento
        await eventoRef.delete();

        console.log(`Evento eliminado: ${id}`);
        res.status(200).json({
            ok: true,
            mensaje: "Evento eliminado exitosamente."
        });

    } catch (error) {
        console.error(`Error al eliminar evento ${id}:`, error);
        res.status(500).json({
            ok: false,
            mensaje: "Error interno al eliminar evento."
        });
    }
});

/**
 * Actualizar evento
 * 💡 RUTA PROTEGIDA
 */
// =========================================================
// 3. RUTA PUT/PATCH: Actualizar un evento por ID (ejemplo básico)
// Se recomienda usar PATCH si solo se envían los campos modificados.
// =========================================================
app.put('/api/admin/eventos/:id', autenticarToken, verificaradmin, async (req, res) => {
    const { id } = req.params;
    const updates = req.body;

    // Campos que no se deben actualizar o que requieren validación especial
    delete updates.id;
    delete updates.fechaCreacion;
    updates.fechaActualizacion = new Date();

    try {
        const eventoRef = db.collection('eventos').doc(id);
        const doc = await eventoRef.get();

        if (!doc.exists) {
            return res.status(404).json({ mensaje: "Evento no encontrado." });
        }

        // Actualizar el documento con los datos proporcionados
        await eventoRef.update(updates);

        console.log(`Evento actualizado: ${id}`);
        res.status(200).json({
            ok: true,
            mensaje: "Evento actualizado exitosamente."
        });

    } catch (error) {
        console.error(`Error al actualizar evento ${id}:`, error);
        res.status(500).json({
            ok: false,
            mensaje: "Error interno al actualizar evento."
        });
    }
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
