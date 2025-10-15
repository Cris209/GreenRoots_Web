const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const axios = require("axios");
const validator = require('validator');

// ===================================
// CONFIGURACIÓN INICIAL DE EXPRESS Y FIREBASE
// ===================================

const app = express();
app.use(cors());
app.use(express.json());

// Variables de entorno
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;

// Inicializar Firebase Admin (para Firestore)
const FIREBASE_KEY = process.env.FIREBASE_KEY;

if (!FIREBASE_WEB_API_KEY) {
    throw new Error("La variable de entorno FIREBASE_WEB_API_KEY no está configurada");
}
if (!FIREBASE_KEY) {
    throw new Error("La variable de entorno FIREBASE_KEY (clave privada) no está configurada");
}

try {
    const serviceAccount = JSON.parse(FIREBASE_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
} catch (e) {
    console.error("Error al parsear FIREBASE_KEY. Asegúrate de que el JSON sea válido.", e);
    throw new Error("Error en la inicialización de Firebase Admin.");
}


const db = admin.firestore();

//Almacenamiento temporal para el bloqueo de sesiones (Solo en memoria)
const loginAttempts = {}; // { email: { count: 0, time: Date } }
const MAX_ATTEMPTS = 3;
const LOCKOUT_TIME_MS = 15 * 1000; // 10 minutos

// ===================================
// FUNCIONES DE VALIDACIÓN DE SEGURIDAD
// ===================================

/**
 * Verifica si un nombre cumple con las políticas de seguridad (<= 30 caracteres, sin especiales).
 */
function validateNombre(nombre) {
    if (!nombre) {
        return "El nombre es obligatorio.";
    }
    if (nombre.length > 30) {
        return "El nombre no puede exceder los 30 caracteres.";
    }
    // Solo se permiten letras (incluidas tildes y ñ), números y espacios.
    if (/[^a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ]/.test(nombre)) {
        return "El nombre contiene caracteres especiales no permitidos.";
    }
    // Nota: La detección de nombres obscenos requiere una librería de lista negra compleja.
    return null; 
}

/**
 * Verifica si un email es válido (formato estricto).
 */
async function validateEmail(email) {
    // 1. Verificación de formato estándar estricto
    if (!validator.isEmail(email, { allow_display_name: false, require_tld: true, allow_utf8_local_part: false })) {
        return "El formato del correo electrónico es inválido.";
    }
    
    // 2. Verificación de caracteres especiales (ya cubierta por isEmail estricto)
    // El chequeo de dominio existente (MX record) es costoso y se omite en este entorno.
    
    return null; 
}

/**
 * Verifica si la contraseña cumple con las políticas de seguridad.
 */
function validatePassword(password) {
    // Patrón: Al menos 8 caracteres, mayúscula, minúscula, número, y especial.
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9\s]).{8,}$/;
    
    if (password.length < 8) {
        return "La contraseña debe tener al menos 8 caracteres.";
    }
    if (!passwordPattern.test(password)) {
         return "La contraseña debe incluir mayúsculas, minúsculas, números y al menos un carácter especial.";
    }
    return null;
}

// ===================================
// RUTAS DE AUTENTICACIÓN
// ===================================

//Ruta: REGISTRO (Centralizada y Segura)
app.post("/api/registro", async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    // Validación de datos obligatorios
    if (!nombre || !email || !password || !rol) {
        return res.status(400).json({ ok: false, mensaje: "Faltan datos obligatorios." });
    }

    // 1. VALIDACIONES DE SEGURIDAD
    const nombreError = validateNombre(nombre);
    if (nombreError) {
        return res.status(400).json({ ok: false, mensaje: nombreError });
    }
    
    const emailError = await validateEmail(email);
    if (emailError) {
        return res.status(400).json({ ok: false, mensaje: emailError });
    }
    
    const passwordError = validatePassword(password);
    if (passwordError) {
         return res.status(400).json({ ok: false, mensaje: passwordError });
    }

    try {
        // PASO 1: CREAR USUARIO EN FIREBASE AUTHENTICATION (maneja repetición de email)
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: nombre,
        });

        const uid = userRecord.uid;

        // PASO 2: GUARDAR PERFIL EN FIRESTORE (usando UID como ID del documento)
        await db.collection("usuarios").doc(uid).set({
            nombre: nombre,
            email: email,
            rol: rol,
        });

        res.json({ ok: true, mensaje: "Usuario registrado y perfil creado correctamente", uid: uid });

    } catch (error) {
        console.error("Error en registro:", error);
        let mensajeError = "Error en el servidor.";
        
        if (error.code === 'auth/email-already-in-use') {
            mensajeError = "El correo electrónico ya está registrado.";
            return res.status(409).json({ ok: false, mensaje: mensajeError });
        }
        
        // Si hay otro error de Firebase Auth que no fue capturado por validatePassword
        if (error.code === 'auth/weak-password') {
            mensajeError = "La contraseña es muy débil. Debe cumplir con los requisitos de seguridad.";
            return res.status(400).json({ ok: false, mensaje: mensajeError });
        }
        
        res.status(500).json({ ok: false, mensaje: mensajeError });
    }
});


//Ruta: LOGIN (Centralizada y Bloqueo por Intentos)
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ ok: false, mensaje: "Faltan datos (email o password)" });
        }
        
        // 1. VALIDACIÓN DE EMAIL
        const emailError = await validateEmail(email);
        if (emailError) {
            return res.status(400).json({ ok: false, mensaje: emailError });
        }

        // 2. VERIFICACIÓN DE BLOQUEO POR INTENTOS FALLIDOS (Rate Limiting)
        const now = Date.now();
        const attempts = loginAttempts[email];

        if (attempts) {
            if (attempts.count >= MAX_ATTEMPTS && now - attempts.time < LOCKOUT_TIME_MS) {
                const remainingTime = Math.ceil((LOCKOUT_TIME_MS - (now - attempts.time)) / 60000); // En minutos
                return res.status(429).json({ 
                    ok: false, 
                    mensaje: `Demasiados intentos de inicio de sesión. Intente de nuevo en ${remainingTime} minutos.` 
                });
            } else if (now - attempts.time >= LOCKOUT_TIME_MS) {
                // Resetear si el tiempo de bloqueo ha pasado
                delete loginAttempts[email];
            }
        }
        
        let uid;

        // --- PASO 3: AUTENTICAR CON LA API REST DE FIREBASE ---
        try {
            const loginUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
            
            const authResponse = await axios.post(loginUrl, {
                email: email,
                password: password,
                returnSecureToken: true
            });
            
            // Éxito: borrar intentos fallidos y obtener UID
            delete loginAttempts[email]; 
            uid = authResponse.data.localId;
            
        } catch (authError) {
            // Fallo: Incrementar el contador de intentos fallidos
            loginAttempts[email] = {
                count: (loginAttempts[email]?.count || 0) + 1,
                time: now 
            };
            
            // Devolver 401 Unauthorized con mensaje genérico
            return res.status(401).json({ ok: false, mensaje: "Credenciales incorrectas o usuario no encontrado." });
        }
        
        // --- PASO 4: OBTENER EL PERFIL DE FIRESTORE CON EL UID ---
        const docRef = db.collection("usuarios").doc(uid);
        const doc = await docRef.get();

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
        res.status(500).json({ ok: false, mensaje: "Error interno del servidor al procesar la solicitud." });
    }
});


// ===================================
// INICIO DEL SERVIDOR
// ===================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor Express corriendo en puerto ${PORT}`);
});
