const express = require("express");
const cors = require("cors");
// const bcrypt = require("bcrypt"); // Ya no es necesario para login/registro
const admin = require("firebase-admin");
const axios = require("axios"); // <--- NUEVA DEPENDENCIA

// Inicializar Express
const app = express();
app.use(cors());
app.use(express.json());

// Obtener la clave de la API REST pública de Firebase (web client)
if (!process.env.FIREBASE_WEB_API_KEY) {
    throw new Error("❌ La variable de entorno FIREBASE_WEB_API_KEY no está configurada");
}
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;

// Inicializar Firebase Admin (para Firestore)
if (!process.env.FIREBASE_KEY) {
    throw new Error("❌ La variable de entorno FIREBASE_KEY (clave privada) no está configurada");
}
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ==========================
// 📌 Ruta: REGISTRO (Mantiene la lógica centralizada)
// ==========================
app.post("/api/registro", async (req, res) => {
    // ... Tu lógica de registro con admin.auth().createUser() (no necesita cambios) ...
    // Asegúrate de que esta ruta envíe 'password'.

    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password || !rol) {
        return res.status(400).json({ ok: false, mensaje: "Faltan datos obligatorios (nombre, email, password o rol)" });
    }

    try {
        // PASO 1: CREAR USUARIO EN FIREBASE AUTHENTICATION
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

        res.json({ ok: true, mensaje: "Usuario registrado y perfil creado correctamente", uid: uid });

    } catch (error) {
        console.error("Error en registro:", error);
        let mensajeError = "Error en el servidor.";
        if (error.code === 'auth/email-already-in-use') {
            mensajeError = "El correo electrónico ya está registrado en Firebase Authentication.";
            return res.status(409).json({ ok: false, mensaje: mensajeError });
        }
        if (error.code === 'auth/weak-password') {
            mensajeError = "La contraseña debe tener al menos 6 caracteres.";
            return res.status(400).json({ ok: false, mensaje: mensajeError });
        }
        
        res.status(500).json({ ok: false, mensaje: mensajeError });
    }
});


// ==========================
// 📌 Ruta: LOGIN CENTRALIZADO (Usa la API REST de Firebase Auth)
// ==========================
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ ok: false, mensaje: "Faltan datos (email o password)" });
        }

        let uid;
        
        // --- PASO 1: AUTENTICAR AL USUARIO CON LA API REST DE FIREBASE ---
        try {
            const loginUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
            
            const authResponse = await axios.post(loginUrl, {
                email: email,
                password: password,
                returnSecureToken: true
            });
            
            // Si tiene éxito, la respuesta contiene el UID y los tokens
            uid = authResponse.data.localId;
            
        } catch (authError) {
            // Manejar errores de autenticación de Firebase (credenciales incorrectas, usuario no encontrado)
            console.error("Error de Firebase Auth en login:", authError.response ? authError.response.data : authError.message);
            
            let errorMessage = "Credenciales incorrectas"; // Mensaje por defecto

            if (authError.response && authError.response.data && authError.response.data.error) {
                const firebaseCode = authError.response.data.error.message;
                
                if (firebaseCode.includes("EMAIL_NOT_FOUND") || firebaseCode.includes("INVALID_PASSWORD")) {
                    // Firebase usa mensajes genéricos para evitar ataques de enumeración
                    errorMessage = "Credenciales incorrectas";
                } else {
                    errorMessage = "Error de autenticación desconocido.";
                }
            }

            // Devolver 401 Unauthorized
            return res.status(401).json({ ok: false, mensaje: errorMessage });
        }
        
        // --- PASO 2: OBTENER EL PERFIL DE FIRESTORE CON EL UID OBTENIDO ---
        const docRef = db.collection("usuarios").doc(uid);
        const doc = await docRef.get();

        if (!doc.exists) {
            // Esto sucede si el usuario existe en Firebase Auth pero no en Firestore (debería ser raro)
            return res.status(404).json({ ok: false, mensaje: "Perfil de usuario no encontrado en la base de datos." });
        }

        const usuario = doc.data();

        // --- PASO 3: RESPUESTA EXITOSA ---
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


// ==========================
// 📌 Servidor en Render
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
