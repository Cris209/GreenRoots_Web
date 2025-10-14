const API_URL = "https://greenroots-web.onrender.com/api";
const USUARIO_STORAGE_KEY = "greenroots_usuario"; // Clave para guardar el usuario

// --- Funciones de utilidad para LocalStorage ---

function guardarUsuario(usuario) {
    localStorage.setItem(USUARIO_STORAGE_KEY, JSON.stringify(usuario));
}

function obtenerUsuario() {
    const usuarioString = localStorage.getItem(USUARIO_STORAGE_KEY);
    return usuarioString ? JSON.parse(usuarioString) : null;
}

function eliminarUsuario() {
    localStorage.removeItem(USUARIO_STORAGE_KEY);
}

// -------------------------
// INICIO DE SESIÓN
// -------------------------
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();

    const correo = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const mensajeError = document.getElementById("mensaje-error");

    mensajeError.textContent = "";

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            // Ya no es necesario 'credentials: "include"' porque no usamos cookies de sesión
            body: JSON.stringify({ email: correo, password }) // Corregido 'correo' a 'email' para coincidir con el backend
        });

        const data = await res.json();

        if (!res.ok) {
            // El backend usa 'mensaje' en lugar de 'error', así que lo usamos para el mensaje.
            mensajeError.textContent = data.mensaje || "Error en el inicio de sesión";
            return;
        }

        // --- MANEJO DE SESIÓN CORREGIDO: GUARDAR DATOS DEL USUARIO ---
        if (data.usuario) {
            guardarUsuario(data.usuario);
        }

        // Redirigir si el login es exitoso
        window.location.href = "home.html";

    } catch (err) {
        console.error("Error al iniciar sesión:", err);
        mensajeError.textContent = "Error de conexión con el servidor.";
    }
});

// -------------------------
// VERIFICAR SESIÓN ACTIVA (Para usar en home.html u otras páginas protegidas)
// -------------------------
async function verificarSesion() {
    // Verificar si existe el usuario en localStorage
    if (!obtenerUsuario()) {
        // Si no hay sesión, redirigir al login
        window.location.href = "index.html";
        return false;
    }
    // Si hay usuario, la sesión está activa (no es necesario un fetch extra)
    return true;
}

// -------------------------
// CERRAR SESIÓN
// -------------------------
async function cerrarSesion() {
    // En tu backend no tienes una ruta de /logout.
    // Para simplificar, solo eliminaremos la sesión del frontend.
    eliminarUsuario();
    
    // Si tuvieras una ruta /logout que limpiara una cookie o un token, podrías agregarla aquí.
    /*
    try {
        await fetch(`${API_URL}/logout`, {
            method: "POST",
            credentials: "include", // Si usara cookies
        });
    } catch (err) {
        console.error("Advertencia: No se pudo contactar el endpoint /logout, pero se limpió la sesión local.", err);
    }
    */
    
    window.location.href = "index.html";
}

// Exportar para usar desde home.html
window.verificarSesion = verificarSesion;
window.cerrarSesion = cerrarSesion;

// Opcional: Si el script.js se usa en index.html,
// puedes verificar aquí si el usuario ya está logeado y redirigir
if (document.getElementById("loginForm") && obtenerUsuario()) {
    window.location.href = "home.html"; // Redirigir si ya está logeado
}
