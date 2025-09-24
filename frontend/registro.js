document.getElementById("registroForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  // Tomamos los valores del formulario
  const nombre = document.getElementById("nombre").value;
  const apellido = document.getElementById("apellido").value; // agregamos apellido
  const email = document.getElementById("email").value; // cambiamos correo -> email
  const password = document.getElementById("password").value;

  try {
    const response = await fetch("https://greenroots-web.onrender.com/api/registro", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nombre, apellido, email, password }) // 👈 campos correctos según backend
    });

    const data = await response.json();

    if (response.ok) {
      alert("✅ Registro exitoso 🎉 Ahora puedes iniciar sesión");
      window.location.href = "index.html"; // redirige al login
    } else {
      alert(data.mensaje || "❌ Error en el registro"); // usamos 'mensaje' que retorna el backend
    }

  } catch (err) {
    console.error("Error en la petición:", err);
    alert("⚠️ Error al conectar con el servidor");
  }
});
