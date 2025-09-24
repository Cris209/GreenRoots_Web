document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  // Tomamos los valores del formulario
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  try {
    // Llamamos a la API de tu backend
    const response = await fetch("https://greenroots-web.onrender.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }) // 👈 usamos "email" en vez de "correo"
    });

    const data = await response.json();

    if (response.ok) {
      alert("✅ Inicio de sesión exitoso");
      console.log("Usuario:", data);
      // Aquí podrías redirigir a otra página
      // window.location.href = "/dashboard.html";
    } else {
      alert(`❌ Error: ${data.error}`);
    }
  } catch (err) {
    console.error("Error en la petición:", err);
    alert("⚠️ Error al conectar con el servidor");
  }
});
