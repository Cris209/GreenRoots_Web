document.addEventListener("DOMContentLoaded", () => {
  const registroForm = document.getElementById("registroForm");

  registroForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    const nombre = document.getElementById("nombre").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const rol = document.getElementById("rol").value;

    try {
      const response = await fetch("https://greenroots-web.onrender.com/api/registro", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nombre, email, password, rol })
      });

      const data = await response.json();

      if (response.ok) {
        alert("Registro exitoso 🎉 Ahora puedes iniciar sesión");
        window.location.href = "index.html"; // redirige al login
      } else {
        alert(data.mensaje || "Error en el registro");
      }

    } catch (err) {
      console.error(err);
      alert("Error al conectar con el servidor");
    }
  });
});
