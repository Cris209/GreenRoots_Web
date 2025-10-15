// Nombre del caché y lista de archivos esenciales (Shell)
const CACHE_NAME = 'green-roots-v1';

// Archivos esenciales para la experiencia offline/login
const urlsToCache = [
  '/', 
  '/index.html',        // Nueva página HOME
  '/login.html',        // Nueva página de Login
  '/registro.html',     // Página de Registro
  '/home.css',          
  '/index.css',         
  '/script.js',         // Script de Login/Registro (si lo usas)
  '/home_script.js',    // Script de HOME (si lo usas)
  '/Green_Roots.jpg',   
  '/manifest.json',
  '/offline.html',      // Página de fallback
  // Librerías CDN
  'https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// 1. Instalar Service Worker (Caching de archivos estáticos)
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service Worker: Cacheando shell de la aplicación');
        return cache.addAll(urlsToCache);
      })
  );
});

// 2. Interceptar peticiones de red (Estrategia Cache-First con Fallback Offline)
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  
  // No cachear ni interceptar la API del backend
  if (event.request.url.includes('/api/')) {
    return fetch(event.request);
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // 1. Servir desde caché si existe
        if (response) {
          return response;
        }
        
        // 2. Si no está en caché, ir a la red
        return fetch(event.request).catch(() => {
            // 3. Si la red falla Y la petición es una navegación (página HTML), servir offline.html
            if (event.request.mode === 'navigate') {
                 return caches.match('/offline.html');
            }
        });
      })
  );
});

// 3. Limpiar cachés antiguos
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('Service Worker: Eliminando caché antigua:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
