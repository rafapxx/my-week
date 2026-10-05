// Offline copy of the app. Own files: network first (always fresh when online), cache when offline.
// Firebase SDK files from gstatic: cache first (they never change for a pinned version).
const VERSION = "v1";
const CACHE = "my-week-" + VERSION;
const OWN = ["./", "index.html", "manifest.webmanifest", "icon-180.png", "icon-192.png", "icon-512.png"];
const SDK = "https://www.gstatic.com/firebasejs/11.0.2/";

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(OWN)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k.startsWith("my-week-") && k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);

  if (url.href.startsWith(SDK)) {
    e.respondWith(
      caches.match(req).then(hit => hit || fetch(req).then(res => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
        return res;
      }))
    );
    return;
  }

  if (url.origin === location.origin) {
    e.respondWith(
      fetch(req, { cache: "no-cache" })
        .then(res => {
          if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
          return res;
        })
        .catch(() => caches.match(req).then(hit => hit || (req.mode === "navigate" ? caches.match("index.html") : undefined)))
    );
  }
});
