/* Nessun worker viene registrato dalla pagina principale.
   Questo file neutralizza eventuali vecchie registrazioni limitandosi alle cache RapportoTIA. */
const RAPPORTO_TIA_CACHE_PREFIX="RapportoTIA-";
self.addEventListener("install",event=>{self.skipWaiting()});
self.addEventListener("activate",event=>{
  event.waitUntil((async()=>{
    const keys=await caches.keys();
    await Promise.all(keys.filter(key=>key.startsWith(RAPPORTO_TIA_CACHE_PREFIX)).map(key=>caches.delete(key)));
    await self.registration.unregister();
  })());
});
