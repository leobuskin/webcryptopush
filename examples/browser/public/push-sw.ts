import { cleanupOutdatedCaches, precacheAndRoute } from 'workbox-precaching';

declare const self: ServiceWorkerGlobalScope;

// Required by vite-plugin-pwa injectManifest strategy
cleanupOutdatedCaches();
precacheAndRoute(self.__WB_MANIFEST);

self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Web Push', {
      body: event.data?.text() || '<empty>',
      requireInteraction: false,
    }),
  );
});
