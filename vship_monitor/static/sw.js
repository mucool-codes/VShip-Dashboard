/* Service worker for the home-screen app. It does two small things:
   - lets Android show alert notifications (Chrome requires a service worker), and
   - tapping a notification opens / focuses the dashboard.
   Nothing is cached: this is live data, and the dashboard needs the laptop anyway. */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    for (const c of list) if ("focus" in c) return c.focus();
    return self.clients.openWindow("/");
  }));
});
