self.addEventListener('push', function(event) {
  let data = {};
  try { data = event.data.json(); } catch (e) { data = { title: 'Wimpex', body: event.data.text() }; }
  const title = data.title || 'Wimpex';
  const options = {
    body: data.body || '',
    data: { url: data.url || '/' },
    icon: '/assets/placeholder.txt'
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/';
  event.waitUntil(clients.matchAll({ type: 'window' }).then(windowClients => {
    for (let i = 0; i < windowClients.length; i++) {
      const client = windowClients[i];
      if (client.url === url && 'focus' in client) return client.focus();
    }
    if (clients.openWindow) return clients.openWindow(url);
  }));
});