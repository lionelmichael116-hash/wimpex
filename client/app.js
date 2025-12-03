(function() {
  // ===== STATE =====
  let currentUser = null;
  let currentUserId = null;
  let currentToken = null;
  let isAdmin = false;
  let ws = null;
  let currentFilter = 'none';
  let localStream = null;
  let mediaRecorder = null;
  let recordedChunks = [];
  let conversations = new Map();
  let temp2FAToken = null;

  // ===== DOM ELEMENTS =====
  const authContainer = document.getElementById('authContainer');
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');
  const authTabs = document.querySelectorAll('.tab-btn');
  const authError = document.getElementById('authError');

  const topbar = document.querySelector('.topbar');
  const mainContainer = document.querySelector('.main-container');
  const logoutBtn = document.getElementById('logoutBtn');

  const storiesBtn = document.getElementById('storiesBtn');
  const chatsBtn = document.getElementById('chatsBtn');
  const cameraBtn = document.getElementById('cameraBtn');
  const profileBtn = document.getElementById('profileBtn');

  const storiesView = document.getElementById('storiesView');
  const chatsView = document.getElementById('chatsView');
  const cameraView = document.getElementById('cameraView');
  const profileView = document.getElementById('profileView');
  const settingsView = document.getElementById('settingsView');
  const recommendationsView = document.getElementById('recommendationsView');

  const storiesGrid = document.getElementById('storiesGrid');
  const newStoryBtn = document.getElementById('newStoryBtn');

  const chatsList = document.getElementById('chatsList');
  const chatDetail = document.getElementById('chatDetail');
  const chatName = document.getElementById('chatName');
  const messagesLog = document.getElementById('messagesLog');
  const messageForm = document.getElementById('messageForm');
  const messageInput = document.getElementById('messageInput');
  const backToChats = document.getElementById('backToChats');
  const newChatBtn = document.getElementById('newChatBtn');

  const cameraStream = document.getElementById('cameraStream');
  const filterBtns = document.querySelectorAll('.filter-btn');
  const snapBtn = document.getElementById('snapBtn');
  const recordBtn = document.getElementById('recordBtn');
  const swapCameraBtn = document.getElementById('swapCameraBtn');
  const snapCanvas = document.getElementById('snapCanvas');
  const snapPreview = document.getElementById('snapPreview');
  const snapImage = document.getElementById('snapImage');
  const snapRecipient = document.getElementById('snapRecipient');
  const resnapBtn = document.getElementById('resnapBtn');
  const sendSnapBtn = document.getElementById('sendSnapBtn');

  const profileAvatar = document.getElementById('profileAvatar');
  const profileName = document.getElementById('profileName');
  const profileBio = document.getElementById('profileBio');
  const friendCount = document.getElementById('friendCount');
  const storyCount = document.getElementById('storyCount');
  const editProfileBtn = document.getElementById('editProfileBtn');

  const editProfileModal = document.getElementById('editProfileModal');
  const editProfileForm = document.getElementById('editProfileForm');
  const editBio = document.getElementById('editBio');
  const enable2faBtn = document.getElementById('enable2faBtn');
  const disable2faBtn = document.getElementById('disable2faBtn');
  const twoFaModal = document.getElementById('twoFaModal');
  const twoFaSetupArea = document.getElementById('twoFaSetupArea');
  const twoFaQr = document.getElementById('twoFaQr');
  const twoFaSecret = document.getElementById('twoFaSecret');
  const twoFaSetupCode = document.getElementById('twoFaSetupCode');
  const confirm2faBtn = document.getElementById('confirm2faBtn');
  const cancel2faBtn = document.getElementById('cancel2faBtn');
  const twoFaSetupStatus = document.getElementById('twoFaSetupStatus');
  const twoFaLoginArea = document.getElementById('twoFaLoginArea');
  const twoFaLoginCode = document.getElementById('twoFaLoginCode');
  const submit2faLoginBtn = document.getElementById('submit2faLoginBtn');
  const cancel2faLoginBtn = document.getElementById('cancel2faLoginBtn');
  const twoFaLoginStatus = document.getElementById('twoFaLoginStatus');

  // Onboarding elements
  const onboardingModal = document.getElementById('onboardingModal');
  const onboardingStep1 = document.getElementById('onboardingStep1');
  const onboardingStep2 = document.getElementById('onboardingStep2');
  const onboardingStep3 = document.getElementById('onboardingStep3');
  const onboardingNext1 = document.getElementById('onboardingNext1');
  const onboardingNext2 = document.getElementById('onboardingNext2');
  const onboardingFinish = document.getElementById('onboardingFinish');
  const onboardingSkip = document.getElementById('onboardingSkip');
  const onboardingStatus = document.getElementById('onboardingStatus');

  // ===== STORAGE =====
  function saveSession() {
    localStorage.setItem('wimpex_token', currentToken);
    localStorage.setItem('wimpex_user', JSON.stringify(currentUser));
    localStorage.setItem('wimpex_userId', currentUserId);
    localStorage.setItem('wimpex_isAdmin', isAdmin);
  }

  function loadSession() {
    const token = localStorage.getItem('wimpex_token');
    const user = JSON.parse(localStorage.getItem('wimpex_user') || 'null');
    const userId = localStorage.getItem('wimpex_userId');
    const admin = localStorage.getItem('wimpex_isAdmin') === 'true';
    if (token && user && userId) {
      currentToken = token;
      currentUser = user;
      currentUserId = userId;
      isAdmin = admin;
      return true;
    }
    return false;
  }

  function clearSession() {
    localStorage.removeItem('wimpex_token');
    localStorage.removeItem('wimpex_user');
    localStorage.removeItem('wimpex_userId');
    localStorage.removeItem('wimpex_isAdmin');
    currentUser = null;
    currentUserId = null;
    currentToken = null;
    isAdmin = false;
  }

  // ===== AUTH TABS =====
  authTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      authTabs.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      const tab = btn.dataset.tab;
      if (tab === 'login') {
        loginForm.style.display = 'block';
        signupForm.style.display = 'none';
      } else if (tab === 'signup') {
        loginForm.style.display = 'none';
        signupForm.style.display = 'block';
      }
      authError.style.display = 'none';
    });
  });

  // ===== FORGOT PASSWORD =====
  const forgotLink = document.getElementById('forgotLink');
  const forgotModal = document.getElementById('forgotModal');
  const forgotEmail = document.getElementById('forgotEmail');
  const sendForgotBtn = document.getElementById('sendForgotBtn');
  const cancelForgotBtn = document.getElementById('cancelForgotBtn');
  const forgotStatus = document.getElementById('forgotStatus');

  if (forgotLink) forgotLink.addEventListener('click', (e) => { e.preventDefault(); forgotModal.style.display = 'flex'; });
  if (cancelForgotBtn) cancelForgotBtn.addEventListener('click', () => { forgotModal.style.display = 'none'; forgotStatus.textContent = ''; });

  if (sendForgotBtn) sendForgotBtn.addEventListener('click', async () => {
    const email = forgotEmail.value.trim();
    if (!email) return forgotStatus.textContent = 'Enter your email';
    forgotStatus.textContent = 'Sending...';
    try {
      const res = await fetch('/api/auth/forgot', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }) });
      const j = await res.json();
      forgotStatus.textContent = j.message || 'If that email exists we sent a reset link';
    } catch (e) {
      forgotStatus.textContent = 'Error sending reset link';
    }
  });

  // ===== LOGIN =====
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    authError.style.display = 'none';
    
    const input = document.getElementById('loginInput').value.trim();
    const password = document.getElementById('loginPassword').value;
    const loginType = document.querySelector('input[name="loginType"]:checked').value;

    // Check for admin mode
    if (input === 'admin' && password === 'wimpykid') {
      currentUserId = 'admin_' + Date.now();
      currentUser = { 
        username: '👑 ADMIN', 
        avatar: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect fill="%23d4af37" width="100" height="100"/><text x="50" y="70" font-size="60" text-anchor="middle" fill="%230a0e27">👑</text></svg>',
        bio: 'Wimpex Creator', 
        friends: [], 
        followers: [] 
      };
      currentToken = 'admin_token_' + Date.now();
      isAdmin = true;
      saveSession();
      onAuthSuccess();
      showAdminPanel();
      return;
    }

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input, password, loginType })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error);
      }

      const data = await res.json();
      if (data.need2FA) {
        temp2FAToken = data.tempToken;
        if (twoFaLoginArea) twoFaLoginArea.style.display = 'block';
        if (twoFaSetupArea) twoFaSetupArea.style.display = 'none';
        if (twoFaModal) twoFaModal.style.display = 'flex';
        if (twoFaLoginStatus) twoFaLoginStatus.textContent = '';
        return;
      }

      const { userId, username, avatar, token } = data;
      currentUserId = userId;
      currentUser = { username, avatar, bio: 'New to Wimpex ✨', friends: [], followers: [] };
      currentToken = token;
      isAdmin = false;

      saveSession();
      onAuthSuccess();
      loadFriends();
    } catch (err) {
      authError.textContent = err.message;
      authError.style.display = 'block';
    }
  });

  // ===== SIGNUP =====
  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    authError.style.display = 'none';

    const username = document.getElementById('signupUsername').value.trim();
    const phone = document.getElementById('signupPhone').value.trim();
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;
    const confirm = document.getElementById('signupConfirm').value;
    const gender = document.querySelector('input[name="gender"]:checked')?.value;

    if (!gender) {
      authError.textContent = 'Please select a gender';
      authError.style.display = 'block';
      return;
    }

    if (password !== confirm) {
      authError.textContent = 'Passwords do not match';
      authError.style.display = 'block';
      return;
    }

    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, email, phone, password, gender })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error);
      }

      const { userId, avatar, token } = await res.json();
      currentUserId = userId;
      currentUser = { username, avatar, bio: 'New to Wimpex ✨', gender, friends: [], followers: [] };
      currentToken = token;
      isAdmin = false;

      saveSession();
      onAuthSuccess();
      loadFriends();
    } catch (err) {
      authError.textContent = err.message;
      authError.style.display = 'block';
    }
  });

  async function onAuthSuccess() {
    authContainer.style.display = 'none';
    topbar.style.display = 'flex';
    mainContainer.style.display = 'block';
    if (!isAdmin) connectWebSocket();
    updateProfile();
    if (!isAdmin) {
      await checkOnboarding();
      loadStories();
    }
  }

  // Check onboarding status via settings and show modal if incomplete
  async function checkOnboarding() {
    try {
      const res = await fetch('/api/settings', { headers: { 'authorization': `Bearer ${currentToken}` } });
      if (!res.ok) return;
      const user = await res.json();
      // update current user with latest server state
      currentUser = Object.assign({}, currentUser, user);
      saveSession();
      if (!user.onboardingComplete) {
        showOnboarding();
      }
    } catch (e) {
      console.warn('Onboarding check failed', e);
    }
  }

  function showOnboarding() {
    if (!onboardingModal) return;
    onboardingModal.style.display = 'flex';
    onboardingStep1 && (onboardingStep1.style.display = 'block');
    onboardingStep2 && (onboardingStep2.style.display = 'none');
    onboardingStep3 && (onboardingStep3.style.display = 'none');
    if (onboardingStatus) onboardingStatus.textContent = '';
  }

  function hideOnboarding() {
    if (!onboardingModal) return;
    onboardingModal.style.display = 'none';
  }

  if (onboardingNext1) onboardingNext1.addEventListener('click', () => {
    if (onboardingStep1) onboardingStep1.style.display = 'none';
    if (onboardingStep2) onboardingStep2.style.display = 'block';
  });

  if (onboardingNext2) onboardingNext2.addEventListener('click', () => {
    if (onboardingStep2) onboardingStep2.style.display = 'none';
    if (onboardingStep3) onboardingStep3.style.display = 'block';
  });

  async function completeOnboarding() {
    if (!currentToken) return;
    if (onboardingStatus) onboardingStatus.textContent = 'Saving...';
    try {
      const res = await fetch('/api/onboarding/complete', { method: 'POST', headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' } });
      if (!res.ok) {
        const j = await res.json();
        if (onboardingStatus) onboardingStatus.textContent = j.error || 'Failed to save';
        return;
      }
      currentUser.onboardingComplete = true;
      saveSession();
      if (onboardingStatus) onboardingStatus.textContent = '';
      hideOnboarding();
      alert('Onboarding complete — enjoy Wimpex!');
    } catch (e) {
      console.error('Complete onboarding error', e);
      if (onboardingStatus) onboardingStatus.textContent = 'Network error';
    }
  }

  if (onboardingFinish) onboardingFinish.addEventListener('click', completeOnboarding);
  if (onboardingSkip) onboardingSkip.addEventListener('click', () => { hideOnboarding(); });

  // ===== ADMIN PANEL =====
  function showAdminPanel() {
    storiesView.innerHTML = `
      <div style="padding: 20px; color: #d4af37; text-align: center;">
        <h2>👑 ADMIN DASHBOARD 👑</h2>
        <p>Welcome, Wimpex Creator!</p>
        <button onclick="location.reload()" style="padding: 10px 20px; background: #d4af37; color: #0a0e27; border: none; border-radius: 8px; cursor: pointer; font-weight: bold;">Reset App</button>
        <div style="margin-top: 20px; padding: 20px; background: rgba(212, 175, 55, 0.1); border-radius: 8px;">
          <h3>Admin Stats</h3>
          <p>🔑 Admin Mode Active</p>
          <p>✨ Wimpex Status: Operational</p>
          <p>💾 Database: Persistent JSON</p>
          <p>🔐 Auth: JWT + Bcrypt</p>
        </div>
      </div>
    `;
  }

  // ===== LOGOUT =====
  logoutBtn.addEventListener('click', () => {
    clearSession();
    if (ws) ws.close();
    authContainer.style.display = 'flex';
    topbar.style.display = 'none';
    mainContainer.style.display = 'none';
    conversations.clear();
    document.getElementById('loginEmail').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('signupUsername').value = '';
    document.getElementById('signupEmail').value = '';
    document.getElementById('signupPassword').value = '';
    document.getElementById('signupConfirm').value = '';
  });

  // ===== WEBSOCKET =====
  function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}`);

    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ type: 'auth', token: currentToken }));
      console.log('✨ Connected to Wimpex');
    });

    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }

      if (msg.type === 'new-message') {
        const { from, fromUsername, text, time } = msg;
        const convoId = [currentUserId, from].sort().join('-');
        if (!conversations.has(convoId)) conversations.set(convoId, []);
        conversations.get(convoId).push({ from, text, time });
        appendMessage(fromUsername, text, 'other');
        playNotification();
      }

      if (msg.type === 'snap-notification') {
        const { fromUsername } = msg;
        alert(`🔥 New snap from ${fromUsername}!`);
      }

      if (msg.type === 'user-typing') {
        chatName.innerHTML = chatName.textContent.replace(' ✍️ typing...', '') + ' <span style="color:#d4af37">✍️ typing...</span>';
      }
    });

    ws.addEventListener('close', () => {
      if (!isAdmin) setTimeout(connectWebSocket, 3000);
    });
  }

  // ===== NAVIGATION =====
  function switchView(view) {
    document.querySelectorAll('.view').forEach(v => v.style.display = 'none');
    view.style.display = 'block';

    document.querySelectorAll('.nav-btn:not(#logoutBtn)').forEach(b => b.classList.remove('active'));
    if (view === storiesView) storiesBtn.classList.add('active');
    if (view === chatsView) chatsBtn.classList.add('active');
    if (view === cameraView) cameraBtn.classList.add('active');
    if (view === profileView) profileBtn.classList.add('active');

    if (view === cameraView) initCamera();
  }

  storiesBtn.addEventListener('click', () => { 
    if (!isAdmin) { switchView(storiesView); loadStories(); }
    else switchView(storiesView);
  });
  chatsBtn.addEventListener('click', () => { if (!isAdmin) switchView(chatsView); });
  cameraBtn.addEventListener('click', () => { if (!isAdmin) switchView(cameraView); });
  profileBtn.addEventListener('click', () => { if (!isAdmin) { switchView(profileView); updateProfile(); } });

  // Settings button
  const settingsBtn = document.getElementById('settingsBtn');
  settingsBtn.addEventListener('click', () => {
    if (!isAdmin) { switchView(settingsView); loadSettings(); }
  });
  const enableNotificationsBtn = document.getElementById('enableNotificationsBtn');

  // Recommendations button
  const recommendationsBtn = document.getElementById('recommendationsBtn');
  recommendationsBtn.addEventListener('click', () => {
    if (!isAdmin) { switchView(recommendationsView); loadRecommendations(); }
  });

  // ===== 2FA UI Handlers =====
  if (enable2faBtn) enable2faBtn.addEventListener('click', async () => {
    if (!currentToken) return alert('Please log in to enable 2FA');
    if (twoFaSetupArea) twoFaSetupArea.style.display = 'none';
    if (twoFaLoginArea) twoFaLoginArea.style.display = 'none';
    if (twoFaModal) twoFaModal.style.display = 'flex';
    if (twoFaSetupStatus) twoFaSetupStatus.textContent = 'Loading...';
    try {
      const res = await fetch('/api/2fa/setup', { headers: { 'authorization': `Bearer ${currentToken}` } });
      const j = await res.json();
      if (!res.ok) { if (twoFaSetupStatus) twoFaSetupStatus.textContent = j.error || 'Error'; return; }
      if (twoFaQr) twoFaQr.src = j.qr;
      if (twoFaSecret) twoFaSecret.textContent = j.secret;
      if (twoFaSetupArea) twoFaSetupArea.style.display = 'block';
      if (twoFaSetupStatus) twoFaSetupStatus.textContent = '';
    } catch (e) {
      if (twoFaSetupStatus) twoFaSetupStatus.textContent = 'Error';
    }
  });

  if (cancel2faBtn) cancel2faBtn.addEventListener('click', () => {
    if (twoFaModal) twoFaModal.style.display = 'none';
    if (twoFaSetupStatus) twoFaSetupStatus.textContent = '';
    if (twoFaLoginStatus) twoFaLoginStatus.textContent = '';
    if (twoFaSetupCode) twoFaSetupCode.value = '';
    if (twoFaLoginCode) twoFaLoginCode.value = '';
  });

  if (confirm2faBtn) confirm2faBtn.addEventListener('click', async () => {
    const code = twoFaSetupCode?.value.trim();
    if (!code) { if (twoFaSetupStatus) twoFaSetupStatus.textContent = 'Enter code'; return; }
    if (twoFaSetupStatus) twoFaSetupStatus.textContent = 'Verifying...';
    try {
      const res = await fetch('/api/2fa/verify', { method: 'POST', headers: { 'content-type': 'application/json', 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ code }) });
      const j = await res.json();
      if (!res.ok) { if (twoFaSetupStatus) twoFaSetupStatus.textContent = j.error || 'Invalid code'; return; }
      if (twoFaModal) twoFaModal.style.display = 'none';
      if (twoFaSetupStatus) twoFaSetupStatus.textContent = '';
      alert('2FA enabled');
    } catch (e) { if (twoFaSetupStatus) twoFaSetupStatus.textContent = 'Error verifying'; }
  });

  if (disable2faBtn) disable2faBtn.addEventListener('click', async () => {
    if (!currentToken) return alert('Please log in to disable 2FA');
    const code = prompt('Enter current 2FA code to disable');
    if (!code) return;
    try {
      const res = await fetch('/api/2fa/disable', { method: 'POST', headers: { 'content-type': 'application/json', 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ code }) });
      const j = await res.json();
      if (!res.ok) return alert(j.error || 'Failed to disable 2FA');
      alert('2FA disabled');
    } catch (e) { alert('Error disabling 2FA'); }
  });

  if (submit2faLoginBtn) submit2faLoginBtn.addEventListener('click', async () => {
    const code = twoFaLoginCode?.value.trim();
    if (!code) { if (twoFaLoginStatus) twoFaLoginStatus.textContent = 'Enter code'; return; }
    if (twoFaLoginStatus) twoFaLoginStatus.textContent = 'Verifying...';
    try {
      const res = await fetch('/api/auth/login-2fa', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tempToken: temp2FAToken, code }) });
      const j = await res.json();
      if (!res.ok) { if (twoFaLoginStatus) twoFaLoginStatus.textContent = j.error || 'Invalid code'; return; }
      const { userId, username, avatar, token } = j;
      currentUserId = userId;
      currentUser = { username, avatar, bio: 'New to Wimpex ✨', friends: [], followers: [] };
      currentToken = token;
      isAdmin = false;
      saveSession();
      if (twoFaModal) twoFaModal.style.display = 'none';
      if (twoFaLoginStatus) twoFaLoginStatus.textContent = '';
      onAuthSuccess();
      loadFriends();
    } catch (e) { if (twoFaLoginStatus) twoFaLoginStatus.textContent = 'Error during verify'; }
  });

  if (cancel2faLoginBtn) cancel2faLoginBtn.addEventListener('click', () => { if (twoFaModal) twoFaModal.style.display = 'none'; temp2FAToken = null; if (twoFaLoginStatus) twoFaLoginStatus.textContent = ''; });

  // ===== PUSH NOTIFICATIONS (Service Worker & Subscriptions) =====
  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
    return outputArray;
  }

  async function registerSW() {
    if ('serviceWorker' in navigator) {
      try {
        const reg = await navigator.serviceWorker.register('/service-worker.js');
        return reg;
      } catch (e) { console.error('SW registration failed', e); }
    }
    return null;
  }

  async function subscribePush() {
    if (!currentToken) return alert('Log in to enable notifications');
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return alert('Push not supported in this browser');
    const reg = await registerSW();
    if (!reg) return;
    // ask server for VAPID public key
    const pkRes = await fetch('/api/push/publicKey');
    const pkJson = await pkRes.json();
    const publicKey = pkJson.publicKey;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(publicKey) });
    // send to server
    await fetch('/api/push/subscribe', { method: 'POST', headers: { 'content-type': 'application/json', 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ subscription: sub }) });
    localStorage.setItem('wimpex_push_endpoint', sub.endpoint);
    if (enableNotificationsBtn) enableNotificationsBtn.textContent = '🔕';
    alert('Notifications enabled');
  }

  async function unsubscribePush() {
    if (!('serviceWorker' in navigator)) return;
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return;
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return;
    const endpoint = sub.endpoint;
    await sub.unsubscribe();
    await fetch('/api/push/unsubscribe', { method: 'POST', headers: { 'content-type': 'application/json', 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ endpoint }) });
    localStorage.removeItem('wimpex_push_endpoint');
    if (enableNotificationsBtn) enableNotificationsBtn.textContent = '🔔';
    alert('Notifications disabled');
  }

  if (enableNotificationsBtn) enableNotificationsBtn.addEventListener('click', async () => {
    try {
      if (Notification.permission === 'granted') {
        // toggle off
        await unsubscribePush();
      } else if (Notification.permission === 'denied') {
        alert('Notifications are blocked in your browser. Please enable them in site settings.');
      } else {
        const perm = await Notification.requestPermission();
        if (perm === 'granted') await subscribePush();
      }
    } catch (e) { console.error('Push error', e); alert('Failed to toggle notifications'); }
  });

  // try to register SW on load to make subscription fast
  if ('serviceWorker' in navigator) {
    registerSW().then(() => {
      // update button state
      navigator.serviceWorker.getRegistration().then(async (reg) => {
        if (!reg) return;
        const sub = await reg.pushManager.getSubscription();
        if (sub && enableNotificationsBtn) enableNotificationsBtn.textContent = '🔕';
      });
    });
  }

  // ===== MEDIA CDN UPLOAD HELPERS =====
  function dataURLtoBlob(dataurl) {
    const arr = dataurl.split(',');
    const match = arr[0].match(/:(.*?);/);
    const mime = match ? match[1] : 'application/octet-stream';
    const bstr = atob(arr[1]);
    let n = bstr.length;
    const u8arr = new Uint8Array(n);
    while (n--) u8arr[n] = bstr.charCodeAt(n);
    return new Blob([u8arr], { type: mime });
  }

  async function uploadMediaToCDN(dataUrl, filename = 'upload.jpg') {
    // Try presign first
    try {
      const pk = await fetch('/api/upload/presign?filename=' + encodeURIComponent(filename) + '&contentType=' + encodeURIComponent(dataUrl.split(':')[1].split(';')[0]), {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      if (pk.ok) {
        const pres = await pk.json();
        const blob = dataURLtoBlob(dataUrl);
        const put = await fetch(pres.url, { method: 'PUT', body: blob, headers: { 'Content-Type': blob.type } });
        if (put.ok) return { ok: true, url: pres.publicUrl };
      }
    } catch (e) {
      console.warn('Presign upload failed', e);
    }

    // Fallback: server-side CDN endpoint
    try {
      const res = await fetch('/api/upload/cdn', { method: 'POST', headers: { 'content-type': 'application/json', 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ filename, data: dataUrl }) });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('Server CDN upload failed', e);
    }

    // Final fallback: return original dataUrl so existing endpoints can accept it
    return { ok: false, url: dataUrl };
  }

  // ===== STORIES =====
  async function loadStories() {
    try {
      const res = await fetch('/api/stories', {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      const stories = await res.json();
      storiesGrid.innerHTML = '';

      stories.forEach(story => {
        const card = document.createElement('div');
        card.className = 'story-card';
        card.innerHTML = `<img src="${story.media}" alt=""><div class="user-info">${story.username}</div>`;
        card.addEventListener('click', () => viewStory(story));
        storiesGrid.appendChild(card);
      });
    } catch (err) {
      console.error('Error loading stories:', err);
    }
  }

  function viewStory(story) {
    const modal = document.getElementById('storyViewerModal');
    const storyImage = document.getElementById('storyImage');
    const storyVideo = document.getElementById('storyVideo');
    const storyUsername = document.getElementById('storyUsername');
    const storyTimestamp = document.getElementById('storyTimestamp');

    if (story.media.endsWith('.mp4') || story.media.includes('video')) {
      storyImage.style.display = 'none';
      storyVideo.style.display = 'block';
      storyVideo.src = story.media;
    } else {
      storyImage.style.display = 'block';
      storyVideo.style.display = 'none';
      storyImage.src = story.media;
    }

    storyUsername.textContent = story.username;
    storyTimestamp.textContent = new Date(story.createdAt).toLocaleTimeString();
    modal.style.display = 'block';

    fetch(`/api/stories/${story.storyId}/view`, {
      method: 'POST',
      headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ viewerId: currentUserId })
    });

    const closeBtn = document.getElementById('closeStoryViewer');
    closeBtn.onclick = () => modal.style.display = 'none';
  }

  newStoryBtn.addEventListener('click', () => {
    if (!isAdmin) {
      switchView(cameraView);
      snapRecipient.value = 'story';
    }
  });

  // ===== CAMERA =====
  async function initCamera() {
    if (localStream) return;
    try {
      localStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: false });
      cameraStream.srcObject = localStream;
    } catch (err) {
      alert('Camera access denied');
    }
  }

  function applyFilter(filter) {
    cameraStream.style.filter = {
      'none': 'none',
      'sepia': 'sepia(100%)',
      'grayscale': 'grayscale(100%)',
      'invert': 'invert(100%)',
      'blur': 'blur(8px)'
    }[filter] || 'none';
    currentFilter = filter;
  }

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyFilter(btn.dataset.filter);
    });
  });

  snapBtn.addEventListener('click', () => {
    const ctx = snapCanvas.getContext('2d');
    snapCanvas.width = cameraStream.videoWidth;
    snapCanvas.height = cameraStream.videoHeight;
    ctx.drawImage(cameraStream, 0, 0);
    snapImage.src = snapCanvas.toDataURL('image/jpeg', 0.8);
    snapPreview.style.display = 'block';
  });

  resnapBtn.addEventListener('click', () => {
    snapPreview.style.display = 'none';
  });

  recordBtn.addEventListener('click', async () => {
    if (!mediaRecorder) {
      recordedChunks = [];
      const mimeType = 'video/webm;codecs=vp8,opus';
      mediaRecorder = new MediaRecorder(localStream, { mimeType });
      mediaRecorder.ondataavailable = (e) => recordedChunks.push(e.data);
      mediaRecorder.onstop = () => {
        const blob = new Blob(recordedChunks, { type: 'video/webm' });
        const reader = new FileReader();
        reader.onload = () => {
          snapImage.src = reader.result;
          snapPreview.style.display = 'block';
        };
        reader.readAsDataURL(blob);
      };
      mediaRecorder.start();
      recordBtn.style.background = 'rgba(212, 175, 55, 0.6)';
      recordBtn.textContent = '⏹ Stop';
    } else {
      mediaRecorder.stop();
      mediaRecorder = null;
      recordBtn.style.background = 'rgba(212, 175, 55, 0.2)';
      recordBtn.textContent = '⏺ Record';
    }
  });

  swapCameraBtn.addEventListener('click', async () => {
    if (localStream) {
      localStream.getTracks().forEach(t => t.stop());
      localStream = null;
      const facing = cameraStream.videoWidth > cameraStream.videoHeight ? 'environment' : 'user';
      localStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facing }, audio: false });
      cameraStream.srcObject = localStream;
    }
  });

  sendSnapBtn.addEventListener('click', async () => {
    const recipient = snapRecipient.value.trim();
    if (!recipient) return alert('Enter recipient or "story"');

    const media = snapImage.src;
    try {
      // UI: show uploading state
      sendSnapBtn.disabled = true; sendSnapBtn.textContent = 'Uploading...';
      // Upload media to CDN if possible and get a public URL
      const uploadRes = await uploadMediaToCDN(media, 'snap.jpg');
      const mediaUrl = uploadRes.url || media;

      if (recipient.toLowerCase() === 'story') {
        await fetch('/api/stories', {
          method: 'POST',
          headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({ media: mediaUrl })
        });
        alert('✨ Story posted!');
        loadStories();
      } else {
        const searchRes = await fetch(`/api/search?q=${recipient}`, {
          headers: { 'authorization': `Bearer ${currentToken}` }
        });
        const results = await searchRes.json();
        const user = results[0];
        if (user) {
          await fetch('/api/snaps', {
            method: 'POST',
            headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
            body: JSON.stringify({ toId: user.userId, media: mediaUrl })
          });
          ws.send(JSON.stringify({ type: 'snap-sent', toId: user.userId }));
          alert(`📸 Snap sent!`);
        } else {
          alert('User not found');
        }
      }
      snapPreview.style.display = 'none';
      snapRecipient.value = '';
    } catch (err) {
      alert('Error sending snap: ' + err.message);
    }
    finally {
      // restore button state
      sendSnapBtn.disabled = false; sendSnapBtn.textContent = 'Send Snap';
    }
  });

  // ===== CHAT =====
  function selectChat(otherUserId, otherUsername) {
    chatName.textContent = otherUsername;
    const convoId = [currentUserId, otherUserId].sort().join('-');
    messagesLog.innerHTML = '';
    chatDetail.style.display = 'block';

    const msgs = conversations.get(convoId) || [];
    msgs.forEach(msg => {
      appendMessage(msg.from === currentUserId ? currentUser.username : otherUsername, msg.text, msg.from === currentUserId ? 'own' : 'other');
    });

    window.currentConvoId = convoId;
    window.currentOtherId = otherUserId;
  }

  function appendMessage(sender, text, type) {
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${type}`;
    msgDiv.textContent = text;
    messagesLog.appendChild(msgDiv);
    messagesLog.scrollTop = messagesLog.scrollHeight;
  }

  messageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text) return;

    appendMessage(currentUser.username, text, 'own');

    ws.send(JSON.stringify({
      type: 'message',
      toId: window.currentOtherId,
      text
    }));

    const convoId = window.currentConvoId;
    if (!conversations.has(convoId)) conversations.set(convoId, []);
    conversations.get(convoId).push({ from: currentUserId, text, time: Date.now() });

    try {
      await fetch('/api/messages', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ toId: window.currentOtherId, text })
      });
    } catch (err) {
      console.error('Error saving message:', err);
    }

    messageInput.value = '';
  });

  backToChats.addEventListener('click', () => {
    chatDetail.style.display = 'none';
  });

  newChatBtn.addEventListener('click', () => {
    const username = prompt('Enter username to chat with:');
    if (username) {
      const user = Array.from(contacts.values()).find(u => u.username === username);
      if (user) {
        selectChat(user.userId, user.username);
      } else {
        alert('User not found');
      }
    }
  });

  // ===== PROFILE =====
  function updateProfile() {
    profileAvatar.src = currentUser.avatar;
    profileName.textContent = currentUser.username;
    profileBio.textContent = currentUser.bio;
    friendCount.textContent = currentUser.friends?.length || 0;
    storyCount.textContent = Math.floor(Math.random() * 10);
  }

  editProfileBtn.addEventListener('click', () => {
    editBio.value = currentUser.bio;
    editProfileModal.style.display = 'block';
  });

  editProfileForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/users/${currentUserId}`, {
        method: 'PUT',
        headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ bio: editBio.value })
      });
      const updated = await res.json();
      currentUser.bio = updated.bio;
      saveSession();
      updateProfile();
      editProfileModal.style.display = 'none';
    } catch (err) {
      alert('Error updating profile');
    }
  });

  // ===== FRIENDS =====
  async function loadFriends() {
    try {
      const res = await fetch('/api/friends', {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      const friends = await res.json();
      currentUser.friends = friends.map(f => f.userId);
      updateProfile();
    } catch (err) {
      console.error('Error loading friends:', err);
    }
  }

  const friendsModal = document.getElementById('friendsModal');
  const addFriendForm = document.getElementById('addFriendForm');
  const friendInput = document.getElementById('friendInput');
  const friendsList = document.getElementById('friendsList');
  const closeModalBtn = document.querySelector('.close-modal-btn');
  const addFriendsBtn = document.getElementById('addFriendsBtn');

  addFriendsBtn.addEventListener('click', () => {
    friendsModal.style.display = 'block';
    displayFriends();
  });

  addFriendForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = friendInput.value.trim();
    if (!query) return;

    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      const results = await res.json();
      
      if (results.length === 0) {
        alert('No users found');
        return;
      }

      const user = results[0];
      if (user.isFriend) {
        alert('Already friends with this user');
        return;
      }

      const addRes = await fetch('/api/friends/add', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ targetId: user.userId })
      });

      if (!addRes.ok) throw new Error('Failed to add friend');

      friendInput.value = '';
      await loadFriends();
      displayFriends();
      alert(`✨ Added ${user.username} as friend!`);
    } catch (err) {
      alert('Error: ' + err.message);
    }
  });

  function displayFriends() {
    friendsList.innerHTML = '';
    if (!currentUser.friends || currentUser.friends.length === 0) {
      friendsList.innerHTML = '<p style="text-align:center;color:#999;">No friends yet. Add one!</p>';
      return;
    }

    currentUser.friends.forEach(friendId => {
      // In a real app, you'd fetch friend details. For now, show the ID
      const item = document.createElement('div');
      item.className = 'friend-item';
      item.innerHTML = `
        <div class="friend-info">
          <div class="friend-name">Friend ${friendId.substring(0, 6)}</div>
          <div class="friend-detail">ID: ${friendId}</div>
        </div>
        <div class="friend-actions">
          <button onclick="removeFriend('${friendId}')">Remove</button>
        </div>
      `;
      friendsList.appendChild(item);
    });
  }

  window.removeFriend = async function(friendId) {
    if (confirm('Remove this friend?')) {
      try {
        const res = await fetch('/api/friends/remove', {
          method: 'POST',
          headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({ targetId: friendId })
        });
        if (res.ok) {
          await loadFriends();
          displayFriends();
          alert('Friend removed');
        }
      } catch (err) {
        alert('Error removing friend');
      }
    }
  };

  closeModalBtn.addEventListener('click', () => {
    friendsModal.style.display = 'none';
  });
  // ===== RECOMMENDATIONS =====
  const recommendationsList = document.getElementById('recommendationsList');
  const noRecommendations = document.getElementById('noRecommendations');

  async function loadRecommendations() {
    try {
      const res = await fetch('/api/recommendations', {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      const recommendations = await res.json();

      recommendationsList.innerHTML = '';
      
      if (recommendations.length === 0) {
        noRecommendations.classList.remove('hidden');
        return;
      }

      noRecommendations.classList.add('hidden');

      recommendations.forEach(user => {
        const card = document.createElement('div');
        card.className = 'recommendation-card';
        const genderEmoji = user.gender === 'male' ? '♂️' : user.gender === 'female' ? '♀️' : '✨';
        
        card.innerHTML = `
          <img src="${user.avatar}" alt="" class="rec-avatar">
          <div class="rec-info">
            <h4>${user.username} ${genderEmoji}</h4>
            <p class="rec-bio">${user.bio}</p>
            <p class="rec-mutual">${user.mutualFriends > 0 ? `${user.mutualFriends} mutual friend${user.mutualFriends > 1 ? 's' : ''}` : 'No mutual friends'}</p>
          </div>
          <button class="rec-add-btn" onclick="addRecommendedFriend('${user.userId}')">Add</button>
        `;
        recommendationsList.appendChild(card);
      });
    } catch (err) {
      console.error('Error loading recommendations:', err);
    }
  }

  window.addRecommendedFriend = async function(userId) {
    try {
      const res = await fetch('/api/friends/add', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${currentToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ targetId: userId })
      });

      if (!res.ok) throw new Error('Failed to add friend');

      await loadFriends();
      await loadRecommendations();
      alert('✨ Friend added!');
    } catch (err) {
      alert('Error: ' + err.message);
    }
  };
  // ===== SETTINGS =====
  const settingsForm = document.getElementById('settingsForm');
  const settingsAvatarPreview = document.getElementById('settingsAvatarPreview');
  const uploadAvatarBtn = document.getElementById('uploadAvatarBtn');
  const avatarInput = document.getElementById('avatarInput');
  const avatarUploadProgress = document.getElementById('avatarUploadProgress');
  const avatarUploadBar = avatarUploadProgress && avatarUploadProgress.querySelector('.progress-bar');
  const settingsUsername = document.getElementById('settingsUsername');
  const settingsEmail = document.getElementById('settingsEmail');
  const settingsPhone = document.getElementById('settingsPhone');
  const settingsBio = document.getElementById('settingsBio');
  const bioCharCount = document.getElementById('bioCharCount');
  const settingsStatus = document.getElementById('settingsStatus');

  async function loadSettings() {
    try {
      const res = await fetch('/api/settings', {
        headers: { 'authorization': `Bearer ${currentToken}` }
      });
      const user = await res.json();

      settingsAvatarPreview.src = user.avatar;
      settingsUsername.value = user.username;
      settingsEmail.value = user.email;
      settingsPhone.value = user.phone || '';
      settingsBio.value = user.bio;
      updateBioCharCount();
    } catch (err) {
      console.error('Error loading settings:', err);
    }
  }

  uploadAvatarBtn.addEventListener('click', () => {
    avatarInput.click();
  });

  avatarInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (file.size > 5000000) {
      alert('Image too large (max 5MB)');
      return;
    }

    const reader = new FileReader();
    reader.onload = async (event) => {
      // show immediate preview
      settingsAvatarPreview.src = event.target.result;
      // start upload to CDN with progress
      if (!currentToken) return; // must be logged in
      // UI: indicate uploading
      uploadAvatarBtn.disabled = true; uploadAvatarBtn.textContent = 'Uploading...';
      if (avatarUploadProgress) avatarUploadProgress.classList.remove('hidden');
      try {
        // get presigned url
        const filename = file.name || 'avatar.jpg';
        const pkRes = await fetch('/api/upload/presign?filename=' + encodeURIComponent(filename) + '&contentType=' + encodeURIComponent(file.type), { headers: { 'authorization': `Bearer ${currentToken}` } });
        if (pkRes.ok) {
          const pres = await pkRes.json();
          // upload with XHR to track progress
          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('PUT', pres.url);
            xhr.setRequestHeader('Content-Type', file.type);
            xhr.upload.onprogress = (ev) => {
              if (ev.lengthComputable && avatarUploadBar) {
                const pct = Math.round((ev.loaded / ev.total) * 100);
                avatarUploadBar.style.width = pct + '%';
              }
            };
            xhr.onload = () => {
              if (xhr.status >= 200 && xhr.status < 300) resolve(); else reject(new Error('Upload failed ' + xhr.status));
            };
            xhr.onerror = () => reject(new Error('Network error'));
            xhr.send(file);
          });
          // update preview to public URL
          settingsAvatarPreview.src = pres.publicUrl;
        } else {
          // fallback to server-side CDN upload
          const fd = new FormData();
          fd.append('file', file);
          await fetch('/api/upload/cdn', { method: 'POST', headers: { 'authorization': `Bearer ${currentToken}` }, body: JSON.stringify({ filename, data: event.target.result }) });
        }
      } catch (err) {
        console.error('Avatar upload error', err);
        alert('Avatar upload failed');
      } finally {
        uploadAvatarBtn.disabled = false; uploadAvatarBtn.textContent = '📷 Change Avatar';
        if (avatarUploadProgress) { setTimeout(() => { avatarUploadProgress.classList.add('hidden'); if (avatarUploadBar) avatarUploadBar.style.width = '0%'; }, 800); }
      }
    };
    reader.readAsDataURL(file);
  });

  settingsBio.addEventListener('input', updateBioCharCount);

  function updateBioCharCount() {
    const count = settingsBio.value.length;
    bioCharCount.textContent = `${count}/200 characters`;
  }

  settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    settingsStatus.classList.add('hidden');

    try {
      const updates = {
        username: settingsUsername.value.trim(),
        email: settingsEmail.value.trim(),
        phone: settingsPhone.value.trim(),
        bio: settingsBio.value.trim(),
        avatar: settingsAvatarPreview.src
      };

      // Validate
      if (!updates.username) {
        showSettingsStatus('Username required', 'error');
        return;
      }

      if (updates.username.length < 3) {
        showSettingsStatus('Username must be at least 3 characters', 'error');
        return;
      }

      if (updates.bio.length > 200) {
        showSettingsStatus('Bio too long (max 200 characters)', 'error');
        return;
      }

      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: {
          'authorization': `Bearer ${currentToken}`,
          'content-type': 'application/json'
        },
        body: JSON.stringify(updates)
      });

      if (!res.ok) {
        const err = await res.json();
        showSettingsStatus(err.error, 'error');
        return;
      }

      const updated = await res.json();
      currentUser = updated;
      saveSession();
      updateProfile();

      showSettingsStatus('✨ Profile updated successfully!', 'success');
      setTimeout(() => {
        showSettingsStatus('', '');
      }, 3000);
    } catch (err) {
      showSettingsStatus('Error saving settings: ' + err.message, 'error');
    }
  });

  function showSettingsStatus(message, type) {
    settingsStatus.textContent = message;
    settingsStatus.className = 'status-message ' + type;
    if (message) {
      settingsStatus.classList.remove('hidden');
    } else {
      settingsStatus.classList.add('hidden');
    }
  }

  // ===== HELPERS =====
  function playNotification() {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    osc.frequency.value = 800;
    osc.connect(ctx.destination);
    osc.start();
    setTimeout(() => osc.stop(), 50);
  }

  let contacts = new Map();

  // ===== INIT =====
  if (loadSession()) {
    onAuthSuccess();
    if (isAdmin) showAdminPanel();
  } else {
    authContainer.style.display = 'flex';
  }

  console.log('🌟 Wimpex loaded');
})();
