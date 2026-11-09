/*
 * D-Send v2 — interface.
 * Règle de sécurité : aucune donnée utilisateur n'est insérée avec innerHTML.
 * Tout passe par textContent ou des éléments créés un par un (protection XSS).
 */
(() => {
  const C = DSendCrypto;
  const $ = (id) => document.getElementById(id);
  const MAX_FILE = 8 * 1024 * 1024;

  const state = { csrf: '', user: null, key: null, contacts: [], peer: null, lastId: 0, seen: new Set(), mode: 'login', timers: [] };

  /* ---------- API ---------- */
  async function api(action, { method = 'GET', body = null, query = '' } = {}) {
    const res = await fetch('api.php?action=' + action + query, {
      method,
      credentials: 'same-origin',
      headers: method === 'POST' ? { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf } : {},
      body: body ? JSON.stringify(body) : null,
    });
    const data = await res.json().catch(() => ({ error: 'Réponse inattendue du serveur.' }));
    if (data.csrf) state.csrf = data.csrf;
    if (!res.ok) {
      if (res.status === 401 && state.user) { await resetLocal(); show('auth'); }
      throw new Error(data.error || 'Erreur ' + res.status);
    }
    return data;
  }

  /* ---------- Vues ---------- */
  function show(view) {
    for (const v of ['auth', 'unlock', 'app']) $('view-' + v).hidden = v !== view;
  }
  function toast(msg) {
    const t = $('toast'); t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, 3500);
  }
  function setError(id, msg) { const e = $(id); e.textContent = msg || ''; e.hidden = !msg; }

  /* ---------- Authentification ---------- */
  function setMode(mode) {
    state.mode = mode;
    $('tab-login').setAttribute('aria-selected', String(mode === 'login'));
    $('tab-register').setAttribute('aria-selected', String(mode === 'register'));
    $('confirm-wrap').hidden = mode !== 'register';
    $('auth-submit').textContent = mode === 'login' ? 'Se connecter' : 'Créer mon compte';
    $('auth-password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
    setError('auth-error', '');
  }
  $('tab-login').onclick = () => setMode('login');
  $('tab-register').onclick = () => setMode('register');

  $('form-auth').onsubmit = async (e) => {
    e.preventDefault();
    const email = $('auth-email').value.trim().toLowerCase();
    const password = $('auth-password').value;
    setError('auth-error', '');
    if (!email || !$('auth-email').checkValidity()) return setError('auth-error', 'Saisissez une adresse e-mail valide.');
    if (password.length < 10) return setError('auth-error', 'Le mot de passe doit contenir au moins 10 caractères.');
    if (state.mode === 'register' && password !== $('auth-confirm').value) return setError('auth-error', 'Les deux mots de passe ne sont pas identiques.');

    $('auth-submit').disabled = true; $('auth-busy').hidden = false;
    try {
      if (state.mode === 'register') {
        const acct = await C.createAccount(password);
        const data = await api('register', { method: 'POST', body: { email, ...acct.payload } });
        await enterApp(data.user, acct.privateKey);
      } else {
        const { salt } = await api('prelogin', { method: 'POST', body: { email } });
        const { authSecret, wrapKey } = await C.deriveFromPassword(password, salt);
        const data = await api('login', { method: 'POST', body: { email, auth_secret: authSecret } });
        await enterApp(data.user, await C.unlockPrivateKey(data.user, wrapKey));
      }
      $('form-auth').reset();
    } catch (err) {
      setError('auth-error', err.message);
    } finally {
      $('auth-submit').disabled = false; $('auth-busy').hidden = true;
    }
  };

  $('form-unlock').onsubmit = async (e) => {
    e.preventDefault();
    setError('unlock-error', '');
    try {
      const { wrapKey } = await C.deriveFromPassword($('unlock-password').value, state.user.kdf_salt);
      const key = await C.unlockPrivateKey(state.user, wrapKey);
      $('form-unlock').reset();
      await enterApp(state.user, key);
    } catch (err) {
      setError('unlock-error', 'Mot de passe incorrect.');
    }
  };
  $('unlock-logout').onclick = () => logout();

  async function enterApp(user, key) {
    state.user = user; state.key = key;
    await C.storeKey(user.id, key);
    $('me-email').textContent = user.email;
    show('app');
    await loadContacts();
    startPolling();
  }

  async function resetLocal() {
    state.timers.forEach(clearInterval); state.timers = [];
    state.user = null; state.key = null; state.peer = null; state.contacts = [];
    $('messages').replaceChildren(); $('contact-list').replaceChildren();
    $('thread').hidden = true; $('thread-empty').hidden = false;
    await C.wipeKeys();
  }

  async function logout(message) {
    try { await api('logout', { method: 'POST' }); } catch (e) { /* session déjà fermée */ }
    await resetLocal();
    await api('session');
    setMode('login'); show('auth');
    if (message) toast(message);
  }
  $('btn-logout').onclick = () => logout('Vous êtes déconnecté.');
  $('btn-panic').onclick = () => logout('Verrouillage d\'urgence : clés et messages effacés de cet appareil.');

  /* ---------- Contacts ---------- */
  function avatar(el, user) {
    el.className = 'avatar c-' + user.color;
    el.textContent = user.email.charAt(0).toUpperCase();
  }

  async function loadContacts() {
    const { contacts } = await api('contacts');
    state.contacts = contacts;
    const list = $('contact-list');
    list.replaceChildren();
    $('contacts-empty').hidden = contacts.length > 0;
    for (const c of contacts) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'contact' + (state.peer && state.peer.id === c.id ? ' active' : '');
      const av = document.createElement('span'); avatar(av, c);
      const name = document.createElement('span'); name.className = 'contact-name'; name.textContent = c.email;
      const when = document.createElement('span'); when.className = 'contact-when';
      when.textContent = c.last_at ? new Date(c.last_at * 1000).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
      btn.append(av, name, when);
      btn.onclick = () => openThread(c);
      li.append(btn); list.append(li);
    }
  }

  /* ---------- Conversation ---------- */
  async function openThread(peer) {
    state.peer = peer; state.lastId = 0; state.seen.clear();
    $('thread-empty').hidden = true; $('thread').hidden = false;
    $('safety').hidden = true;
    avatar($('peer-avatar'), peer);
    $('peer-email').textContent = peer.email;
    $('messages').replaceChildren();
    for (const b of document.querySelectorAll('.contact')) b.classList.toggle('active', b.querySelector('.contact-name').textContent === peer.email);
    await pullMessages();
    $('msg-input').focus();
  }

  $('btn-safety').onclick = async () => {
    $('safety-number').textContent = await C.safetyNumber(state.user.public_key, state.peer.public_key);
    $('safety').hidden = !$('safety').hidden;
  };

  $('btn-clear').onclick = async () => {
    const btn = $('btn-clear');
    if (btn.dataset.confirm !== '1') { btn.dataset.confirm = '1'; btn.textContent = 'Confirmer la suppression'; setTimeout(() => { btn.dataset.confirm = ''; btn.textContent = 'Supprimer la discussion'; }, 4000); return; }
    btn.dataset.confirm = ''; btn.textContent = 'Supprimer la discussion';
    const { deleted } = await api('delete_conversation', { method: 'POST', body: { with: state.peer.id } });
    $('messages').replaceChildren(); state.lastId = 0; state.seen.clear();
    toast(deleted + ' message(s) supprimé(s) du serveur.');
  };

  async function pullMessages() {
    if (!state.peer || !state.key) return;
    const peer = state.peer;
    const { messages } = await api('messages', { query: '&with=' + peer.id + '&after=' + state.lastId });
    if (peer !== state.peer) return;
    const key = await C.conversationKey(state.key, state.user.id, peer);
    for (const m of messages) {
      state.lastId = Math.max(state.lastId, m.id);
      if (state.seen.has(m.id)) continue;
      state.seen.add(m.id);
      let payload;
      try { payload = await C.decryptJson(key, m.iv, m.ciphertext); }
      catch (e) { payload = { error: true }; }
      renderMessage(m, payload);
    }
    if (messages.length) $('messages').scrollTop = $('messages').scrollHeight;
  }

  /* ---------- Pièces jointes ---------- */
  const FILE_KINDS = [
    ['image', 'Image', /^(png|jpe?g|gif|webp|svg|bmp|heic)$/],
    ['pdf', 'Document PDF', /^pdf$/],
    ['doc', 'Document', /^(docx?|odt|rtf|txt|md)$/],
    ['sheet', 'Tableur', /^(xlsx?|ods|csv)$/],
    ['slides', 'Présentation', /^(pptx?|odp|key)$/],
    ['archive', 'Archive', /^(zip|rar|7z|tar|gz|bz2)$/],
    ['audio', 'Audio', /^(mp3|wav|ogg|m4a|flac|aac)$/],
    ['video', 'Vidéo', /^(mp4|webm|mov|avi|mkv)$/],
  ];

  function formatSize(n) {
    if (n < 1024) return n + ' o';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0).replace('.', ',') + ' Ko';
    return (n / 1048576).toFixed(1).replace('.', ',') + ' Mo';
  }

  // Icône construite élément par élément : aucun innerHTML dans l'application.
  function downloadIcon() {
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: '18', height: '18', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })) svg.setAttribute(k, v);
    for (const d of ['M12 4v11', 'm7 10 5 5 5-5', 'M5 20h14']) { const path = document.createElementNS(NS, 'path'); path.setAttribute('d', d); svg.append(path); }
    return svg;
  }

  function fileCard(url, name, type, size) {
    const ext = (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
    const found = FILE_KINDS.find(([, , re]) => re.test(ext)) || ['other', 'Fichier'];
    const a = document.createElement('a');
    a.href = url; a.download = name; a.className = 'file-card';
    a.title = 'Télécharger ' + name;

    const icon = document.createElement('span');
    icon.className = 'file-icon'; icon.dataset.kind = found[0];
    icon.textContent = (ext || '?').slice(0, 4).toUpperCase();

    const info = document.createElement('span'); info.className = 'file-info';
    const fname = document.createElement('span'); fname.className = 'file-name'; fname.textContent = name;
    const meta = document.createElement('span'); meta.className = 'file-meta';
    meta.textContent = formatSize(size) + ' · ' + found[1];
    info.append(fname, meta);

    const dl = document.createElement('span'); dl.className = 'file-dl'; dl.setAttribute('aria-hidden', 'true');
    dl.append(downloadIcon());

    a.append(icon, info, dl);
    return a;
  }

  function renderMessage(m, p) {
    const mine = Number(m.sender_id) === Number(state.user.id);
    const row = document.createElement('div'); row.className = 'msg ' + (mine ? 'mine' : 'theirs');
    const bubble = document.createElement('div'); bubble.className = 'bubble';
    if (p.error) {
      bubble.classList.add('broken'); bubble.textContent = 'Message illisible : il a été altéré ou chiffré avec une autre clé.';
    } else if (m.kind === 'file') {
      const bytes = C.fromB64(p.data);
      const blob = new Blob([bytes], { type: p.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      bubble.classList.add('has-file');
      if (/^image\/(png|jpe?g|gif|webp)$/.test(p.type)) {
        bubble.classList.add('media');
        const view = document.createElement('a');
        view.href = url; view.target = '_blank'; view.rel = 'noopener'; view.className = 'file-preview';
        view.title = 'Ouvrir l\'image';
        const img = document.createElement('img'); img.src = url; img.alt = p.name; img.loading = 'lazy';
        view.append(img); bubble.append(view);
      }
      bubble.append(fileCard(url, p.name, p.type, bytes.length));
    } else {
      bubble.textContent = p.text;
    }
    const meta = document.createElement('small');
    meta.textContent = new Date(m.created_at * 1000).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    row.append(bubble, meta);
    $('messages').append(row);
  }

  async function send(kind, payload) {
    setError('send-error', '');
    const key = await C.conversationKey(state.key, state.user.id, state.peer);
    const { iv, ciphertext } = await C.encryptJson(key, payload);
    await api('send', { method: 'POST', body: { to: state.peer.id, kind, iv, ciphertext } });
    await pullMessages();
  }

  $('composer').onsubmit = async (e) => {
    e.preventDefault();
    const text = $('msg-input').value.trim();
    if (!text) return;
    $('msg-input').value = '';
    try { await send('text', { text }); } catch (err) { $('msg-input').value = text; setError('send-error', err.message); }
  };

  $('file-input').onchange = async (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    if (f.size > MAX_FILE) return setError('send-error', 'Fichier trop lourd : 8 Mo maximum.');
    try {
      const data = C.toB64(new Uint8Array(await f.arrayBuffer()));
      await send('file', { name: f.name.slice(0, 200), type: f.type, data });
      toast('Fichier chiffré et envoyé.');
    } catch (err) { setError('send-error', err.message); }
  };

  function startPolling() {
    state.timers.forEach(clearInterval);
    state.timers = [
      setInterval(() => pullMessages().catch(() => {}), 3000),
      setInterval(() => loadContacts().catch(() => {}), 15000),
    ];
  }

  /* ---------- Démarrage ---------- */
  (async () => {
    if (!window.crypto || !crypto.subtle) {
      document.body.textContent = 'Ce navigateur ne permet pas le chiffrement (Web Crypto). Utilisez une version récente de Chrome, Firefox ou Safari, en HTTPS.';
      return;
    }
    const { user } = await api('session');
    if (!user) { await C.wipeKeys(); setMode('login'); return show('auth'); }
    state.user = user;
    const key = await C.loadKey(user.id);
    if (key) return enterApp(user, key);
    show('unlock');
  })();
})();
