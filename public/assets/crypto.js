/*
 * D-Send v2 — cryptographie côté navigateur (Web Crypto API).
 *
 * - Le mot de passe ne quitte jamais le navigateur. PBKDF2-SHA-256 (600 000 itérations)
 *   en dérive deux secrets indépendants : un secret d'authentification (envoyé au serveur,
 *   qui le hache en Argon2id) et une clé AES-256 qui chiffre la clé privée de l'utilisateur.
 * - Chaque utilisateur possède une paire de clés ECDH P-256. Le serveur ne stocke que la
 *   clé publique et la clé privée chiffrée.
 * - Deux utilisateurs dérivent la même clé de conversation (ECDH + HKDF-SHA-256) ;
 *   chaque message est chiffré en AES-256-GCM avec un IV aléatoire de 96 bits.
 */
const DSendCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 600000;
  const subtle = crypto.subtle;

  const toB64 = (buf) => {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveFromPassword(password, saltB64) {
    const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations: PBKDF2_ITERATIONS }, base, 512));
    const authSecret = toB64(bits.slice(0, 32));
    const wrapKey = await subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    bits.fill(0);
    return { authSecret, wrapKey };
  }

  async function createAccount(password) {
    const salt = toB64(crypto.getRandomValues(new Uint8Array(16)));
    const { authSecret, wrapKey } = await deriveFromPassword(password, salt);
    const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const pkcs8 = await subtle.exportKey('pkcs8', pair.privateKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encPriv = await subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, pkcs8);
    const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    new Uint8Array(pkcs8).fill(0);
    return {
      privateKey,
      payload: {
        kdf_salt: salt,
        auth_secret: authSecret,
        public_key: toB64(await subtle.exportKey('spki', pair.publicKey)),
        enc_private_key: toB64(encPriv),
        private_key_iv: toB64(iv),
      },
    };
  }

  // Déchiffre la clé privée et la réimporte en « non exportable » : même un script
  // injecté ne pourrait pas en extraire les octets.
  async function unlockPrivateKey(user, wrapKey) {
    const pkcs8 = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(user.private_key_iv) }, wrapKey, fromB64(user.enc_private_key));
    const key = await subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    new Uint8Array(pkcs8).fill(0);
    return key;
  }

  const pairCache = new Map();
  async function conversationKey(myPrivateKey, myId, other) {
    const cacheKey = other.id + ':' + other.public_key;
    if (pairCache.has(cacheKey)) return pairCache.get(cacheKey);
    const theirPub = await subtle.importKey('spki', fromB64(other.public_key), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await subtle.deriveBits({ name: 'ECDH', public: theirPub }, myPrivateKey, 256);
    const hkdfBase = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const ids = [Number(myId), Number(other.id)].sort((a, b) => a - b).join('|');
    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: await subtle.digest('SHA-256', enc.encode('dsend-v2|' + ids)), info: enc.encode('dsend-v2 message key') },
      hkdfBase, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    pairCache.set(cacheKey, key);
    return key;
  }

  async function encryptJson(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { iv: toB64(iv), ciphertext: toB64(ct) };
  }

  async function decryptJson(key, ivB64, ctB64) {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ctB64));
    return JSON.parse(dec.decode(pt));
  }

  // « Numéro de sécurité » : à comparer de vive voix pour détecter une substitution de clé.
  async function safetyNumber(pubA, pubB) {
    const [a, b] = [pubA, pubB].sort();
    const hash = new Uint8Array(await subtle.digest('SHA-256', enc.encode(a + '|' + b)));
    let digits = '';
    for (let i = 0; i < 12; i++) digits += String(((hash[i * 2] << 8) | hash[i * 2 + 1]) % 100000).padStart(5, '0');
    return digits.match(/.{5}/g).join(' ');
  }

  /* Stockage local de la clé privée (non exportable) pour la durée de la session. */
  const DB = 'dsend-keys';
  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('keys');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function storeKey(uid, key) {
    try {
      const db = await idb();
      await new Promise((res, rej) => { const tx = db.transaction('keys', 'readwrite'); tx.objectStore('keys').put(key, 'u' + uid); tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
    } catch (e) { /* stockage indisponible : la clé reste en mémoire seulement */ }
  }
  async function loadKey(uid) {
    try {
      const db = await idb();
      return await new Promise((res) => { const r = db.transaction('keys').objectStore('keys').get('u' + uid); r.onsuccess = () => res(r.result || null); r.onerror = () => res(null); });
    } catch (e) { return null; }
  }
  async function wipeKeys() {
    pairCache.clear();
    try { await new Promise((res) => { const r = indexedDB.deleteDatabase(DB); r.onsuccess = r.onerror = r.onblocked = () => res(); }); } catch (e) { /* rien */ }
  }

  return { toB64, fromB64, deriveFromPassword, createAccount, unlockPrivateKey, conversationKey, encryptJson, decryptJson, safetyNumber, storeKey, loadKey, wipeKeys };
})();
