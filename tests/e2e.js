/*
 * D-Send v2 — test de bout en bout (Playwright).
 * Usage : voir la section « Tests » du README (serveur lancé avec DSEND_TEST_DB=test.sqlite,
 *         puis npm test). Des comptes de test sont créés à chaque exécution : ne jamais
 *         lancer ce script contre la vraie base.
 */
const { chromium } = require('playwright');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BASE = process.env.BASE_URL || 'http://localhost:8000/';
const PASSWORD = 'MotDePasse-Solide-2026';
const run = Date.now();
let failures = 0;
const check = (ok, label) => { console.log((ok ? '  OK   ' : '  ÉCHEC ') + label); if (!ok) failures++; };

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsend-'));
  const png = path.join(tmp, 'photo.png');
  fs.writeFileSync(png, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'));
  const big = path.join(tmp, 'document-7.8Mo.bin');
  fs.writeFileSync(big, Buffer.alloc(8_200_000, 7));

  const browser = await chromium.launch();
  const page = async () => { const c = await browser.newContext(); const p = await c.newPage(); await p.goto(BASE); return p; };
  const register = async (p, email) => {
    await p.click('#tab-register');
    await p.fill('#auth-email', email); await p.fill('#auth-password', PASSWORD); await p.fill('#auth-confirm', PASSWORD);
    await p.click('#auth-submit'); await p.waitForSelector('#view-app:not([hidden])', { timeout: 30000 });
  };

  const a = await page(); await register(a, `alice-${run}@test.local`);
  const b = await page(); await register(b, `bob-${run}@test.local`);
  await a.reload(); await a.waitForSelector('#view-app:not([hidden])');
  await a.click(`.contact:has-text("bob-${run}")`);

  const xss = 'Rendez-vous 18h <script>window.pwned=1</script><img src=x onerror="window.pwned=1">';
  await a.fill('#msg-input', xss); await a.press('#msg-input', 'Enter');
  await a.setInputFiles('#file-input', png);
  await a.setInputFiles('#file-input', big);
  await a.waitForSelector('text=document-7.8Mo.bin', { timeout: 60000 });

  await b.reload(); await b.waitForSelector('#view-app:not([hidden])');
  await b.click(`.contact:has-text("alice-${run}")`);
  await b.waitForSelector('text=document-7.8Mo.bin', { timeout: 60000 });
  const texts = await b.$$eval('.bubble', (els) => els.map((e) => e.textContent));
  check(texts.some((t) => t.includes('Rendez-vous 18h <script>')), 'le destinataire déchiffre le message');
  check(await b.evaluate(() => !window.pwned) && (await b.$$('.messages script')).length === 0, 'le HTML reçu est affiché comme du texte (pas de XSS)');
  check((await b.$$('.bubble img')).length === 1, 'la photo chiffrée est reçue et affichée');
  check(texts.some((t) => t.includes('document-7.8Mo.bin')), 'un fichier de 7,8 Mo passe');

  await b.click('#btn-safety'); await a.click('#btn-safety');
  check(await a.textContent('#safety-number') === await b.textContent('#safety-number'), 'numéro de sécurité identique des deux côtés');

  const e = await page();
  await e.fill('#auth-email', `alice-${run}@test.local`); await e.fill('#auth-password', 'mauvais-mot-de-passe');
  await e.click('#auth-submit'); await e.waitForSelector('#auth-error:not([hidden])', { timeout: 30000 });
  check((await e.textContent('#auth-error')).includes('incorrect'), 'mauvais mot de passe refusé');

  await a.click('#btn-panic'); await a.waitForSelector('#view-auth:not([hidden])');
  const left = await a.evaluate(() => new Promise((r) => { const q = indexedDB.open('dsend-keys', 1); q.onupgradeneeded = () => r(0); q.onsuccess = () => { const d = q.result; if (!d.objectStoreNames.contains('keys')) return r(0); const c = d.transaction('keys').objectStore('keys').count(); c.onsuccess = () => r(c.result); }; }));
  check(left === 0, 'verrouillage d\'urgence : aucune clé ne reste sur l\'appareil');

  await browser.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? `\n${failures} test(s) en échec.` : '\nTous les tests passent.');
  process.exit(failures ? 1 : 0);
})().catch((err) => { console.error(err); process.exit(1); });
