/*
 * Tryb online. Telefon mistrza gry trzyma stan lobby, losuje role i każdemu graczowi
 * wysyła wyłącznie jego własną rolę, kartę i historię.
 *
 * Transport: dwa publiczne brokery MQTT naraz (WebSocket po TLS). Broker jest publiczny,
 * więc traktujemy go jak wrogą sieć:
 *
 * - Szyfrowanie: każda wiadomość poza ogłoszeniem klucza mistrza gry jest szyfrowana
 *   AES-GCM kluczem z ECDH P-256 (mistrz gry ↔ gracz). AES-GCM wykrywa każdą zmianę treści.
 * - Uwierzytelnienie mistrza gry: kod lobby to skrót klucza publicznego mistrza gry,
 *   a link zawiera pełny odcisk (SHA-256). Gracz przyjmuje tylko klucz, który pasuje,
 *   i przypina go na stałe. Drugi pasujący klucz oznacza próbę podszycia: gra się zatrzymuje.
 * - Uwierzytelnienie gracza: mistrz gry przypina klucz publiczny gracza przy pierwszym
 *   dołączeniu. Wiadomość z innym kluczem dla tego samego gracza jest odrzucana.
 * - Powtórki: każda wiadomość ma rosnący licznik, zapamiętywany po obu stronach.
 *   Nagrana i wysłana ponownie wiadomość (np. „użyj karty”) jest odrzucana.
 * - Walidacja: wszystko, co przychodzi z sieci, jest sprawdzane co do typu i formatu,
 *   a tekst trafia na ekran wyłącznie przez esc().
 * - Limity: rozmiar wiadomości, liczba wiadomości na sekundę, liczba graczy.
 */
(() => {
  // Nie działamy w ramce na cudzej stronie (clickjacking).
  if (window.top !== window.self) {
    document.getElementById("app").textContent = "Otwórz tę stronę bezpośrednio, nie w ramce.";
    return;
  }

  const { ROLES, POWER_BY_ID, STORIES, esc, defaultConfig, validate, deal, renderConfig,
          applyConfigAction, autoMafia, renderIdentity, confirmBox, keepAwake } = window.Mafia;

  // Parametr ?broker= działa tylko dla brokera na tym komputerze (testy).
  const BROKERS = (() => {
    const v = new URLSearchParams(location.search).get("broker");
    if (v && /^ws:\/\/(127\.0\.0\.1|localhost):\d{2,5}(\/[\w-]*)?$/.test(v)) return [v];
    return ["wss://broker.emqx.io:8084/mqtt", "wss://broker.hivemq.com:8884/mqtt"];
  })();
  const TOPIC = "mafia-pl-v3";
  const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ";   // bez I i O
  const CODE_LEN = 6;
  const HOST_KEY = "mafia-online-host-v3";
  const PLAYER_KEY = "mafia-online-player-v3";
  const CONFIG_KEY = "mafia-roles-v1";   // te same ustawienia ról co w trybie jednego telefonu
  const PING_MS = 4000;
  const ANNOUNCE_MS = 10000;
  const TIMEOUT_MS = 13000;
  const NOTFOUND_MS = 7000;
  const MAX_PLAYERS = 30;
  const MAX_PAYLOAD = 16384;

  const app = document.getElementById("app");
  const ui = { screen: "home", confirm: null, error: "", reveal: false, status: "connecting", spoof: false };

  // ---------- Walidacja ----------
  const isToken = v => typeof v === "string" && /^[0-9a-f]{24}$/.test(v);
  const isB64u43 = v => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v);
  const isCode = v => typeof v === "string" && new RegExp(`^[${CODE_CHARS}]{${CODE_LEN}}$`).test(v);
  const isCounter = v => Number.isSafeInteger(v) && v > 0;
  const isPub = v => v && typeof v === "object" && v.kty === "EC" && v.crv === "P-256" && isB64u43(v.x) && isB64u43(v.y);
  const isBox = v => v && typeof v.iv === "string" && /^[A-Za-z0-9+/]{16}$/.test(v.iv) &&
                     typeof v.ct === "string" && v.ct.length <= MAX_PAYLOAD && /^[A-Za-z0-9+/]+=*$/.test(v.ct);

  function readJSON(key) { try { return JSON.parse(localStorage.getItem(key)) || null; } catch { return null; } }
  function writeJSON(key, v) { try { v === null ? localStorage.removeItem(key) : localStorage.setItem(key, JSON.stringify(v)); } catch {} }
  function randomToken() { return Array.from(crypto.getRandomValues(new Uint8Array(12)), b => b.toString(16).padStart(2, "0")).join(""); }
  // Usuwa znaki sterujące i niewidoczne (np. odwracanie kierunku tekstu), które pozwalają podszyć się pod cudze imię.
  function cleanName(raw) { return String(raw || "").replace(/[\p{C}]/gu, "").trim().replace(/\s+/g, " ").slice(0, 24); }
  function cleanCode(raw) { return String(raw || "").toUpperCase().replace(/[^A-Z]/g, "").slice(0, CODE_LEN); }
  function clock(ts) { return new Date(ts).toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" }); }
  function vibrate(p) { try { navigator.vibrate && navigator.vibrate(p); } catch {} }
  function parseHash() {
    const [c, f] = location.hash.slice(1).split(".");
    const code = cleanCode(c);
    return { code: isCode(code) ? code : "", fp: isB64u43(f) ? f : "" };
  }
  function lobbyUrl(code, fp) { return location.origin + location.pathname + "#" + code + "." + fp; }
  const topics = code => ({
    host: `${TOPIC}/${code}/host`,
    inbox: `${TOPIC}/${code}/in`,
    to: token => `${TOPIC}/${code}/to/${token}`
  });

  // Prosty limiter: najwyżej `rate` zdarzeń na sekundę, z zapasem `burst`.
  function limiter(rate, burst) {
    let tokens = burst, last = Date.now();
    return () => {
      const now = Date.now();
      tokens = Math.min(burst, tokens + (now - last) / 1000 * rate);
      last = now;
      if (tokens < 1) return false;
      tokens -= 1;
      return true;
    };
  }

  // Licznik rosnący także po odświeżeniu strony (zapisany) i przy cofniętym zegarze.
  function nextCounter(last) { return Math.max(Date.now() * 1000, (last || 0) + 1); }

  // =====================================================================
  // SZYFROWANIE
  // =====================================================================
  const subtle = crypto.subtle;
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64u = buf => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function newKeyPair() {
    const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    return { priv: await subtle.exportKey("jwk", kp.privateKey), pub: pubOnly(await subtle.exportKey("jwk", kp.publicKey)) };
  }
  function pubOnly(jwk) { return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }; }
  function samePub(a, b) { return !!(a && b && a.x === b.x && a.y === b.y); }
  async function sharedKey(privJwk, pubJwk) {
    const priv = await subtle.importKey("jwk", privJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
    const pub = await subtle.importKey("jwk", pubOnly(pubJwk), { name: "ECDH", namedCurve: "P-256" }, false, []);
    return subtle.deriveKey({ name: "ECDH", public: pub }, priv, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function seal(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function unseal(key, box) {
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
    const obj = JSON.parse(new TextDecoder().decode(pt));
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw new Error("bad");
    return obj;
  }

  // Odcisk klucza mistrza gry i wyprowadzony z niego kod lobby.
  async function fingerprint(pub) {
    const h = new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode("mafia-pl|" + pub.x + "|" + pub.y)));
    let code = "";
    for (const b of h) { if (b < 240 && code.length < CODE_LEN) code += CODE_CHARS[b % 24]; }
    return { fp: b64u(h), code: code.length === CODE_LEN ? code : "" };
  }

  // =====================================================================
  // TRANSPORT: kilka brokerów naraz, duplikaty odrzucane po id wiadomości
  // =====================================================================
  function createBus(subs, onMessage, onStatus) {
    const seen = new Set();
    const seenOrder = [];
    const clients = BROKERS.map(url => {
      const c = mqtt.connect(url, {
        clientId: "mafia-" + randomToken(),
        clean: true,
        keepalive: 30,
        reconnectPeriod: 2500,
        connectTimeout: 10000
      });
      c.on("connect", () => { c.subscribe(subs(), { qos: 1 }); onStatus(); });
      c.on("close", onStatus);
      c.on("offline", onStatus);
      c.on("error", () => {});
      c.on("message", (topic, payload) => {
        if (payload.length > MAX_PAYLOAD) return;
        const text = payload.toString();
        if (!text) { onMessage(topic, null); return; }
        let msg;
        try { msg = JSON.parse(text); } catch { return; }
        if (!msg || typeof msg !== "object" || Array.isArray(msg)) return;
        if (typeof msg.mid === "string") {
          if (seen.has(msg.mid)) return;
          seen.add(msg.mid); seenOrder.push(msg.mid);
          if (seenOrder.length > 1000) seen.delete(seenOrder.shift());
        }
        onMessage(topic, msg);
      });
      return c;
    });
    return {
      publish(topic, obj, opts = {}) {
        const body = obj === null ? "" : JSON.stringify({ ...obj, mid: randomToken() });
        for (const c of clients) if (c.connected) c.publish(topic, body, { qos: opts.qos ?? 1, retain: !!opts.retain });
      },
      connected() { return clients.some(c => c.connected); },
      wake() { for (const c of clients) if (!c.connected && !c.disconnecting) c.reconnect(); },
      end() { for (const c of clients) { try { c.end(true); } catch {} } }
    };
  }

  // =====================================================================
  // MISTRZ GRY
  // =====================================================================
  // host = { code, fp, keys: {priv, pub}, cfg, players: [{token, name, pub}], phase,
  //          assignment: {token: {...}}, log: [], alerts: [], lastN: {token: n}, seq }
  let host = null;
  let hostBus = null;
  let hostReady = false;
  const keyCache = new Map();      // "x|y" -> AES key (z ograniczeniem rozmiaru)
  const lastSeen = new Map();      // token -> ms
  const inboxLimit = limiter(40, 80);
  const deriveLimit = limiter(8, 16);
  const announceLimit = limiter(1, 3);
  let inboxChain = Promise.resolve();
  let saveTimer = null;

  function saveHost() {
    if (!host) return writeJSON(HOST_KEY, null);
    writeJSON(HOST_KEY, host);
    const prev = readJSON(CONFIG_KEY) || {};
    writeJSON(CONFIG_KEY, { ...prev, ...host.cfg });
  }
  function saveHostSoon() { clearTimeout(saveTimer); saveTimer = setTimeout(saveHost, 300); }

  async function startHost(existing) {
    ui.screen = "host";
    ui.status = "connecting";
    ui.spoof = false;
    render();
    if (existing && (!isPub(existing.keys?.pub) || !existing.keys?.priv || !isCode(existing.code))) existing = null;
    if (!existing) {
      let keys, id;
      do { keys = await newKeyPair(); id = await fingerprint(keys.pub); } while (!id.code);
      existing = {
        code: id.code, fp: id.fp, keys,
        cfg: defaultConfig(readJSON(CONFIG_KEY) || {}),
        players: [], phase: "lobby", assignment: {}, log: [], alerts: [], lastN: {}, seq: 0
      };
    }
    host = existing;
    host.lastN = host.lastN || {};
    saveHost();
    openHostBus();
    keepAwake();
    render();
  }

  function openHostBus() {
    if (hostBus) hostBus.end();
    hostReady = false;
    keyCache.clear();
    const t = topics(host.code);
    hostBus = createBus(
      () => [t.host, t.inbox],
      (topic, msg) => {
        if (topic === t.host) {
          // Ktoś nadpisał ogłoszenie lobby (wyczyścił je albo podał swój klucz). Ogłaszamy się ponownie.
          if (!msg || !samePub(msg.pub, host.keys.pub)) {
            if (msg && isPub(msg.pub)) checkSpoof(msg.pub);
            if (hostReady && announceLimit()) announce();
          }
          return;
        }
        if (topic === t.inbox && msg && hostReady && inboxLimit()) {
          // Po kolei, żeby dwie równoczesne prośby tego samego gracza nie dodały go dwa razy.
          inboxChain = inboxChain.then(() => handleInbox(msg)).catch(() => {});
        }
      },
      () => {
        if (!hostBus) return;
        if (hostBus.connected()) {
          if (!hostReady) { hostReady = true; broadcast(); }
          announce();
          ui.status = "online";
        } else {
          ui.status = "reconnecting";
        }
        render();
      }
    );
  }

  async function checkSpoof(pub) {
    const id = await fingerprint(pub);
    if (host && id.code === host.code) { ui.spoof = true; render(); }
  }

  function announce() {
    if (hostBus) hostBus.publish(topics(host.code).host, { t: "hello", pub: host.keys.pub }, { retain: true });
  }
  setInterval(() => { if (host && hostReady && ui.screen === "host") announce(); }, ANNOUNCE_MS);

  async function keyForPub(pub, mayDerive) {
    const id = pub.x + "|" + pub.y;
    if (keyCache.has(id)) return keyCache.get(id);
    if (!mayDerive) return null;
    let k;
    try { k = await sharedKey(host.keys.priv, pub); } catch { return null; }   // np. punkt spoza krzywej
    if (keyCache.size > 200) keyCache.delete(keyCache.keys().next().value);
    keyCache.set(id, k);
    return k;
  }

  async function sendTo(token, obj) {
    const p = host.players.find(x => x.token === token);
    if (!p || !hostBus) return;
    const key = await keyForPub(p.pub, true);
    if (!key) return;
    await sendWithKey(key, token, obj);
  }
  async function sendWithKey(key, token, obj) {
    host.seq = nextCounter(host.seq);
    saveHostSoon();
    hostBus.publish(topics(host.code).to(token), await seal(key, { ...obj, seq: host.seq }));
  }

  async function handleInbox(msg) {
    if (!isPub(msg.pub) || !isBox(msg)) return;
    const known = host.players.find(p => samePub(p.pub, msg.pub));
    // Wyprowadzanie klucza dla nieznanych nadawców jest kosztowne, więc limitowane (ochrona przed zalewaniem).
    const key = await keyForPub(msg.pub, !!known || deriveLimit());
    if (!key) return;
    let inner;
    try { inner = await unseal(key, msg); } catch { return; }
    const token = inner.token;
    if (!isToken(token) || !isCounter(inner.n)) return;
    const owner = host.players.find(p => p.token === token);
    if (owner && !samePub(owner.pub, msg.pub)) return;           // podszywanie się pod gracza
    if (!owner && known) return;                                  // jeden klucz = jeden gracz
    if ((host.lastN[token] || 0) >= inner.n) return;              // powtórka starej wiadomości
    host.lastN[token] = inner.n;
    saveHostSoon();

    if (!owner) {
      if (inner.t !== "join") return;
      const name = cleanName(inner.name);
      const refuse = text => sendWithKey(key, token, { t: "error", msg: text });
      if (!name) return refuse("Podaj imię.");
      if (host.phase !== "lobby") return refuse("Gra już trwa. Poproś mistrza gry, żeby wrócił do lobby, wtedy dołączysz.");
      if (host.players.length >= MAX_PLAYERS) return refuse(`Lobby jest pełne (${MAX_PLAYERS} graczy).`);
      if (host.players.some(p => p.name.toLowerCase() === name.toLowerCase())) return refuse(`Imię ${name} jest już zajęte w tym lobby. Wybierz inne.`);
      host.players.push({ token, name, pub: pubOnly(msg.pub) });
      autoMafia(host.cfg, host.players.length);
      lastSeen.set(token, Date.now());
      saveHost();
      broadcast();
      render();
      return;
    }

    lastSeen.set(token, Date.now());
    switch (inner.t) {
      case "join": {
        const name = cleanName(inner.name);
        if (host.phase === "lobby" && name && owner.name !== name &&
            !host.players.some(p => p !== owner && p.name.toLowerCase() === name.toLowerCase())) {
          owner.name = name; saveHost(); broadcast();
        } else {
          sendState(token);
        }
        render(true);
        break;
      }
      case "ping": sendTo(token, { t: "pong" }); break;
      case "use": handleUse(token); break;
      case "leave": if (host.phase === "lobby") removePlayer(token, false); break;
    }
  }

  function removePlayer(token, notify) {
    if (notify) sendTo(token, { t: "kicked" });
    setTimeout(() => {
      host.players = host.players.filter(p => p.token !== token);
      autoMafia(host.cfg, host.players.length);
      saveHost();
      broadcast();
      render();
    }, notify ? 200 : 0);
  }

  function handleUse(token) {
    const a = host.assignment[token];
    const p = host.players.find(x => x.token === token);
    if (host.phase !== "game" || !a || !a.power || a.used || !p) { sendState(token); return; }
    a.used = Date.now();
    const entry = { id: randomToken(), name: p.name, power: a.power, role: a.role, at: a.used };
    host.log.unshift(entry);
    host.alerts.push(entry.id);
    vibrate([200, 100, 200]);
    saveHost();
    sendState(token);
    render();
  }

  function hostDeal() {
    const n = host.players.length;
    if (!validate(host.cfg, n).ok) return;
    const dealt = deal(host.cfg, n);
    host.assignment = {};
    host.players.forEach((p, i) => { host.assignment[p.token] = { ...dealt[i], used: null }; });
    host.phase = "game";
    host.dealId = randomToken();
    host.log = [];
    host.alerts = [];
    saveHost();
    broadcast();
  }

  function stateFor(token) {
    const p = host.players.find(x => x.token === token);
    if (!p) return { t: "kicked" };
    let me = null;
    if (host.phase === "game" && host.assignment[token]) {
      const a = host.assignment[token];
      const partners = a.role === "mafia"
        ? host.players.filter(x => x.token !== token && host.assignment[x.token]?.role === "mafia").map(x => x.name)
        : null;
      me = { name: p.name, deal: host.dealId, role: a.role, power: a.power, story: a.story, used: a.used, partners };
    }
    return { t: "state", lobby: { phase: host.phase, players: host.players.map(x => x.name) }, name: p.name, me };
  }

  function sendState(token) { if (hostReady) sendTo(token, stateFor(token)); }
  function broadcast() { if (hostReady) for (const p of host.players) sendState(p.token); }
  function isOnline(token) { return Date.now() - (lastSeen.get(token) || 0) < TIMEOUT_MS; }

  async function endHost() {
    if (hostBus && hostReady) {
      await Promise.all(host.players.map(p => sendTo(p.token, { t: "closed" })));
      hostBus.publish(topics(host.code).host, null, { retain: true });   // usuń ogłoszenie lobby
    }
    const bus = hostBus;
    setTimeout(() => bus && bus.end(), 800);
    hostBus = null; hostReady = false;
    host = null;
    saveHost();
    ui.screen = "home";
    ui.confirm = null;
    render();
  }

  // Odśwież statusy online co kilka sekund.
  setInterval(() => { if (ui.screen === "host" && !ui.confirm) render(true); }, PING_MS);

  function statusBadge(s) {
    const map = {
      online: ["on", "Lobby otwarte"],
      connecting: ["wait", "Otwieram lobby…"],
      reconnecting: ["off", "Brak internetu, łączę ponownie…"]
    };
    const [cls, label] = map[s] || map.connecting;
    return `<span class="status"><span class="dot ${cls}"></span>${label}</span>`;
  }

  function spoofWarning() {
    return ui.spoof
      ? `<p class="warn">Ktoś próbuje podszyć się pod to lobby. Gracze, którzy dołączyli z linku, są bezpieczni. Jeśli komuś wyświetla się ostrzeżenie, załóżcie nowe lobby.</p>`
      : "";
  }

  function renderHost() {
    if (!host) return `<section class="screen"><h2>Otwieram lobby…</h2></section>`;
    return host.phase === "lobby" ? renderHostLobby() : renderHostGame();
  }

  function renderHostLobby() {
    const n = host.players.length;
    const v = validate(host.cfg, n);
    const list = n
      ? host.players.map((p, i) => `
          <li>
            <span class="num">${i + 1}.</span>
            <span class="name">${esc(p.name)}</span>
            <span class="status"><span class="dot ${isOnline(p.token) ? "on" : "off"}"></span></span>
            <button class="btn-remove" data-act="kick" data-token="${esc(p.token)}" aria-label="Usuń ${esc(p.name)}">×</button>
          </li>`).join("")
      : `<li class="empty">Nikt jeszcze nie dołączył. Wyślij graczom link albo podaj im kod.</li>`;
    return `
      <section class="screen">
        <div>
          <div class="eyebrow">Mafia online · mistrz gry</div>
          <h1>Lobby</h1>
        </div>
        ${statusBadge(ui.status)}
        ${spoofWarning()}
        <div class="code-box">
          <span class="eyebrow">Kod lobby</span>
          <span class="code">${esc(host.code)}</span>
          <span class="link">${esc(lobbyUrl(host.code, host.fp))}</span>
          <button data-act="copy-link">Kopiuj link dla graczy</button>
          <span class="summary">Link jest bezpieczniejszy niż przepisywanie kodu: zawiera pełny odcisk klucza tego lobby.</span>
        </div>

        <div>
          <div class="eyebrow">Gracze (${n})</div>
          <ul class="players">${list}</ul>
        </div>

        ${renderConfig(host.cfg, n)}
        ${v.ok ? "" : `<p class="warn">${esc(v.msg)}</p>`}

        <div class="spacer"></div>
        <div class="actions">
          <button class="btn-primary" data-act="host-deal" ${v.ok && hostReady ? "" : "disabled"}>Rozdaj role</button>
          <button class="btn-ghost" data-act="host-close">Zamknij lobby</button>
          ${ui.confirm === "close" ? confirmBox("Zamknąć lobby? Wszyscy gracze zostaną rozłączeni.", "host-close-yes") : ""}
        </div>
      </section>`;
  }

  function renderHostGame() {
    const alerts = host.alerts.map(id => host.log.find(e => e.id === id)).filter(Boolean);
    const alertHtml = alerts.map(e => `
      <div class="alert" role="alert">
        <span class="eyebrow" style="color:var(--power)">Użycie karty · ${clock(e.at)}</span>
        <span class="who-uses">${esc(e.name)} używa karty <em>${esc(POWER_BY_ID[e.power].name)}</em></span>
        <p>${esc(POWER_BY_ID[e.power].desc)}</p>
        <p class="muted">Rola: <strong style="color:${ROLES[e.role].color}">${esc(ROLES[e.role].name)}</strong></p>
        <button class="btn-ghost" data-act="ack" data-id="${esc(e.id)}">Przyjąłem</button>
      </div>`).join("");

    const roster = host.players.map(p => {
      const a = host.assignment[p.token];
      if (!a) return "";
      const r = ROLES[a.role];
      const pw = a.power ? `<span class="p ${a.used ? "used" : ""}">${esc(POWER_BY_ID[a.power].name)}${a.used ? ` · użyta ${clock(a.used)}` : ""}</span>` : "";
      const st = a.story !== null ? `<span class="s">${esc(STORIES[a.story].t)}</span>` : "";
      return `<li>
        <span><span class="status"><span class="dot ${isOnline(p.token) ? "on" : "off"}"></span></span> ${esc(p.name)}${pw}${st}</span>
        <span class="r" style="color:${r.color}">${esc(r.name)}</span>
      </li>`;
    }).join("");

    const log = host.log.length
      ? `<ul class="log">${host.log.map(e => `<li><span>${esc(e.name)}: ${esc(POWER_BY_ID[e.power].name)}</span><time>${clock(e.at)}</time></li>`).join("")}</ul>`
      : `<p class="muted">Nikt jeszcze nie użył karty.</p>`;

    return `
      <section class="screen">
        <div>
          <div class="eyebrow">Mafia online · mistrz gry · ${esc(host.code)}</div>
          <h2>Gra trwa</h2>
        </div>
        ${statusBadge(ui.status)}
        ${spoofWarning()}
        ${alertHtml}
        ${host.cfg.storiesOn ? `<p>Pierwszego dnia każdy po kolei opowiada swoje backstory.</p>` : ""}
        <div>
          <div class="eyebrow">Role graczy</div>
          <ul class="roster">${roster}</ul>
        </div>
        ${host.cfg.powersOn ? `<div><div class="eyebrow">Użyte karty</div>${log}</div>` : ""}
        <div class="spacer"></div>
        <div class="actions">
          <button class="btn-primary" data-act="host-redeal">Nowe losowanie, ci sami gracze</button>
          <button class="btn-ghost" data-act="host-lobby">Wróć do lobby</button>
          ${ui.confirm === "redeal" ? confirmBox("Wylosować role od nowa? Wszyscy dostaną nowe role i karty.", "host-redeal-yes") : ""}
          ${ui.confirm === "lobby" ? confirmBox("Zakończyć grę i wrócić do lobby? Gracze stracą obecne role.", "host-lobby-yes") : ""}
        </div>
      </section>`;
  }

  // =====================================================================
  // GRACZ
  // =====================================================================
  // player = { token, keys, name, code, fp, hostPin, n, seq }
  let player = null;
  let playerBus = null;
  let hostKey = null;
  let lobby = null;
  let me = null;
  let lastFromHost = 0;
  let joinedAt = 0;
  let pendingUse = false;
  const playerInLimit = limiter(30, 60);
  let playerChain = Promise.resolve();

  function savePlayer() { if (player) writeJSON(PLAYER_KEY, player); }

  async function startPlayer(code, name, fp) {
    const prev = readJSON(PLAYER_KEY);
    const keys = prev && isPub(prev.keys?.pub) && prev.keys.priv ? prev.keys : await newKeyPair();
    const same = prev && prev.code === code && isToken(prev.token);
    player = {
      token: same ? prev.token : randomToken(),
      keys, name, code,
      fp: fp || (same ? prev.fp || "" : ""),
      hostPin: same && isPub(prev.hostPin) ? prev.hostPin : null,
      n: same ? prev.n || 0 : 0,
      seq: same ? prev.seq || 0 : 0
    };
    // Link z innym odciskiem niż przypięty klucz: to nie jest to samo lobby.
    if (player.hostPin && player.fp) {
      const id = await fingerprint(player.hostPin);
      if (id.fp !== player.fp) { player.hostPin = null; player.seq = 0; }
    }
    savePlayer();
    lobby = null; me = null; hostKey = null; lastFromHost = 0; pendingUse = false;
    ui.screen = "player";
    ui.status = "connecting";
    ui.error = "";
    ui.reveal = false;
    history.replaceState(null, "", location.pathname + location.search + "#" + code + (player.fp ? "." + player.fp : ""));
    keepAwake();
    if (player.hostPin) hostKey = await sharedKey(player.keys.priv, player.hostPin);
    render();
    openPlayerBus();
  }

  function openPlayerBus() {
    if (playerBus) playerBus.end();
    const t = topics(player.code);
    joinedAt = Date.now();
    playerBus = createBus(
      () => [t.host, t.to(player.token)],
      (topic, msg) => {
        if (!playerInLimit()) return;
        // Po kolei: dwa różne ogłoszenia naraz nie mogą ominąć wykrywania podróbki.
        if (topic === t.host) playerChain = playerChain.then(() => onHello(msg)).catch(() => {});
        else if (topic === t.to(player.token) && msg && isBox(msg)) playerChain = playerChain.then(() => onFromHost(msg)).catch(() => {});
      },
      () => {
        if (!playerBus || ui.status === "spoofed" || ui.status === "refused") return;
        if (!playerBus.connected()) { ui.status = "offline"; render(); return; }
        if (ui.status === "offline" || ui.status === "connecting") {
          ui.status = lobby ? "online" : "searching"; render();
          if (hostKey) sendJoin();
        }
      }
    );
  }

  async function onHello(msg) {
    if (!player || ui.status === "spoofed") return;
    if (!msg || msg.t !== "hello" || !isPub(msg.pub)) return;
    if (samePub(msg.pub, player.hostPin)) {
      if (!hostKey) hostKey = await sharedKey(player.keys.priv, player.hostPin);
      if (!lobby) sendJoin();
      return;
    }
    // Nowy klucz: musi pasować do kodu (i do odcisku z linku, jeśli jest).
    const id = await fingerprint(msg.pub);
    if (id.code !== player.code) return;                        // śmieci albo nieudana podróbka
    if (player.fp && id.fp !== player.fp) { spoofed(); return; } // pasuje do kodu, ale nie do linku
    if (player.hostPin) { spoofed(); return; }                   // drugi pasujący klucz dla tego lobby
    let k;
    try { k = await sharedKey(player.keys.priv, msg.pub); } catch { return; }
    player.hostPin = pubOnly(msg.pub);
    player.fp = id.fp;
    player.seq = 0;
    savePlayer();
    hostKey = k;
    history.replaceState(null, "", location.pathname + location.search + "#" + player.code + "." + player.fp);
    sendJoin();
  }

  function spoofed() {
    ui.status = "spoofed";
    stopPlayer(false);
    render();
  }

  async function sendBox(inner, qos) {
    if (!player || !playerBus || !hostKey || ui.status === "spoofed") return;
    player.n = nextCounter(player.n);
    savePlayer();
    const box = await seal(hostKey, { ...inner, token: player.token, n: player.n });
    playerBus.publish(topics(player.code).inbox, { pub: player.keys.pub, ...box }, { qos: qos ?? 1 });
  }
  function sendJoin() { sendBox({ t: "join", name: player.name }); }

  async function onFromHost(box) {
    if (!hostKey) return;
    let msg;
    try { msg = await unseal(hostKey, box); } catch { return; }
    if (!isCounter(msg.seq) || msg.seq <= player.seq) return;   // powtórka starej wiadomości
    player.seq = msg.seq;
    savePlayer();
    lastFromHost = Date.now();
    handleFromHost(msg);
  }

  // Wiadomość od mistrza gry jest uwierzytelniona, ale i tak sprawdzamy kształt danych.
  function validState(msg) {
    const l = msg.lobby;
    if (!l || (l.phase !== "lobby" && l.phase !== "game") || !Array.isArray(l.players) || l.players.length > MAX_PLAYERS) return false;
    if (!l.players.every(n => typeof n === "string" && n.length <= 24)) return false;
    if (typeof msg.name !== "string" || msg.name.length > 24) return false;
    const m = msg.me;
    if (m === null) return true;
    if (!m || typeof m !== "object") return false;
    if (!Object.hasOwn(ROLES, m.role)) return false;
    if (m.power !== null && !Object.hasOwn(POWER_BY_ID, m.power)) return false;
    if (m.story !== null && !(Number.isInteger(m.story) && m.story >= 0 && m.story < STORIES.length)) return false;
    if (m.used !== null && !Number.isFinite(m.used)) return false;
    if (!isToken(m.deal)) return false;
    if (m.partners !== null && !(Array.isArray(m.partners) && m.partners.every(n => typeof n === "string" && n.length <= 24))) return false;
    return typeof m.name === "string" && m.name.length <= 24;
  }

  function handleFromHost(msg) {
    if (msg.t === "state") {
      if (!validState(msg)) return;
      const prev = me;
      lobby = msg.lobby; me = msg.me;
      if (msg.name !== player.name) { player.name = msg.name; savePlayer(); }
      // Nowe losowanie: zasłoń ekran, żeby nowa rola nie pokazała się komuś przypadkiem.
      const changed = me && (!prev || prev.deal !== me.deal);
      if (changed) { ui.reveal = false; ui.confirm = null; vibrate(150); }
      if (!me || me.used) pendingUse = false;
      ui.status = "online"; ui.error = "";
      render();
    } else if (msg.t === "pong") {
      if (ui.status !== "online" && lobby) { ui.status = "online"; render(); }
    } else if (msg.t === "error" || msg.t === "kicked" || msg.t === "closed") {
      ui.status = "refused";
      ui.error = msg.t === "error" ? String(msg.msg || "").slice(0, 200)
        : msg.t === "kicked" ? "Mistrz gry usunął Cię z lobby." : "Mistrz gry zamknął lobby.";
      stopPlayer(false);
      render();
    }
  }

  // Co kilka sekund: ping do mistrza gry albo ponowna prośba o dołączenie.
  setInterval(() => {
    if (!player || !playerBus || ui.screen !== "player") return;
    if (["refused", "spoofed"].includes(ui.status) || !playerBus.connected()) return;
    if (!lobby) {
      if (hostKey) sendJoin();
      if (!player.hostPin && Date.now() - joinedAt > NOTFOUND_MS && ui.status !== "notfound") { ui.status = "notfound"; render(); }
      return;
    }
    sendBox({ t: "ping" }, 0);
    if (Date.now() - lastFromHost > TIMEOUT_MS && ui.status === "online") { ui.status = "hostgone"; render(); }
  }, PING_MS);

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    if (playerBus) { playerBus.wake(); if (lobby) sendBox({ t: "ping" }, 0); else if (hostKey) sendJoin(); }
    if (hostBus) { hostBus.wake(); if (hostReady) announce(); }
  });

  function stopPlayer(forget) {
    if (playerBus) { const b = playerBus; playerBus = null; setTimeout(() => b.end(), 500); }
    if (forget) {
      // Klucze zostają (to tożsamość telefonu), znika tylko udział w tym lobby.
      const keys = player && player.keys;
      writeJSON(PLAYER_KEY, keys ? { keys } : null);
      player = null;
      ui.screen = "home";
      history.replaceState(null, "", location.pathname + location.search);
    }
  }

  function renderPlayer() {
    if (ui.status === "spoofed") {
      return `
        <section class="screen">
          <div><div class="eyebrow">Mafia online · ${esc(player ? player.code : "")}</div><h2>Uwaga: podróbka lobby</h2></div>
          <p class="warn">Ktoś podszywa się pod mistrza gry tego lobby. Rozłączyłem Cię, żeby nikt nie podejrzał Twojej roli.</p>
          <p>Poproś mistrza gry, żeby założył nowe lobby i wysłał Ci link (nie sam kod).</p>
          <div class="spacer"></div>
          <button class="btn-primary" data-act="player-home">Wróć na start</button>
        </section>`;
    }
    if (ui.status === "refused") {
      return `
        <section class="screen">
          <div><div class="eyebrow">Mafia online · ${esc(player ? player.code : "")}</div><h2>Nie udało się dołączyć</h2></div>
          <p class="warn">${esc(ui.error)}</p>
          <div class="spacer"></div>
          <div class="actions">
            <button class="btn-primary" data-act="retry-join">Spróbuj ponownie</button>
            <button class="btn-ghost" data-act="player-home">Wróć na start</button>
          </div>
        </section>`;
    }

    const code = esc(player.code);
    const badge = {
      online: ["on", "Połączono z mistrzem gry"],
      connecting: ["wait", "Łączę z serwerem…"],
      searching: ["wait", `Szukam lobby ${code}…`],
      notfound: ["off", `Nie widzę lobby ${code}. Sprawdź kod albo poproś mistrza gry, żeby otworzył stronę lobby.`],
      offline: ["off", "Brak internetu, łączę ponownie…"],
      hostgone: ["off", "Mistrz gry nie odpowiada. Pewnie wygasił ekran. Czekam…"]
    }[ui.status] || ["wait", "Łączę…"];
    const statusHtml = `<span class="status"><span class="dot ${badge[0]}"></span>${badge[1]}</span>`;

    if (!me) {
      const names = lobby ? lobby.players : [];
      return `
        <section class="screen">
          <div>
            <div class="eyebrow">Mafia online · ${code}</div>
            <h2>Cześć, ${esc(player.name)}</h2>
          </div>
          ${statusHtml}
          <p class="muted">${lobby ? "Czekaj, aż mistrz gry rozda role. Twoja rola pojawi się tutaj." : "Za chwilę zobaczysz listę graczy."}</p>
          ${lobby ? `
          <div>
            <div class="eyebrow">W lobby (${names.length})</div>
            <ul class="players">${names.map((n, i) => `<li><span class="num">${i + 1}.</span><span class="name">${esc(n)}</span>${n === player.name ? `<span class="tag">to Ty</span>` : ""}</li>`).join("")}</ul>
          </div>` : ""}
          <div class="spacer"></div>
          <div class="actions">
            <button class="btn-ghost" data-act="player-leave">Opuść lobby</button>
            ${ui.confirm === "leave" ? confirmBox("Opuścić lobby?", "player-leave-yes") : ""}
          </div>
        </section>`;
    }

    let footer = "";
    if (me.power) {
      if (me.used) {
        footer = `<p class="note">Karta użyta o ${clock(me.used)}. Mistrz gry dostał powiadomienie.</p>`;
      } else if (pendingUse) {
        footer = `<p class="note">Wysyłam do mistrza gry…</p>`;
      } else if (ui.confirm === "use") {
        footer = confirmBox(`Użyć karty ${esc(POWER_BY_ID[me.power].name)}? Mistrz gry dostanie powiadomienie, a karty nie da się użyć drugi raz.`, "use-yes");
      } else {
        footer = `<p class="note">Działa raz na grę.</p>
          <button class="btn-power" data-act="use" ${ui.status === "online" ? "" : "disabled"}>Użyj karty</button>`;
      }
    }

    return `
      <section class="screen">
        <div class="eyebrow">Mafia online · ${code}</div>
        ${statusHtml}
        ${ui.reveal
          ? `${renderIdentity(me, me.partners, footer)}
             <button class="btn-ghost" data-act="hide-role">Ukryj</button>`
          : `<div class="veil">
               <span style="font-family:var(--font-display);font-size:2.2rem">${esc(me.name)}</span>
               <p class="muted">Role są rozdane. Zasłoń ekran przed innymi i odkryj swoją rolę.</p>
               <button class="btn-primary" data-act="show-role">Pokaż moją rolę</button>
             </div>
             ${me.power && !me.used ? `<p class="muted">Masz kartę mocy. Przycisk do jej użycia jest pod rolą.</p>` : ""}`}
        <div class="spacer"></div>
      </section>`;
  }

  // =====================================================================
  // START
  // =====================================================================
  function renderHome() {
    const prev = readJSON(PLAYER_KEY) || {};
    const h = parseHash();
    const savedHost = readJSON(HOST_KEY);
    return `
      <section class="screen">
        <div>
          <div class="eyebrow">Mafia · każdy na swoim telefonie</div>
          <h1>Mafia online</h1>
        </div>
        <a class="mode-link" href="index.html">← Gra na jednym telefonie</a>

        <form class="actions" id="join-form" autocomplete="off">
          <div class="eyebrow">Dołącz jako gracz</div>
          <div class="field">
            <label class="muted" for="join-code">Kod lobby</label>
            <input class="code-input" id="join-code" type="text" inputmode="text" maxlength="${CODE_LEN}" placeholder="ABCDEF" value="${esc(h.code || prev.code || "")}" autocapitalize="characters">
          </div>
          <div class="field">
            <label class="muted" for="join-name">Twoje imię</label>
            <input id="join-name" type="text" maxlength="24" placeholder="Imię" value="${esc(prev.name || "")}" enterkeyhint="go">
          </div>
          ${h.fp ? `<p class="summary">Link zawiera odcisk klucza lobby, więc połączenie jest w pełni zweryfikowane.</p>` : ""}
          ${ui.error ? `<p class="warn">${esc(ui.error)}</p>` : ""}
          <button class="btn-primary" type="submit">Dołącz</button>
        </form>

        <div class="or">albo</div>

        <div class="actions">
          <div class="eyebrow">Prowadzisz grę?</div>
          ${savedHost && isCode(savedHost.code) ? `<button class="btn-primary" data-act="host-resume">Wróć do lobby ${esc(savedHost.code)}</button>` : ""}
          <button class="${savedHost ? "btn-ghost" : "btn-primary"}" data-act="host-new">Załóż nowe lobby</button>
          <p class="summary">Mistrz gry nie dostaje roli. Ustawia grę, widzi role wszystkich i dostaje powiadomienia o użytych kartach. Najlepiej, żeby jego telefon miał tę stronę otwartą przez całą grę.</p>
        </div>
      </section>`;
  }

  let lastScreen = null;
  function render(quiet) {
    if (quiet && ui.screen !== "host") return;
    const active = document.activeElement;
    if (quiet && active && active.tagName === "INPUT" && app.contains(active)) return;
    const html = ui.screen === "host" ? renderHost() : ui.screen === "player" ? renderPlayer() : renderHome();
    app.innerHTML = html;
    if (ui.screen !== lastScreen) window.scrollTo(0, 0);
    lastScreen = ui.screen;
  }

  // ---------- Events ----------
  app.addEventListener("submit", e => {
    e.preventDefault();
    if (e.target.id !== "join-form") return;
    const code = cleanCode(document.getElementById("join-code").value);
    const name = cleanName(document.getElementById("join-name").value);
    if (!isCode(code)) { ui.error = `Kod lobby ma ${CODE_LEN} liter.`; render(); return; }
    if (!name) { ui.error = "Wpisz swoje imię."; render(); return; }
    ui.error = "";
    const h = parseHash();
    startPlayer(code, name, h.code === code ? h.fp : "");
  });

  app.addEventListener("change", e => {
    const act = e.target.dataset.act;
    if (!act || !host || ui.screen !== "host") return;
    if (applyConfigAction(host.cfg, act, e.target, host.players.length)) { saveHost(); render(); }
  });

  app.addEventListener("click", e => {
    const btn = e.target.closest("button[data-act]");
    if (!btn || btn.disabled) return;
    const act = btn.dataset.act;
    if (host && ui.screen === "host" && applyConfigAction(host.cfg, act, btn, host.players.length)) { saveHost(); render(); return; }
    switch (act) {
      // start
      case "host-new": writeJSON(HOST_KEY, null); startHost(null); return;
      case "host-resume": startHost(readJSON(HOST_KEY)); return;
      // mistrz gry
      case "copy-link": {
        const url = lobbyUrl(host.code, host.fp);
        if (navigator.clipboard) navigator.clipboard.writeText(url).then(() => { btn.textContent = "Skopiowano"; }, () => {});
        return;
      }
      case "kick": if (isToken(btn.dataset.token)) removePlayer(btn.dataset.token, true); return;
      case "host-deal": hostDeal(); break;
      case "host-redeal": ui.confirm = "redeal"; break;
      case "host-redeal-yes": ui.confirm = null; hostDeal(); break;
      case "host-lobby": ui.confirm = "lobby"; break;
      case "host-lobby-yes":
        ui.confirm = null; host.phase = "lobby"; host.assignment = {}; host.alerts = [];
        saveHost(); broadcast(); break;
      case "host-close": ui.confirm = "close"; break;
      case "host-close-yes": endHost(); return;
      case "ack": host.alerts = host.alerts.filter(id => id !== btn.dataset.id); saveHost(); break;
      // gracz
      case "show-role": ui.reveal = true; break;
      case "hide-role": ui.reveal = false; ui.confirm = null; break;
      case "use": ui.confirm = "use"; break;
      case "use-yes":
        ui.confirm = null;
        pendingUse = true;
        sendBox({ t: "use" });
        // Gdyby potwierdzenie nie dotarło, pozwól spróbować jeszcze raz.
        setTimeout(() => { if (pendingUse && me && !me.used) { pendingUse = false; render(); } }, 8000);
        break;
      case "player-leave": ui.confirm = "leave"; break;
      case "player-leave-yes":
        ui.confirm = null;
        sendBox({ t: "leave" }).finally(() => { stopPlayer(true); render(); });
        return;
      case "retry-join": {
        const p = player;
        ui.error = "";
        if (p) startPlayer(p.code, p.name, p.fp);
        return;
      }
      case "player-home": stopPlayer(true); ui.error = ""; ui.status = "connecting"; break;
      case "confirm-no": ui.confirm = null; break;
      default: return;
    }
    render();
  });

  // Po odświeżeniu strony wróć tam, gdzie się było.
  const resumeHost = readJSON(HOST_KEY);
  const resumePlayer = readJSON(PLAYER_KEY);
  const h = parseHash();
  if (!window.mqtt || !crypto.subtle) {
    app.innerHTML = `<section class="screen"><h2>Brak połączenia</h2><p class="warn">Nie udało się wczytać biblioteki do łączenia telefonów albo przeglądarka nie obsługuje szyfrowania. Sprawdź internet i odśwież stronę.</p></section>`;
  } else if (resumeHost && !h.code) {
    startHost(resumeHost);
  } else if (resumePlayer && isCode(resumePlayer.code) && resumePlayer.name && (!h.code || h.code === resumePlayer.code)) {
    startPlayer(resumePlayer.code, resumePlayer.name, h.code === resumePlayer.code ? h.fp : resumePlayer.fp);
  } else {
    render();
  }
})();
