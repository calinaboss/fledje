# 💩 Fledje Poop Shooter & Leaderboard (Cloudflare Pages + D1)

Mini-gioco arcade web con sistema account, leaderboard globale e backend serverless su **Cloudflare Pages**, **Workers** e **Cloudflare D1 (SQLite)**.

Progettato con standard di **massima sicurezza OWASP** per repo pubbliche su GitHub (nessuna password, secret o token hardcodato nel codice).

---

## 🎮 Come Funziona il Gioco
- **Personaggio:** La faccia di Fledje (`face.png`). Si muove con `A` / `D` (o frecce `←` / `→`) oppure touch da smartphone.
- **Sparo:** Spara cacche 💩 (`poop.png`) con la barra `Spazio` o con tap/click.
- **Nemici:** I water (`toilet.png`) scendono dall'alto; distruggili prima che tocchino terra o il giocatore!
- **Final Boss:** Al raggiungimento di 200 punti compare il **Final Boss** (`finalboss.png`) con barra della vita e pattern di attacco speciali.
- **Sfondo:** Mappa custom (`mappa.jpg`).
- **Leaderboard:** Salvataggio punteggio su Cloudflare D1 e classifica globale in tempo reale.

---

## 🛡️ Sicurezza OWASP Implementata

1. **Anti SQL-Injection (OWASP A03: Injection):**
   - Tutte le interazioni col database D1 utilizzano rigorosamente **Prepared Statements parametrizzati** (`db.prepare(...).bind(...)`).
   - Zero concatenazioni di stringhe o template literals SQL.

2. **Sicurezza Password (OWASP A07: Identification and Authentication Failures):**
   - Hashing tramite standard industriale crittografico **PBKDF2-SHA256 con 100.000 iterazioni**.
   - Generazione di un **Salt casuale crittografico unico a 16 byte** per ciascun utente (`crypto.getRandomValues`).
   - Le password non vengono mai salvate in chiaro.

3. **Autenticazione Sessione (Anti-Spoofing & Anti-Tampering):**
   - I punteggi possono essere inviati solo tramite un **Token firmato crittograficamente con HMAC-SHA256**.
   - Validazione della scadenza del token.

4. **Sanitizzazione Input & Anti-XSS (OWASP A03):**
   - Regex whitelist sul nome utente: `^[a-zA-Z0-9_\-]{3,20}$`.
   - Escape di tutto l'HTML dinamico prima del rendering nella classifica con funzione anti-XSS (`escapeHtml`).

5. **Security Headers & CORS (OWASP A05: Security Misconfiguration):**
   - Inserimento di header HTTP conformi:
     - `Content-Security-Policy`
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `X-XSS-Protection: 1; mode=block`
     - `Referrer-Policy: strict-origin-when-cross-origin`

6. **Repo Pubblica Sicura:**
   - Nessun segreto salvato nei file sorgenti. Il segreto JWT può essere configurato come variabile d'ambiente (`JWT_SECRET`) su Cloudflare.

---

## 🚀 Setup e Deploy su Cloudflare Pages

### 1. Crea il Database D1 su Cloudflare
Dalla CLI di wrangler o dalla dashboard di Cloudflare:
```bash
npx wrangler d1 create fledje-db
```
Prendi l'ID del database generato e aggiornalo nel file `wrangler.toml` se necessario.

### 2. Esegui lo Schema SQL
```bash
npx wrangler d1 execute fledje-db --file=schema.sql --remote
```

### 3. Collega il Database al progetto Cloudflare Pages
Nella Dashboard di Cloudflare:
1. Vai su **Workers & Pages** -> seleziona il tuo progetto `fledje`.
2. Vai su **Settings** -> **Functions** -> **D1 database bindings**.
3. Aggiungi binding:
   - **Variable name:** `DB`
   - **D1 database:** seleziona `fledje-db`.
4. (Opzionale per max sicurezza) Aggiungi la variabile d'ambiente segreta:
   - **Variable name:** `JWT_SECRET`
   - **Value:** una chiave segreta a tua scelta.

### 4. Deploy
Fai semplicemente il push sul tuo repository GitHub:
```bash
git add .
git commit -m "feat: fledje poop shooter and d1 leaderboard"
git push origin master
```
Cloudflare Pages pubblicherà in automatico sia i file statici (`index.html`, `game.html`, immagini) sia le Cloudflare Pages Functions (`/api/auth`, `/api/leaderboard`).
