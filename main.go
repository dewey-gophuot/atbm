package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/gorilla/websocket"
)

type report struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Username   string    `json:"username"`
	Ciphertext string    `json:"ciphertext"`
	Plaintext  string    `json:"plaintext,omitempty"`
}

type submitReportRequest struct {
	Username   string `json:"username"`
	Ciphertext string `json:"ciphertext"`
}

type decryptAllRequest struct {
	Passphrase string `json:"passphrase"`
}

type wsEvent struct {
	Type   string `json:"type"`
	Report report `json:"report"`
}

type app struct {
	mu             sync.Mutex
	reports        []report
	nextID         int64
	clientsMu      sync.Mutex
	clients        map[*websocket.Conn]struct{}
	storagePath    string
	privateKeyRing openpgp.EntityList
	publicKey      string
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const submitPageHTML = `<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Live PGP Demo</title>
  <script src="https://cdn.jsdelivr.net/npm/openpgp@5.11.3/dist/openpgp.min.js"></script>
  <style>
		:root { --ink: #102a43; --accent: #0a9396; --accent2: #ee9b00; --panel: #f8fafc; }
		body {
			font-family: ui-monospace, Menlo, monospace;
			max-width: 900px;
			margin: 32px auto;
			padding: 0 16px;
			line-height: 1.5;
			background: linear-gradient(160deg, #fffdf4 0%, #f6fffd 60%, #edf6ff 100%);
			color: var(--ink);
		}
		textarea, input, button { width: 100%; margin-top: 10px; font: inherit; }
		textarea {
		  min-height: 240px;
			border: 2px solid #88c0d0;
			border-radius: 14px;
			padding: 12px;
			background: #ffffff;
		}
		input {
			border: 1px solid #a5b7cc;
			border-radius: 10px;
			padding: 10px;
		}
		button {
			padding: 12px;
			cursor: pointer;
			background: var(--accent);
			color: #fff;
			border: 0;
			border-radius: 10px;
			font-weight: 700;
		}
    .ok { color: #0a7a28; }
    .err { color: #b70000; }
		.box {
			border: 1px solid #c9d7e6;
			border-radius: 12px;
			padding: 12px;
			margin-top: 16px;
			background: var(--panel);
		}
		.username-badge {
			display: inline-block;
			margin-top: 8px;
			background: #fff3d4;
			color: #7c2d12;
			border: 1px solid #f7c76b;
			border-radius: 999px;
			padding: 6px 12px;
			font-size: 14px;
			font-weight: 800;
			letter-spacing: .04em;
		}
  </style>
</head>
<body>
  <h1>Live PGP Demo</h1>
  <p>Nhập câu bất kỳ. Dữ liệu sẽ được mã hóa bằng PGP ngay trên trình duyệt trước khi gửi.</p>

  <div class="box">
    <label>Backend URL</label>
    <input id="backendUrl" value="" placeholder="https://your-backend.example.com" />
		<div id="usernameBadge" class="username-badge"></div>
    <label>Nội dung</label>
    <textarea id="msg" placeholder="Xin chao tu hang ghe thu 3..."></textarea>
    <button id="sendBtn">Ma hoa va gui</button>
    <p id="status"></p>
  </div>

  <div class="box">
    <strong>PGP Public Key</strong>
    <pre id="pubkey" style="white-space: pre-wrap"></pre>
  </div>

  <script>
    const backendInput = document.getElementById('backendUrl');
    const msgEl = document.getElementById('msg');
    const statusEl = document.getElementById('status');
    const pubKeyEl = document.getElementById('pubkey');
		const usernameBadgeEl = document.getElementById('usernameBadge');
    const sendBtn = document.getElementById('sendBtn');
		let username = '';

		function generateUsername() {
			const prefixes = ['Falcon', 'Pixel', 'Neon', 'Cipher', 'Nova', 'Echo', 'Comet', 'Drift'];
			const suffixes = ['Fox', 'Rider', 'Spark', 'Wave', 'Ninja', 'Scope', 'Pilot', 'Leaf'];
			const a = prefixes[Math.floor(Math.random() * prefixes.length)];
			const b = suffixes[Math.floor(Math.random() * suffixes.length)];
			const n = Math.floor(100 + Math.random() * 900);
			return a + b + n;
		}

		function refreshUsername() {
			username = generateUsername();
			usernameBadgeEl.textContent = 'Username: ' + username;
		}

    function normalizeBaseURL(raw) {
      let s = (raw || '').trim();
      if (!s) s = window.location.origin;
      return s.replace(/\/$/, '');
    }

    async function loadPublicKey() {
      const base = normalizeBaseURL(backendInput.value);
      backendInput.value = base;
      const resp = await fetch(base + '/public-key');
      if (!resp.ok) {
        throw new Error('Khong tai duoc public key: HTTP ' + resp.status);
      }
      const key = await resp.text();
      pubKeyEl.textContent = key;
      return key;
    }

    sendBtn.addEventListener('click', async () => {
      try {
        statusEl.className = '';
        statusEl.textContent = 'Dang ma hoa...';
        const publicKeyArmored = await loadPublicKey();
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: msgEl.value });
        const ciphertext = await openpgp.encrypt({ message, encryptionKeys: publicKey, format: 'armored' });

        const base = normalizeBaseURL(backendInput.value);
        const resp = await fetch(base + '/submit-report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username, ciphertext })
        });
        if (!resp.ok) {
          throw new Error('Gui that bai: HTTP ' + resp.status);
        }
        statusEl.className = 'ok';
				statusEl.textContent = 'Da gui thanh cong voi username ' + username + ' (chi gui du lieu da ma hoa).';
				refreshUsername();
      } catch (err) {
        statusEl.className = 'err';
        statusEl.textContent = err.message || String(err);
      }
    });

    backendInput.value = window.location.origin;
		refreshUsername();
    loadPublicKey().catch((e) => {
      statusEl.className = 'err';
      statusEl.textContent = e.message || String(e);
    });
  </script>
</body>
</html>`

const screenPageHTML = `<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PGP Live Wall</title>
  <style>
    :root { --bg: #0a0f1f; --fg: #dbe7ff; --enc: #8fb9ff; --dec: #84f5c9; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      color: var(--fg);
      background: radial-gradient(circle at 20% 10%, #1c2c57 0%, #0a0f1f 45%, #02040a 100%);
      min-height: 100vh;
      overflow: hidden;
    }
    header { padding: 20px 24px; border-bottom: 1px solid rgba(255,255,255,0.15); }
    h1 { margin: 0; font-size: 28px; }
		#layout {
      display: grid;
			grid-template-columns: 1fr 1fr;
      gap: 14px;
      padding: 14px;
      max-height: calc(100vh - 82px);
		}
		.panel {
			border: 1px solid rgba(255,255,255,0.15);
			border-radius: 10px;
			background: rgba(255,255,255,0.03);
			min-height: 0;
			display: flex;
			flex-direction: column;
		}
		.panel h2 {
			margin: 0;
			padding: 10px 12px;
			border-bottom: 1px solid rgba(255,255,255,0.12);
			font-size: 16px;
			letter-spacing: .04em;
		}
		.stream {
			overflow: auto;
			padding: 14px;
			display: flex;
			flex-direction: column;
			align-items: stretch;
			gap: 18px;
			max-height: calc(100vh - 144px);
    }
    .card {
      border: 1px solid rgba(255,255,255,0.16);
      border-radius: 10px;
      padding: 12px;
      background: rgba(255,255,255,0.05);
      animation: pop .35s ease;
			width: 100%;
			min-height: 180px;
			overflow: auto;
    }
    .enc { border-color: rgba(143,185,255,0.6); }
    .dec { border-color: rgba(132,245,201,0.8); background: rgba(132,245,201,0.11); }
		.meta {
			font-size: 12px;
			opacity: .85;
			margin-bottom: 10px;
			padding-bottom: 8px;
			border-bottom: 1px dashed rgba(255,255,255,0.22);
		}
		.username {
			margin-bottom: 10px;
			padding: 2px 8px;
			display: inline-block;
			border-radius: 999px;
			background: rgba(255, 209, 102, 0.14);
			font-weight: 900;
			color: #ffd166;
			font-size: 14px;
			letter-spacing: .03em;
		}
		.dec .username {
			color: #8ff7cb;
			background: rgba(143, 247, 203, 0.14);
		}
		pre {
			margin: 0;
			white-space: pre;
			overflow: auto;
			font-size: 12px;
			line-height: 1.45;
			padding-right: 4px;
		}
    @keyframes pop { from { transform: translateY(8px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
		@media (max-width: 980px) {
			body { overflow: auto; }
			#layout { grid-template-columns: 1fr; max-height: none; }
			.stream { max-height: 45vh; }
		}
  </style>
</head>
<body>
  <header>
    <h1>Live Encrypted Feed</h1>
  </header>
	<section id="layout">
		<article class="panel">
			<h2>Encrypted PGP Blocks</h2>
			<section id="encStream" class="stream"></section>
		</article>
		<article class="panel">
			<h2>Decrypted Plaintext</h2>
			<section id="decStream" class="stream"></section>
		</article>
	</section>

  <script>
		const encStream = document.getElementById('encStream');
		const decStream = document.getElementById('decStream');
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(proto + '//' + window.location.host + '/ws');

    function addCard(type, report) {
      const card = document.createElement('article');
      card.className = 'card ' + (type === 'decrypted' ? 'dec' : 'enc');
      const ts = new Date(report.timestamp || Date.now()).toLocaleTimeString();
      const title = type === 'decrypted' ? 'DECRYPTED' : 'ENCRYPTED';
      const body = type === 'decrypted' ? report.plaintext : report.ciphertext;
	const username = report.username || 'Anonymous';
	card.innerHTML = '<div class="meta">#' + report.id + ' | ' + title + ' | ' + ts + '</div><div class="username">@' + username + '</div><pre></pre>';
      card.querySelector('pre').textContent = body;
			const target = type === 'decrypted' ? decStream : encStream;
			target.prepend(card);
			while (target.children.length > 120) {
				target.removeChild(target.lastChild);
      }
    }

    ws.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        addCard(payload.type, payload.report);
      } catch (e) {
        console.error(e);
      }
    };

    ws.onerror = () => {
      const card = document.createElement('article');
      card.className = 'card';
      card.textContent = 'WebSocket loi, vui long refresh.';
			encStream.prepend(card);
    };
  </script>
</body>
</html>`

func main() {
	addr := envOrDefault("ADDR", ":4321")
	publicKeyPath := envOrDefault("PUBLIC_KEY_PATH", "public.asc")
	privateKeyPath := envOrDefault("PRIVATE_KEY_PATH", "private.asc")
	storagePath := envOrDefault("REPORT_STORAGE", "reports.jsonl")
	demoKeyName := envOrDefault("DEMO_KEY_NAME", "Live Demo")
	demoKeyEmail := envOrDefault("DEMO_KEY_EMAIL", "demo@example.local")
	demoKeyPassphrase := envOrDefault("DEMO_KEY_PASSPHRASE", "")

	if err := ensureKeyFiles(publicKeyPath, privateKeyPath, demoKeyName, demoKeyEmail, demoKeyPassphrase); err != nil {
		log.Fatalf("cannot prepare key files: %v", err)
	}

	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalf("cannot read public key %q: %v", publicKeyPath, err)
	}

	var privateKeyRing openpgp.EntityList
	if b, readErr := os.ReadFile(privateKeyPath); readErr == nil {
		privateKeyRing, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
		if err != nil {
			log.Fatalf("cannot parse private key %q: %v", privateKeyPath, err)
		}
		log.Printf("private key loaded from %s", privateKeyPath)
	} else {
		log.Printf("private key not found at %s, /admin/decrypt-all will be disabled", privateKeyPath)
	}

	a := &app{
		clients:        make(map[*websocket.Conn]struct{}),
		storagePath:    storagePath,
		privateKeyRing: privateKeyRing,
		publicKey:      string(publicKeyBytes),
	}

	if err := a.loadReports(); err != nil {
		log.Fatalf("cannot load reports: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleSubmitPage)
	mux.HandleFunc("/screen", a.handleScreenPage)
	mux.HandleFunc("/public-key", a.handlePublicKey)
	mux.HandleFunc("/submit-report", a.handleSubmitReport)
	mux.HandleFunc("/admin/decrypt-all", a.handleDecryptAll)
	mux.HandleFunc("/ws", a.handleWS)

	server := withCORS(mux)
	log.Printf("server listening at http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, server))
}

func ensureKeyFiles(publicKeyPath, privateKeyPath, name, email, passphrase string) error {
	_, pubErr := os.Stat(publicKeyPath)
	_, priErr := os.Stat(privateKeyPath)
	if pubErr == nil && priErr == nil {
		return nil
	}
	if pubErr == nil && os.IsNotExist(priErr) {
		return fmt.Errorf("private key %q is missing while public key exists", privateKeyPath)
	}
	if os.IsNotExist(pubErr) && priErr == nil {
		return fmt.Errorf("public key %q is missing while private key exists", publicKeyPath)
	}
	if !os.IsNotExist(pubErr) && pubErr != nil {
		return pubErr
	}
	if !os.IsNotExist(priErr) && priErr != nil {
		return priErr
	}

	if err := generateDemoKeyPair(publicKeyPath, privateKeyPath, name, email, passphrase); err != nil {
		return err
	}
	log.Printf("generated demo key pair: public=%s private=%s", publicKeyPath, privateKeyPath)
	if strings.TrimSpace(passphrase) == "" {
		log.Printf("generated fallback key is not passphrase-protected")
	} else {
		log.Printf("note: DEMO_KEY_PASSPHRASE is ignored for auto-generated fallback key")
	}
	return nil
}

func generateDemoKeyPair(publicKeyPath, privateKeyPath, name, email, passphrase string) error {
	_ = passphrase
	entity, err := openpgp.NewEntity(name, "", email, nil)
	if err != nil {
		return fmt.Errorf("create entity: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(filepath.Clean(publicKeyPath)), 0o755); err != nil && filepath.Dir(publicKeyPath) != "." {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(privateKeyPath)), 0o755); err != nil && filepath.Dir(privateKeyPath) != "." {
		return err
	}

	pubFile, err := os.OpenFile(publicKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	pubArmor, err := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	if err := entity.Serialize(pubArmor); err != nil {
		return err
	}
	if err := pubArmor.Close(); err != nil {
		return err
	}

	priFile, err := os.OpenFile(privateKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer priFile.Close()

	priArmor, err := armor.Encode(priFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	if err := entity.SerializePrivate(priArmor, nil); err != nil {
		return err
	}
	if err := priArmor.Close(); err != nil {
		return err
	}

	return nil
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) handleSubmitPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, submitPageHTML)
}

func (a *app) handleScreenPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, screenPageHTML)
}

func (a *app) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, a.publicKey)
}

func (a *app) handleSubmitReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req submitReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Username = sanitizeUsername(req.Username)
	req.Ciphertext = strings.TrimSpace(req.Ciphertext)
	if req.Ciphertext == "" {
		http.Error(w, "ciphertext is required", http.StatusBadRequest)
		return
	}

	report := report{
		ID:         atomic.AddInt64(&a.nextID, 1),
		Timestamp:  time.Now().UTC(),
		Username:   req.Username,
		Ciphertext: req.Ciphertext,
	}

	a.mu.Lock()
	a.reports = append(a.reports, report)
	a.mu.Unlock()

	if err := a.appendReport(report); err != nil {
		log.Printf("cannot persist report id=%d: %v", report.ID, err)
	}

	a.broadcast(wsEvent{Type: "encrypted", Report: report})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"id": report.ID,
	})
}

func (a *app) handleDecryptAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(a.privateKeyRing) == 0 {
		http.Error(w, "private key is not loaded", http.StatusServiceUnavailable)
		return
	}

	var req decryptAllRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	decrypted := 0
	failed := 0
	for i := range a.reports {
		if strings.TrimSpace(a.reports[i].Plaintext) != "" {
			continue
		}
		plain, err := decryptPGP(a.privateKeyRing, req.Passphrase, a.reports[i].Ciphertext)
		if err != nil {
			failed++
			continue
		}
		a.reports[i].Plaintext = plain
		decrypted++
		a.broadcast(wsEvent{Type: "decrypted", Report: a.reports[i]})
	}
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"decrypted": decrypted,
		"failed":    failed,
	})
}

func (a *app) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	a.clientsMu.Lock()
	a.clients[conn] = struct{}{}
	a.clientsMu.Unlock()

	// Send existing encrypted feed first so screen isn't empty on refresh.
	a.mu.Lock()
	existing := append([]report(nil), a.reports...)
	a.mu.Unlock()
	for _, r := range existing {
		if err := conn.WriteJSON(wsEvent{Type: "encrypted", Report: r}); err != nil {
			_ = conn.Close()
			a.removeClient(conn)
			return
		}
		if strings.TrimSpace(r.Plaintext) != "" {
			if err := conn.WriteJSON(wsEvent{Type: "decrypted", Report: r}); err != nil {
				_ = conn.Close()
				a.removeClient(conn)
				return
			}
		}
	}

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			_ = conn.Close()
			a.removeClient(conn)
			return
		}
	}
}

func (a *app) removeClient(conn *websocket.Conn) {
	a.clientsMu.Lock()
	delete(a.clients, conn)
	a.clientsMu.Unlock()
}

func (a *app) broadcast(evt wsEvent) {
	a.clientsMu.Lock()
	defer a.clientsMu.Unlock()
	for c := range a.clients {
		if err := c.WriteJSON(evt); err != nil {
			_ = c.Close()
			delete(a.clients, c)
		}
	}
}

func (a *app) appendReport(r report) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(a.storagePath)), 0o755); err != nil && filepath.Dir(a.storagePath) != "." {
		return err
	}
	f, err := os.OpenFile(a.storagePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, string(b))
	return err
}

func (a *app) loadReports() error {
	f, err := os.Open(a.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var maxID int64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r report
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		a.reports = append(a.reports, r)
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	atomic.StoreInt64(&a.nextID, maxID)
	return nil
}

func decryptPGP(privateKeyRing openpgp.EntityList, passphrase, ciphertext string) (string, error) {
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte(passphrase), nil
	}

	block, err := armor.Decode(strings.NewReader(ciphertext))
	if err != nil {
		return "", fmt.Errorf("armor decode: %w", err)
	}
	md, err := openpgp.ReadMessage(block.Body, privateKeyRing, prompt, nil)
	if err != nil {
		return "", fmt.Errorf("read message: %w", err)
	}
	b, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return string(b), nil
}

func sanitizeUsername(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "Anonymous"
	}
	if len(v) > 48 {
		v = v[:48]
	}
	return v
}
