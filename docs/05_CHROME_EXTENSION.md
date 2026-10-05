# 05 — The Chrome Extension, From Basics

The extension turns PhishGuard from "a page you visit and paste a URL into" into **passive,
automatic protection** — it checks every page you navigate to and warns you *before* you interact.
This document explains browser extensions from scratch, then this one specifically.

---

## 1. What a browser extension is (from zero)

A browser extension is a small program made of **web technologies (HTML/CSS/JS)** that the browser
loads with **elevated privileges** — it can observe tabs, run code in pages, and show its own UI.
Extensions are sandboxed and must **declare** every privilege they want in a **manifest** file, so
the user can see exactly what they're granting.

### Manifest V2 vs Manifest V3 (why V3)

- **MV2** (old) used a **persistent background page** that ran forever in the background — heavy on
  memory and a security concern.
- **MV3** (current, mandatory) replaces it with an **event-driven service worker** that spins up
  only when needed and is killed when idle, and enforces a strict **Content Security Policy (CSP)**
  — notably **no `eval`, no `new Function`, no remote code**. This project targets **MV3** because
  MV2 is being removed and MV3 is more secure and resource-light.

---

## 2. The parts of this extension

```
extension/
├── manifest.json    ← the declaration: what it is, what it can do
├── background.js    ← the service worker: watches tabs, checks URLs, injects warnings
├── config.js        ← API base + a bounded in-memory cache + fetchWithTimeout
├── popup.html       ← the little window when you click the toolbar icon
└── popup.js         ← fills the popup with the verdict for the current tab
```

### 2.1 `manifest.json` — the declaration

Key fields:
```json
{
  "manifest_version": 3,
  "permissions": ["scripting", "storage"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "action": { "default_popup": "popup.html" }
}
```
- **`manifest_version: 3`** — MV3.
- **`permissions: ["scripting", "storage"]`** —
  - `scripting`: lets the worker **inject** code into a page (to draw the warning banner).
  - `storage`: lets it persist settings (like a custom API base) via `chrome.storage.local`.
  - *(A redundant permission was dropped during the security audit — least-privilege.)*
- **`host_permissions: ["<all_urls>"]`** — needed so it can check whatever site you're on. This is
  the broadest host permission and is justified because a phishing checker must work on *any* page;
  it's the one permission worth being ready to explain in an interview.
- **`background.service_worker`** — names the MV3 service worker.
- **`action.default_popup`** — the toolbar popup.

### 2.2 `background.js` — the service worker (the engine)

This is the always-ready-but-idle brain. What it does:

1. **Loads config** with `importScripts("config.js")` (how a service worker pulls in another
   script).
2. **Listens for navigation:** `chrome.tabs.onUpdated` fires when a tab finishes loading a URL.
3. **`shouldSkip(url)`** — ignores non-web URLs (`chrome://`, `about:`, extension pages, blank
   tabs) so it only checks real http(s) pages.
4. **`checkUrl(url)`** — the core: first checks the **local cache** (see config.js); on a miss it
   calls the backend `POST /predict_url` (via `fetchWithTimeout`), then caches the verdict.
5. **`setBadge(...)`** — paints the toolbar icon badge (e.g. a red "!" for phishing, a check for
   safe) so you get an at-a-glance signal without opening anything.
6. **`injectWarning(tabId, verdict)`** — if the verdict is bad, it injects a **warning banner** into
   the page using:
   ```js
   chrome.scripting.executeScript({ target: { tabId }, func: renderBanner, args: [...] })
   ```
   `renderBanner` builds the banner DOM with **`document.createElement` + `textContent`** — never
   `innerHTML` with page data.

### 2.3 `config.js` — API base + bounded cache

- **`DEFAULT_API_BASE`** = `http://localhost:8000`; `getApiBase()` reads an override from
  `chrome.storage.local` (so you can point it at the Render backend without editing code), and
  `getDashboardUrl()` similarly.
- **`fetchWithTimeout(...)`** — an 8-second timeout so a slow/asleep backend can't hang the worker.
- **A bounded cache** — at most **200 entries**, each with a **60-second TTL**, with `evictCache()`
  removing the oldest/expired. This means revisiting or refreshing a page doesn't spam the backend,
  and memory stays bounded (important: an unbounded cache in a long-lived worker is a leak).

### 2.4 `popup.html` / `popup.js` — the toolbar UI

When you click the toolbar icon:
- `popup.js`'s `init()` queries the **active tab**, gets its URL, and asks for the verdict.
- `renderResult()` fills a **static HTML scaffold** and sets values via `textContent` /
  `querySelector` — again, **no attacker data via `innerHTML`**.
- A `VERDICT` map turns SAFE/SUSPICIOUS/PHISHING into a color, icon, and label; `setBadge` mirrors
  it on the icon; `truncate` shortens long URLs for display.

---

## 3. How the extension connects to the backend

It calls the **exact same API** the web app does:
```
POST  {apiBase}/predict_url    { "url": "<current tab url>" }
```
So there is **one detection brain** (the FastAPI 6-gate ladder) and three clients (checker page,
dashboard, extension). The extension adds only: **automatic triggering** (on navigation), a
**cache** (to avoid re-checking), a **badge**, and an **injected banner**.

Flow for one page visit:
```
you navigate → chrome.tabs.onUpdated → shouldSkip? → cache hit? 
   → (miss) POST /predict_url → cache the verdict → setBadge 
   → if bad: chrome.scripting.executeScript(renderBanner) → banner appears on the page
```

---

## 4. The security fixes (worth mentioning explicitly)

Two real vulnerabilities were found and fixed in the extension during the hardening pass — these
make great "I found and fixed a security bug" interview points:

1. **CSP violation / unsafe code execution (fixed).** An earlier version built the warning banner
   using **`new Function(...)`** — which MV3's Content Security Policy **forbids** (it's how remote
   code injection happens). It was rebuilt to use `chrome.scripting.executeScript({ func })` with
   the banner constructed via `createElement` + `textContent`. Now CSP-compliant and injection-safe.

2. **DOM-based XSS surface (fixed).** Rendering an attacker-controlled URL or reason via
   `innerHTML` could execute markup embedded in a malicious URL. All rendering switched to
   `textContent`/`querySelector` on a static scaffold, so hostile input is shown as **text, never
   executed** — essential because *the entire input to this tool is hostile URLs*.

3. **Least privilege + resource safety.** A redundant permission was removed, `fetch` calls have
   timeouts, and the cache is bounded (200 entries / 60 s TTL) so the long-lived worker can't leak
   memory.

---

## 5. Distribution

The packaged extension ships as **`frontend/phishguard-extension.zip`**, and
**`frontend/extension.html`** is the install guide (load-unpacked in Chrome's developer mode, or
distribute the zip). No build step — it's plain HTML/CSS/JS, consistent with the rest of the
frontend.

---

## 6. Interview soundbite

> *"The extension is a Manifest V3 Chrome extension. A service worker listens for tab navigation,
> checks each page against the same FastAPI `/predict_url` endpoint the web app uses — with an
> 8-second timeout and a bounded 200-entry, 60-second cache so it doesn't spam the backend — and if
> a page is phishing it paints a toolbar badge and injects a warning banner. I built the banner with
> `chrome.scripting.executeScript` and `createElement`/`textContent` instead of `eval`/`innerHTML`,
> both to satisfy MV3's Content Security Policy and to eliminate a DOM-XSS surface, since every input
> to this tool is by definition a hostile URL."*

Next: [06_TESTING.md](06_TESTING.md) — the test suite and the statistical probes.
