#!/usr/bin/env python3
"""
Web Audit QA v4
===============
Auditoría funcional + seguridad completa:
  • Auto-activación de venv + auto-instalación de dependencias
  • Crawl automático con pausa/reanudación manual (panel flotante persistente)
  • Captura COMPLETA de network requests y consola
  • Detección de errores JS, links rotos, forms
  • OWASP Top 10 checks + superficie de exposición
  • API discovery y validación
  • Panel de control flotante (headed) con Pausar/Continuar via expose_function
  • SSO: login manual → guarda cookies → continúa audit
  • Sin límite de páginas por defecto (--max-pages 0)
  • Reporte nombrado: {dominio}_{fecha}.html

Uso:
    python3 web.py https://ejemplo.com
    python3 web.py --headed --max-pages 50 https://ejemplo.com
    python3 web.py --headed --login-url /login --email u@x.com --password clave https://sitio.com
    python3 web.py --headed --sso --login-url /login https://sitio.com

Si no pasas argumentos, usa .env-web (se crea automáticamente la primera vez).
"""

import os
import subprocess
import sys
from pathlib import Path


def _venv_python(root: Path) -> Path:
    if sys.platform == "win32":
        return root / ".venv" / "Scripts" / "python.exe"

    python3 = root / ".venv" / "bin" / "python3"
    return python3 if python3.exists() else root / ".venv" / "bin" / "python"


def _running_in_project_venv(venv_python: Path) -> bool:
    try:
        return Path(sys.executable).resolve() == venv_python.resolve()
    except OSError:
        return False


def _ensure_dependencies():
    """
    Crea .venv junto a web.py, relanza el proceso dentro de él e instala
    dependencias y Chromium sin modificar el Python de Homebrew.
    """
    root = Path(__file__).resolve().parent
    venv_dir = root / ".venv"
    venv_python = _venv_python(root)

    # Al ejecutar ./web.py, el shebang inicia Homebrew Python. En ese caso,
    # crea el venv una vez y reemplaza el proceso por el Python del venv.
    if not _running_in_project_venv(venv_python):
        if not venv_python.exists():
            print("\n📦 Creando entorno virtual local: .venv ...")
            subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])

            venv_python = _venv_python(root)
            if not venv_python.exists():
                print(f"❌ No se encontró Python dentro del venv: {venv_python}")
                sys.exit(1)

            print("   ✅ Entorno virtual creado.\n")

        print("🔁 Ejecutando dentro de .venv...\n")
        os.execv(
            str(venv_python),
            [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
        )

    required = {
        "playwright": "playwright",
        "requests": "requests",
    }

    missing = []
    for module_name, package_name in required.items():
        try:
            __import__(module_name)
        except ImportError:
            missing.append(package_name)

    if missing:
        print(f"\n📦 Instalando dependencias faltantes: {', '.join(missing)}...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", "pip"]
            )
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", *missing]
            )
            print("   ✅ Dependencias instaladas.\n")
        except subprocess.CalledProcessError as error:
            print(f"   ❌ No se pudieron instalar las dependencias: {error}")
            print(
                f"   Ejecuta manualmente: "
                f"{sys.executable} -m pip install {' '.join(missing)}"
            )
            sys.exit(1)

    # Playwright requiere además descargar su navegador.
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
                browser.close()
            except Exception:
                print("\n📦 Instalando navegador Chromium para Playwright...")
                subprocess.check_call(
                    [sys.executable, "-m", "playwright", "install", "chromium"]
                )
                print("   ✅ Chromium instalado.\n")

    except Exception as error:
        print(f"⚠️ No se pudo verificar Chromium: {error}")


_ensure_dependencies()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import time  # noqa: E402
import urllib.parse  # noqa: E402
from dataclasses import asdict, dataclass, field  # noqa: E402
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402

from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout  # noqa: E402


# ── Datos ─────────────────────────────────────────────────────────

@dataclass
class Issue:
    url: str
    kind: str        # js_error|broken_link|form_error|http_error|network|security|exposure|api|misc
    severity: str     # critical|warning|info
    message: str
    screenshot: str = ""
    details: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%H:%M:%S")


@dataclass
class NetEntry:
    page_url: str
    method: str
    url: str
    status: int = 0
    resource_type: str = ""
    size_bytes: int = 0
    duration_ms: int = 0
    failed: bool = False
    error_text: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%H:%M:%S")


@dataclass
class ConEntry:
    page_url: str
    level: str
    text: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%H:%M:%S")


@dataclass
class PageResult:
    url: str
    status: int = 0
    title: str = ""
    screenshot: str = ""
    load_time_ms: int = 0
    forms_found: int = 0
    forms_tested: int = 0
    links_found: int = 0
    issues: list = field(default_factory=list)
    network: list = field(default_factory=list)
    console: list = field(default_factory=list)


FAKE = {
    "name": "Test Auditor", "first_name": "Test", "last_name": "Auditor",
    "email": "test-audit@example.com", "phone": "+1 555-0100",
    "company": "Audit Corp", "message": "Mensaje de prueba QA.",
    "subject": "Prueba QA", "address": "123 Test St", "city": "Santo Domingo",
    "country": "DO", "zip": "10100", "url": "https://example.com",
    "password": "TestPass123!", "username": "testauditor", "search": "test", "q": "test",
}
FIELD_PAT = {
    "email": r"email|correo", "phone": r"phone|tel|mobile|celular",
    "name": r"name|nombre", "company": r"company|empresa",
    "message": r"message|mensaje|comment|nota|text|body",
    "subject": r"subject|asunto", "address": r"address|direcci",
    "city": r"city|ciudad", "country": r"country|pa[ií]s",
    "zip": r"zip|postal", "url": r"url|website|sitio",
    "password": r"password|contrase|clave|pass\b",
    "username": r"username|usuario|user\b", "search": r"search|buscar|q\b",
}


# ── Auditor ───────────────────────────────────────────────────────

class WebAuditor:
    CRUD_MARKER = "QA-TEST-AUDIT"

    def __init__(self, base_url, output, headed=False, max_pages=0,
                 login_url="", email="", password="", sso=False,
                 allowed_domains=None, test_crud=False):
        p = urllib.parse.urlparse(base_url)

        if not p.scheme or not p.netloc:
            raise ValueError("La URL debe incluir protocolo, por ejemplo: http://10.10.20.207:2714")

        self.base_url = f"{p.scheme}://{p.netloc}"
        self.start_path = p.path or "/"
        self.domain = p.netloc
        self.output = output
        self.headed = headed
        self.max_pages = max_pages  # 0 = sin límite
        self.sso = sso
        self.login_url = login_url
        self.login_email = email
        self.login_password = password
        self.test_crud = test_crud
        self._crud_created = []  # registros de prueba creados: {url, id, deleted}

        self.allowed_domains = {p.netloc}
        if allowed_domains:
            for d in allowed_domains:
                d = d.strip()
                if d:
                    self.allowed_domains.add(d)

        self.ss_dir = output / "screenshots"
        self.ss_dir.mkdir(parents=True, exist_ok=True)

        self.visited = set()
        self.queue = []
        self.results = []
        self.issues = []
        self.all_net = []
        self.all_con = []
        self._p_net = []
        self._p_con = []
        self._js_err = []
        self._req_t = {}
        self.apis_found = []
        self._pattern_seen = {}  # base_pattern -> cuántas instancias se encolaron
        self.PATTERN_LIMIT = 3   # máximo de páginas a auditar por patrón repetido
        self._sidebar_explored = False  # solo se descubre el menú lateral una vez
        self.page = None
        self.browser = None
        self.context = None
        self.pw = None

        # Control de pausa
        self._paused = False
        self._last_auto_url = ""

    def start(self):
        print("\n🌐 Abriendo navegador...")
        self.pw = sync_playwright().start()
        self.browser = self.pw.chromium.launch(
            headless=not self.headed,
            args=["--disable-blink-features=AutomationControlled"],
        )
        self.context = self.browser.new_context(
            viewport={"width": 1366, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
            ),
        )
        self.page = self.context.new_page()
        self.page.on("console", self._on_con)
        self.page.on("pageerror", self._on_perr)
        self.page.on("request", self._on_req)
        self.page.on("response", self._on_resp)
        self.page.on("requestfailed", self._on_req_fail)

        # expose_function persiste entre navegaciones — el botón llama a Python.
        # Esto es clave para que el panel se mantenga sincronizado con el
        # estado real, en vez de depender de una bandera JS que se pierde
        # en cada goto().
        if self.headed:
            self.page.expose_function("__qa_toggle", self._toggle_pause)

    def _toggle_pause(self):
        """Llamado desde JS cuando el usuario clickea Pausar/Continuar."""
        self._paused = not self._paused
        state = "PAUSADO" if self._paused else "ACTIVO"
        print(f"   {'⏸' if self._paused else '▶'} {state}")
        return self._paused

    def stop(self):
        """Cierra recursos sin interrupciones (seguro ante Ctrl+C)."""
        for item in (self.context, self.browser, self.pw):
            try:
                if item:
                    item.close() if hasattr(item, "close") else item.stop()
            except KeyboardInterrupt:
                pass
            except Exception:
                pass
        try:
            time.sleep(0.3)
        except KeyboardInterrupt:
            pass

    # ── Eventos ──────────────────────────────────────────────────

    def _on_con(self, message):
        entry = ConEntry(
            page_url=self.page.url if self.page else "",
            level=message.type,
            text=message.text[:1000],
        )
        self._p_con.append(entry)
        self.all_con.append(entry)

        if message.type in ("error", "warning"):
            self._js_err.append({
                "type": message.type,
                "text": message.text,
                "url": self.page.url if self.page else "",
            })
            if message.type == "error":
                print(f"   ❌ [JS Error] {message.text[:150]}")

    def _on_perr(self, error):
        entry = ConEntry(
            page_url=self.page.url if self.page else "",
            level="exception",
            text=str(error)[:1000],
        )
        self._p_con.append(entry)
        self.all_con.append(entry)
        self._js_err.append({
            "type": "exception",
            "text": str(error),
            "url": self.page.url if self.page else "",
        })
        print(f"   ❌ [Exception] {str(error)[:150]}")

    def _on_req(self, request):
        self._req_t[request.url] = time.time()
        url = request.url.lower()
        if any(marker in url for marker in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/ws/")):
            if request.url not in [a["url"] for a in self.apis_found]:
                self.apis_found.append({
                    "url": request.url[:300],
                    "method": request.method,
                    "type": request.resource_type,
                    "page": self.page.url if self.page else "",
                })

    def _on_resp(self, response):
        started = self._req_t.pop(response.url, time.time())
        try:
            size = int(response.headers.get("content-length", 0))
        except Exception:
            size = 0

        entry = NetEntry(
            page_url=self.page.url if self.page else "",
            method=response.request.method,
            url=response.url[:500],
            status=response.status,
            resource_type=response.request.resource_type,
            size_bytes=size,
            duration_ms=int((time.time() - started) * 1000),
        )
        self._p_net.append(entry)
        self.all_net.append(entry)

        if response.status >= 400 or "/api/" in response.url.lower():
            print(f"      ↳ {response.request.method} {response.url[:80]} → {response.status}")

    def _on_req_fail(self, request):
        self._req_t.pop(request.url, None)
        entry = NetEntry(
            page_url=self.page.url if self.page else "",
            method=request.method,
            url=request.url[:500],
            resource_type=request.resource_type,
            failed=True,
            error_text=str(request.failure or "")[:200],
        )
        self._p_net.append(entry)
        self.all_net.append(entry)

    # ── Helpers ──────────────────────────────────────────────────

    def _norm(self, href):
        if not href:
            return None
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        if href.startswith("/"):
            href = f"{self.base_url}{href}"
        elif not href.startswith("http"):
            return None

        parsed = urllib.parse.urlparse(href)
        if parsed.netloc not in self.allowed_domains:
            return None

        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        return clean

    def _ss(self, label):
        hash_id = hashlib.md5(label.encode()).hexdigest()[:8]
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", label)[:60]
        filename = f"{safe}_{hash_id}.png"
        try:
            self.page.screenshot(path=str(self.ss_dir / filename), full_page=False)
        except Exception:
            pass
        return filename

    # ── Panel de control con Pausar/Continuar ───────────────────

    def _inject_panel(self):
        """Inyecta o re-inyecta el panel. Estado real vive en Python.

        El panel se auto-restaura si el SPA lo elimina del DOM (por ejemplo
        al re-renderizar tras cambiar de pestaña o de ruta interna): guarda
        el HTML actual en window.__qaPanelHTML y arma un MutationObserver +
        vigilante por intervalo que lo reinserta solo, sin depender de que
        Python vuelva a llamar a este método.
        """
        if not self.headed:
            return
        try:
            self.page.evaluate(
                """(state) => {
                    const paused = state.paused;
                    const html = `<div id="qa-panel" style="position:fixed;top:10px;right:10px;z-index:2147483647;
                        background:#1e293b;color:#e2e8f0;border:2px solid ${paused ? '#f59e0b' : '#38bdf8'};
                        border-radius:12px;padding:12px 16px;font:13px/1.4 system-ui;
                        box-shadow:0 8px 32px rgba(0,0,0,.5);min-width:260px;user-select:none;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                            <strong style="color:#38bdf8;">🔍 QA Audit</strong>
                            <span style="font-size:11px;color:${paused ? '#f59e0b' : '#22c55e'};">
                                ${paused ? '⏸ Pausado' : '● Activo'}</span>
                        </div>
                        <div style="font-size:11px;color:#94a3b8;margin-bottom:6px;
                            max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${state.pg}</div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:3px;font-size:12px;">
                            <div>📄 ${state.pages} págs</div>
                            <div>⚠️ ${state.issues} issues</div>
                            <div>🌐 ${state.reqs} reqs</div>
                            <div>🔒 ${state.sec} security</div>
                            <div>📝 ${state.forms} forms</div>
                            <div>🔌 ${state.apis} APIs</div>
                        </div>
                        <div style="margin-top:8px;background:#334155;border-radius:4px;height:4px;">
                            <div style="background:#38bdf8;height:100%;border-radius:4px;width:${state.pct}%;transition:width .3s;"></div>
                        </div>
                        <div style="margin-top:10px;display:flex;gap:6px;">
                            <button onclick="(async()=>{
                                const nowPaused = await window.__qa_toggle();
                                this.textContent = nowPaused ? '▶ Continuar' : '⏸ Pausar';
                                this.style.background = nowPaused ? '#22c55e' : '#f59e0b';
                            })()"
                                style="flex:1;padding:6px;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;
                                color:#fff;background:${paused ? '#22c55e' : '#f59e0b'};">
                                ${paused ? '▶ Continuar' : '⏸ Pausar'}</button>
                        </div>
                        <div style="margin-top:6px;font-size:10px;color:#64748b;text-align:center;">
                            Navega libremente mientras está pausado</div>
                    </div>`;

                    window.__qaPanelHTML = html;

                    const mount = () => {
                        const old = document.getElementById('qa-panel');
                        if (old) old.remove();
                        const wrap = document.createElement('div');
                        wrap.innerHTML = window.__qaPanelHTML;
                        document.documentElement.appendChild(wrap.firstElementChild);
                    };
                    mount();

                    // Auto-restaurar si el SPA elimina el panel del DOM
                    // (re-render de React/Vue, cambio de pestaña, etc.)
                    if (!window.__qaWatchdogSet) {
                        window.__qaWatchdogSet = true;

                        const observer = new MutationObserver(() => {
                            if (!document.getElementById('qa-panel') && window.__qaPanelHTML) {
                                const wrap = document.createElement('div');
                                wrap.innerHTML = window.__qaPanelHTML;
                                document.documentElement.appendChild(wrap.firstElementChild);
                            }
                        });
                        observer.observe(document.documentElement, { childList: true, subtree: true });

                        // Respaldo por si el MutationObserver se pierde algún caso
                        setInterval(() => {
                            if (!document.getElementById('qa-panel') && window.__qaPanelHTML) {
                                const wrap = document.createElement('div');
                                wrap.innerHTML = window.__qaPanelHTML;
                                document.documentElement.appendChild(wrap.firstElementChild);
                            }
                        }, 1000);
                    }
                }""",
                self._panel_state(),
            )
        except Exception:
            pass

    def _panel_state(self):
        sec = sum(1 for i in self.issues if i.kind in ("security", "exposure"))
        page_url = (self.page.url if self.page else "")[:50]
        percent = 100 if self.max_pages == 0 else int(len(self.visited) / max(self.max_pages, 1) * 100)
        return {
            "paused": self._paused,
            "pg": page_url.replace("'", ""),
            "pages": len(self.visited),
            "issues": len(self.issues),
            "reqs": len(self.all_net),
            "sec": sec,
            "forms": sum(r.forms_tested for r in self.results),
            "apis": len(self.apis_found),
            "pct": min(100, percent),
        }

    def _wait_while_paused(self):
        """Espera mientras el audit está pausado, re-inyectando el panel."""
        if not self.headed or not self._paused:
            return

        self._last_auto_url = self.page.url
        print("   ⏸ Pausado — navega libremente. Click «Continuar» para reanudar.")
        counter = 0

        while self._paused:
            time.sleep(0.5)
            counter += 1
            if counter % 6 == 0:
                self._inject_panel()

        print("   ▶ Reanudando audit...")
        current = self.page.url
        if current != self._last_auto_url:
            normalized = self._norm(current)
            if normalized and normalized not in self.visited:
                self.queue.insert(0, normalized)
                print(f"   📌 Añadida al queue: {current}")

    # ── Login ────────────────────────────────────────────────────

    def do_login(self):
        if not self.login_url:
            return True

        login_url = self.login_url if self.login_url.startswith("http") else f"{self.base_url}{self.login_url}"

        if self.sso:
            return self._do_sso_login(login_url)

        if not self.login_email:
            return True

        print(f"🔐 Login automático: {self.login_email}")
        try:
            self.page.goto(login_url, timeout=30000, wait_until="domcontentloaded")
            self.page.wait_for_load_state("networkidle", timeout=10000)
        except PwTimeout:
            pass
        except Exception as error:
            print(f"   ❌ {error}")
            return False

        time.sleep(1)

        try:
            for sel in ('input[name="login"]', 'input[type="email"]', 'input[name*="email" i]', 'input[name*="user" i]'):
                el = self.page.locator(sel).first
                if el.count() and el.is_visible():
                    el.fill(self.login_email)
                    break

            el = self.page.locator('input[type="password"]').first
            if el.is_visible():
                el.fill(self.login_password)

            time.sleep(0.5)

            clicked = False
            for sel in ('button[type="submit"]', 'input[type="submit"]', 'form button:has-text("Log in")', 'form button:has-text("Iniciar")'):
                el = self.page.locator(sel).first
                if el.count() and el.is_visible():
                    el.click()
                    clicked = True
                    break
            if not clicked:
                self.page.locator('input[type="password"]').first.press("Enter")

            try:
                self.page.wait_for_load_state("domcontentloaded", timeout=15000)
            except PwTimeout:
                pass
        except Exception as error:
            print(f"   ⚠️ {error}")
            return False

        # Esperar hasta 8s a que la URL cambie o desaparezca el form de login,
        # en vez de un sleep fijo — algunos SPA tardan en redirigir aunque el
        # login ya fue exitoso.
        login_confirmed = False
        for _ in range(16):
            time.sleep(0.5)
            current_url = self.page.url.lower()

            if "/login" not in current_url:
                login_confirmed = True
                break

            try:
                still_has_password = self.page.locator('input[type="password"]').first.is_visible(timeout=500)
            except Exception:
                still_has_password = False

            if not still_has_password:
                login_confirmed = True
                break

        if not login_confirmed:
            print(f"   ❌ Login falló o permaneció en login: {self.page.url}")
            self._ss("login_failed")
            return False

        print(f"   ✅ Login OK: {self.page.url}\n")
        return True

    def _do_sso_login(self, url):
        print("\n🔐 SSO Manual — Navega al login y autentícate.")
        print(f"   URL: {url}")
        print("   ⏳ Esperando que completes el login...")
        print("   → Click «▶ Continuar» en el panel cuando termines.\n")

        try:
            self.page.goto(url, timeout=30000, wait_until="domcontentloaded")
            self.page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        time.sleep(1)
        self._paused = True
        self._inject_panel()

        started = time.time()
        counter = 0

        while self._paused:
            time.sleep(0.5)
            counter += 1
            if counter % 6 == 0:
                self._inject_panel()
            if time.time() - started > 600:
                print("   ⏰ Timeout SSO (10 min)")
                return False

        cookies = self.context.cookies()
        print(f"   ✅ SSO completado. {len(cookies)} cookies en contexto.")

        if self.domain not in self.page.url:
            try:
                self.page.goto(self.base_url, timeout=15000, wait_until="domcontentloaded")
                time.sleep(2)
            except Exception:
                pass

        print(f"   📍 Actual: {self.page.url}\n")
        return True

    # ── Crawl ────────────────────────────────────────────────────

    # Rutas conocidas de routes.tsx (React Router v7) bajo /dashboard.
    # Sembrarlas directamente es mucho más confiable que descubrirlas
    # por click en el sidebar (nombres de texto pueden no calzar, items
    # colapsados, etc.) — así se garantiza visitar TODAS las secciones,
    # incluyendo las que disparan el "Unexpected Application Error".
    KNOWN_DASHBOARD_ROUTES = [
        "", "new-initiative", "projects", "committees", "votaciones",
        "assignments", "ai-assistance", "saved-reports", "archive",
        "sources", "drafts", "agenda", "schedule-session", "directory",
        "email", "aportes", "notifications", "presidential-dashboard",
        "executive-legislative", "admin", "support", "press",
        "sil", "sil/busqueda", "sil/expedientes", "sil/reportes",
    ]

    def crawl(self):
        first_url = f"{self.base_url}{self.start_path}"

        # Si hay login, comenzar desde la URL post-login (no la ruta original,
        # que suele quedar en /login y provocaría reingresar al formulario)
        if self.login_url:
            normalized = self._norm(self.page.url)
            self.queue.append(normalized or first_url)
        else:
            self.queue.append(first_url)

        # Sembrar todas las rutas conocidas del frontend (routes.tsx)
        for route in self.KNOWN_DASHBOARD_ROUTES:
            seeded = f"{self.base_url}/dashboard" + (f"/{route}" if route else "")
            if seeded not in self.queue and seeded not in self.visited:
                self.queue.append(seeded)

        print(f"   🗺️ {len(self.KNOWN_DASHBOARD_ROUTES)} rutas conocidas sembradas en la cola.")

        limit_reached = lambda: self.max_pages > 0 and len(self.visited) >= self.max_pages  # noqa: E731

        while self.queue and not limit_reached():
            self._wait_while_paused()

            url = self.queue.pop(0)
            if url in self.visited:
                continue

            self.visited.add(url)
            max_str = str(self.max_pages) if self.max_pages > 0 else "∞"
            print(f"\n[{len(self.visited)}/{max_str}] 🔍 {url}")

            result = self._audit_page(url)
            self.results.append(result)

            if result.issues:
                print(f"   ⚠️ {len(result.issues)} problemas")

    def _audit_page(self, url):
        pr = PageResult(url=url)
        self._js_err.clear()
        self._p_net.clear()
        self._p_con.clear()

        started = time.time()
        try:
            resp = self.page.goto(url, timeout=30000, wait_until="domcontentloaded")
            self.page.wait_for_load_state("networkidle", timeout=15000)
            pr.status = resp.status if resp else 0
        except PwTimeout:
            pr.status = 0
        except Exception as error:
            pr.status = 0
            issue = Issue(url=url, kind="http_error", severity="critical", message=f"No cargó: {error}")
            pr.issues.append(issue)
            self.issues.append(issue)
            return pr

        pr.load_time_ms = int((time.time() - started) * 1000)
        time.sleep(1)
        self._inject_panel()

        try:
            pr.title = self.page.title() or "(sin título)"
        except Exception:
            pr.title = "(error)"

        pr.screenshot = self._ss(f"p_{url}")

        if pr.status >= 400:
            sev = "critical" if pr.status >= 500 else "warning"
            issue = Issue(url=url, kind="http_error", severity=sev, message=f"HTTP {pr.status} (página)", screenshot=pr.screenshot)
            pr.issues.append(issue)
            self.issues.append(issue)

        if pr.load_time_ms > 5000:
            issue = Issue(url=url, kind="misc", severity="warning", message=f"Página lenta: {pr.load_time_ms}ms")
            pr.issues.append(issue)
            self.issues.append(issue)

        for err in self._js_err:
            sev = "critical" if err["type"] == "exception" else "warning"
            issue = Issue(url=url, kind="js_error", severity=sev, message=err["text"][:300], screenshot=pr.screenshot)
            pr.issues.append(issue)
            self.issues.append(issue)

        self._check_error_boundary(url, pr)

        # El descubrimiento por click (_discover_sidebar_nav) queda como
        # respaldo disponible pero desactivado: con las rutas reales de
        # routes.tsx sembradas en crawl(), ya no hace falta adivinar por
        # texto del sidebar, y así se evita disparar acciones no
        # idempotentes al clickear botones desconocidos.

        self._extract_links(url, pr)
        self._test_forms(url, pr)
        self._check_meta(url, pr)
        self._check_security(url, pr)

        for ne in self._p_net:
            if ne.failed:
                issue = Issue(url=url, kind="network", severity="warning",
                               message=f"Request fallido: {ne.method} {ne.url[:120]}", details=ne.error_text)
                pr.issues.append(issue)
                self.issues.append(issue)
            elif ne.status >= 400:
                if ne.resource_type == "document":
                    sev = "critical" if ne.status >= 500 else "warning"
                else:
                    sev = "info"
                issue = Issue(url=url, kind="network", severity=sev,
                               message=f"HTTP {ne.status}: {ne.resource_type} {ne.url[:120]}")
                pr.issues.append(issue)
                self.issues.append(issue)

        pr.network = list(self._p_net)
        pr.console = list(self._p_con)
        self._inject_panel()
        return pr

    def _check_error_boundary(self, url, pr):
        """Detecta la pantalla de fallback de React Router / error boundary
        ('Unexpected Application Error!') directamente en el DOM. React
        atrapa estos errores en render y NO los propaga a window.onerror,
        así que el listener pageerror no los ve — hay que buscarlos en el
        texto de la página."""
        try:
            found = self.page.evaluate(
                """() => {
                    const body = document.body.innerText || '';
                    if (!/Unexpected Application Error/i.test(body)) return null;
                    const pre = document.querySelector('pre');
                    return {
                        stack: pre ? pre.innerText.slice(0, 3000) : body.slice(0, 1500),
                    };
                }"""
            )
        except Exception:
            return

        if not found:
            return

        ss = self._ss(f"error_boundary_{url}")
        message = f"⚠️ ErrorBoundary de React: la ruta {url} crashea y queda inutilizable"
        issue = Issue(url=url, kind="js_error", severity="critical",
                       message=message, details=found.get("stack", ""), screenshot=ss)
        pr.issues.append(issue)
        self.issues.append(issue)
        print(f"   🔴 ¡ErrorBoundary detectado! Ruta rota: {url}")
        print(f"      {found.get('stack', '')[:200]}")

    def _discover_sidebar_nav(self, url, pr):
        """Descubre ítems del menú lateral que no son <a href> (navegación
        client-side vía onClick/router.push, común en apps React). Se
        ejecuta UNA sola vez: identifica el texto de cada ítem visible,
        hace click, registra a dónde navega, y vuelve a la página original
        para probar el siguiente — así el crawler llega a secciones que
        _extract_links nunca vería (Correo, Agenda, Asistencia IA, etc.)."""
        try:
            candidates = self.page.evaluate(
                """() => {
                    const out = [];
                    const seen = new Set();
                    const containers = document.querySelectorAll('aside, nav, [class*="sidebar" i]');
                    containers.forEach(c => {
                        c.querySelectorAll('a, button, [role="button"], li').forEach(el => {
                            const text = (el.textContent || '').trim();
                            if (!text || text.length > 60) return;
                            if (/pendiente/i.test(text)) return;
                            if (/cerrar sesi[oó]n|logout|salir/i.test(text)) return;
                            if (el.offsetParent === null) return;
                            if (seen.has(text)) return;
                            seen.add(text);
                            out.push(text);
                        });
                    });
                    return out;
                }"""
            )
        except Exception:
            candidates = []

        if not candidates:
            return

        print(f"   🧭 Explorando {len(candidates)} ítems del menú (navegación por click)...")

        for text in candidates:
            escaped = text.replace('"', '\\"')
            try:
                locator = self.page.locator(
                    f'aside :text-is("{escaped}"), nav :text-is("{escaped}"), [class*="sidebar" i] :text-is("{escaped}")'
                ).first
                if locator.count() == 0:
                    continue

                before = self.page.url
                locator.click(timeout=3000)
                self.page.wait_for_timeout(1000)
                after = self.page.url

                if after != before:
                    normalized = self._norm(after)
                    if normalized and normalized not in self.visited and normalized not in self.queue:
                        self.queue.append(normalized)
                        print(f"      ↳ «{text}» → {after}")

                    # Detectar si el click mismo disparó el error boundary
                    self._check_error_boundary(after, pr)

                if self.page.url != url:
                    self.page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    self.page.wait_for_load_state("networkidle", timeout=10000)
                    time.sleep(0.5)
            except Exception:
                try:
                    if self.page.url != url:
                        self.page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        time.sleep(0.5)
                except Exception:
                    pass
                continue

    # ── Links ────────────────────────────────────────────────────

    def _extract_links(self, url, pr):
        try:
            links = self.page.evaluate(
                """() => {
                    const urls = new Set();
                    document.querySelectorAll('a[href]').forEach(a => { if (a.href) urls.add(a.href); });
                    document.querySelectorAll('[data-href], [data-url], [data-link]').forEach(el => {
                        const h = el.getAttribute('data-href') || el.getAttribute('data-url') || el.getAttribute('data-link');
                        if (h) urls.add(h);
                    });
                    return Array.from(urls).map(href => ({ href, text: '' }));
                }"""
            )
        except Exception:
            links = []

        pr.links_found = len(links)
        added = 0
        skipped_pattern = 0

        for lk in links:
            normalized = self._norm(lk.get("href", ""))
            if not normalized:
                continue
            if normalized in self.visited or normalized in self.queue:
                continue

            # Evita loops en listados con muchas instancias del mismo patrón
            # (ej: /expediente/11205, /expediente/11206, ...): el contador se
            # incrementa al ENCOLAR, no al visitar — así un solo listado con
            # 200 links del mismo patrón no los cuela todos antes de que el
            # primero se marque como visitado.
            match = re.search(r"^(.*/[a-z_-]+/)\d+", normalized)
            if match:
                base_pattern = match.group(1)
                count = self._pattern_seen.get(base_pattern, 0)
                if count >= self.PATTERN_LIMIT:
                    skipped_pattern += 1
                    continue
                self._pattern_seen[base_pattern] = count + 1

            self.queue.append(normalized)
            added += 1

        if added:
            print(f"   ✅ {added} URLs nuevas en cola (total: {len(self.queue)})")
        if skipped_pattern:
            print(f"   ⏭️ {skipped_pattern} URLs omitidas (mismo patrón repetido, límite {self.PATTERN_LIMIT})")

    # ── Formularios ──────────────────────────────────────────────

    def _test_forms(self, url, pr):
        try:
            forms = self.page.evaluate(
                """() => [...document.querySelectorAll('form')].map((f, i) => ({
                    idx: i, action: f.action || '', method: f.method || 'get', id: f.id || '',
                    fields: [...f.querySelectorAll('input,textarea,select')].map(e => ({
                        tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '',
                        id: e.id || '', placeholder: e.placeholder || '',
                        required: e.required, visible: e.offsetParent !== null
                    }))
                }))"""
            )
        except Exception:
            return

        pr.forms_found = len(forms)

        for form in forms:
            visible = [f for f in form["fields"] if f["visible"] and f["type"] not in ("hidden", "submit", "button")]
            if not visible:
                continue

            pr.forms_tested += 1
            print(f"   📝 Form #{form['idx'] + 1} ({len(visible)} campos)")

            for fld in visible:
                self._fill(form["idx"], fld)

            ss = self._ss(f"form_{form['idx']}_{url}")

            try:
                self._js_err.clear()
                result = self.page.evaluate(
                    """(idx) => {
                        const f = document.querySelectorAll('form')[idx];
                        if (!f) return 'no';
                        const b = f.querySelector('input[type="submit"],button[type="submit"],button:not([type])');
                        if (b) { b.click(); return 'ok'; }
                        return 'no_btn';
                    }""",
                    form["idx"],
                )

                if result == "ok":
                    time.sleep(3)
                    try:
                        self.page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                    ss2 = self._ss(f"form_r_{form['idx']}_{url}")

                    for err in self._js_err:
                        sev = "critical" if err["type"] == "exception" else "warning"
                        issue = Issue(url=url, kind="form_error", severity=sev,
                                      message=f"Form #{form['idx'] + 1}: {err['text'][:200]}", screenshot=ss2)
                        pr.issues.append(issue)
                        self.issues.append(issue)

                    try:
                        errs = self.page.evaluate(
                            """() => {
                                const out = [];
                                ['.error', '.alert-danger', '.form-error', '.invalid-feedback', '[class*="error"]'].forEach(sel => {
                                    document.querySelectorAll(sel).forEach(e => {
                                        const t = e.textContent.trim();
                                        if (t && t.length < 200 && e.offsetParent !== null) out.push(t);
                                    });
                                });
                                return out;
                            }"""
                        )
                        for err_text in errs[:5]:
                            issue = Issue(url=url, kind="form_error", severity="warning",
                                          message=f"Form #{form['idx'] + 1}: {err_text}", screenshot=ss2)
                            pr.issues.append(issue)
                            self.issues.append(issue)
                    except Exception:
                        pass

                    if self.page.url != url:
                        try:
                            self.page.goto(url, timeout=15000, wait_until="domcontentloaded")
                            time.sleep(1)
                        except Exception:
                            pass
            except Exception as error:
                issue = Issue(url=url, kind="form_error", severity="warning",
                               message=f"Form #{form['idx'] + 1}: {error}", screenshot=ss)
                pr.issues.append(issue)
                self.issues.append(issue)

    def _fill(self, form_idx, fld):
        field_type = fld["type"]
        tag = fld["tag"]
        hint = f"{fld['name']} {fld['id']} {fld['placeholder']}".lower()
        sel = f"[name='{fld['name']}']" if fld["name"] else (f"#{fld['id']}" if fld["id"] else None)
        if not sel:
            return

        try:
            el = self.page.locator(sel).first
            if not el.is_visible(timeout=2000):
                return
        except Exception:
            return

        if field_type in ("checkbox", "radio"):
            try:
                el.check()
            except Exception:
                pass
            return

        if tag == "select":
            try:
                opts = self.page.evaluate(
                    """(sel) => {
                        const s = document.querySelector(sel);
                        if (!s) return [];
                        return [...s.options].filter(o => o.value).map(o => o.value);
                    }""",
                    sel,
                )
                if opts:
                    el.select_option(opts[min(1, len(opts) - 1)])
            except Exception:
                pass
            return

        if field_type == "file":
            return

        val = None
        for key, pattern in FIELD_PAT.items():
            if re.search(pattern, hint, re.I):
                val = FAKE.get(key, "test")
                break

        if not val:
            val = {
                "email": FAKE["email"], "tel": FAKE["phone"], "phone": FAKE["phone"],
                "url": FAKE["url"], "number": "42", "date": "2025-01-15",
                "password": FAKE["password"],
            }.get(field_type, "Test QA")

        try:
            el.fill(val)
        except Exception:
            try:
                el.type(val)
            except Exception:
                pass

    # ── Meta ─────────────────────────────────────────────────────

    def _check_meta(self, url, pr):
        try:
            m = self.page.evaluate(
                """() => {
                    const r = {};
                    r.title = document.title || '';
                    const d = document.querySelector('meta[name="description"]'); r.desc = d ? d.content : '';
                    const v = document.querySelector('meta[name="viewport"]'); r.vp = v ? v.content : '';
                    r.h1 = document.querySelectorAll('h1').length;
                    r.img_no_alt = [...document.querySelectorAll('img')].filter(i => !i.alt && i.offsetParent !== null).length;
                    r.inp_no_lbl = [...document.querySelectorAll('input:not([type="hidden"])')].filter(i => {
                        if (i.labels && i.labels.length) return false;
                        if (i.getAttribute('aria-label')) return false;
                        return i.offsetParent !== null;
                    }).length;
                    return r;
                }"""
            )
        except Exception:
            return

        checks = [
            (not m.get("title"), "warning", "Falta <title>"),
            (not m.get("desc"), "info", "Falta meta description"),
            (not m.get("vp"), "warning", "Falta meta viewport"),
            (m.get("h1", 0) == 0, "info", "No hay <h1>"),
            (m.get("h1", 0) > 1, "info", f"Múltiples <h1>: {m.get('h1')}"),
            (m.get("img_no_alt", 0) > 0, "warning", f"{m.get('img_no_alt')} imgs sin alt"),
            (m.get("inp_no_lbl", 0) > 0, "warning", f"{m.get('inp_no_lbl')} inputs sin label"),
        ]

        for cond, sev, msg in checks:
            if cond:
                issue = Issue(url=url, kind="misc", severity=sev, message=msg)
                pr.issues.append(issue)
                self.issues.append(issue)

    # ── OWASP + Superficie ───────────────────────────────────────

    def _check_security(self, url, pr):
        try:
            s = self.page.evaluate(
                r"""() => {
                    const r = {};
                    r.csp = !!document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    r.csrf_miss = []; r.http_act = []; r.pwd_ac = [];
                    document.querySelectorAll('form').forEach((f, i) => {
                        if (f.method.toLowerCase() === 'post' && !f.querySelector('input[name*="csrf"],input[name*="token"],input[name*="_token"]'))
                            r.csrf_miss.push(i);
                        if (f.action && f.action.startsWith('http://')) r.http_act.push(i);
                        f.querySelectorAll('input[type="password"]').forEach(p => {
                            if (p.autocomplete !== 'off' && p.autocomplete !== 'new-password') r.pwd_ac.push(i);
                        });
                    });
                    r.comments = 0;
                    const w = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
                    while (w.nextNode()) r.comments++;
                    r.versions = [];
                    document.querySelectorAll('script[src]').forEach(sc => {
                        const m = sc.src.match(/[-@](\d+\.\d+[.\d]*)/);
                        if (m) r.versions.push(sc.src.split('/').pop().slice(0, 60));
                    });
                    r.http_links = 0; r.blank_no_rel = 0;
                    document.querySelectorAll('a[href]').forEach(a => {
                        if (a.href.startsWith('http://') && !a.href.includes('localhost')) r.http_links++;
                        if (a.target === '_blank') {
                            const rel = (a.rel || '').toLowerCase();
                            if (!rel.includes('noopener') && !rel.includes('noreferrer')) r.blank_no_rel++;
                        }
                    });
                    r.pwd_text = 0;
                    document.querySelectorAll('input[type="text"]').forEach(i => {
                        if (/password|contrase|clave|secret|token|api.?key/.test((i.name + i.id + i.placeholder).toLowerCase())) r.pwd_text++;
                    });
                    r.inline_js = document.querySelectorAll('script:not([src])').length;
                    r.inline_ev = document.querySelectorAll('[onclick],[onload],[onerror],[onsubmit]').length;
                    r.ext_iframes = [...document.querySelectorAll('iframe[src]')].filter(i => {
                        try { return new URL(i.src).hostname !== location.hostname; } catch { return false; }
                    }).map(i => i.src.slice(0, 80));
                    r.ls_keys = Object.keys(localStorage).length;
                    r.js_cookies = document.cookie ? document.cookie.split(';').length : 0;
                    return r;
                }"""
            )
        except Exception:
            return

        sec_hdrs = {}
        try:
            sec_hdrs = self.page.evaluate(
                """() => new Promise(resolve => {
                    fetch(location.href, { method: 'HEAD', credentials: 'same-origin' })
                        .then(resp => { const h = {}; resp.headers.forEach((v, k) => h[k] = v); resolve(h); })
                        .catch(() => resolve({}));
                })"""
            )
        except Exception:
            pass

        def add(kind, sev, msg, det=""):
            issue = Issue(url=url, kind=kind, severity=sev, message=msg, details=det)
            pr.issues.append(issue)
            self.issues.append(issue)

        if s.get("csrf_miss"):
            add("security", "critical", f"A01: {len(s['csrf_miss'])} form POST sin CSRF")
        if s.get("http_act"):
            add("security", "critical", "A02: Form action usa HTTP")
        if s.get("http_links", 0) > 0:
            add("security", "warning", f"A02: {s['http_links']} links HTTP inseguro")
        if s.get("inline_js", 0) > 5:
            add("security", "warning", f"A03: {s['inline_js']} scripts inline (XSS)")
        if s.get("inline_ev", 0) > 0:
            add("security", "info", f"A03: {s['inline_ev']} event handlers inline")

        missing = [
            name for header, name in {
                "strict-transport-security": "HSTS",
                "x-content-type-options": "XCTO",
                "x-frame-options": "XFO",
                "referrer-policy": "Referrer",
                "permissions-policy": "Perms",
            }.items()
            if header not in sec_hdrs
        ]
        if missing:
            add("security", "warning", f"A05: Headers faltantes: {', '.join(missing)}")

        if "content-security-policy" not in sec_hdrs and not s.get("csp"):
            add("security", "warning", "A05: Sin CSP")

        if s.get("versions"):
            add("security", "info", f"A06: {len(s['versions'])} libs con versión expuesta", "; ".join(s["versions"][:5]))

        if s.get("pwd_text", 0) > 0:
            add("security", "critical", f"A07: {s['pwd_text']} campo sensible tipo text")
        if s.get("pwd_ac"):
            add("security", "info", "A07: Password sin autocomplete=off")
        if s.get("blank_no_rel", 0) > 0:
            add("exposure", "warning", f"{s['blank_no_rel']} links _blank sin noopener")
        if s.get("comments", 0) > 0:
            add("exposure", "info", f"{s['comments']} comentarios HTML")
        if s.get("ext_iframes"):
            add("exposure", "warning", f"{len(s['ext_iframes'])} iframe(s) externo(s)", "; ".join(s["ext_iframes"][:3]))
        if s.get("js_cookies", 0) > 0:
            add("exposure", "info", f"{s['js_cookies']} cookies sin HttpOnly")
        if s.get("ls_keys", 0) > 5:
            add("exposure", "info", f"{s['ls_keys']} keys en localStorage")

    # ── API Validation ───────────────────────────────────────────

    def _auth_headers(self):
        """Extrae el token de auth guardado por AuthContext en localStorage
        para que las pruebas CRUD (fuera del navegador, vía `requests`)
        lleguen autenticadas igual que la app."""
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        try:
            token = self.page.evaluate(
                """() => localStorage.getItem('sial_access_token')
                    || localStorage.getItem('access_token')
                    || localStorage.getItem('token')"""
            )
            if token:
                headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass
        return headers

    def _auth_cookies(self):
        try:
            return {c["name"]: c["value"] for c in self.context.cookies()}
        except Exception:
            return {}

    def _crud_payload(self):
        marker = f"[{self.CRUD_MARKER}] Registro de prueba — seguro borrar"
        return {
            "nombre": marker, "titulo": marker, "title": marker, "name": marker,
            "descripcion": "Generado automáticamente por auditoría QA.",
            "description": "Generado automáticamente por auditoría QA.",
            "email": "qa-audit@example.com",
            "estado": "borrador", "status": "draft",
        }

    def _collection_roots(self):
        """A partir de los endpoints observados pasivamente (solo GET),
        deriva las URLs de colección (sin ID final) para poder probar
        POST/PUT/DELETE sobre ellas."""
        roots = set()
        for api in self.apis_found:
            u = api["url"].split("?")[0]
            m = re.match(r"^(https?://[^/]+/.+?)/\d+$", u)
            if m:
                roots.add(m.group(1))
            elif not re.search(r"/\d+/", u):
                roots.add(u)
        return sorted(roots)

    def _test_crud_lifecycle(self, root_url, page_ref):
        """Prueba el ciclo CRUD completo (Create → Read → Update → Delete)
        sobre un endpoint de colección. Crea SU PROPIO registro de prueba
        (marcado con CRUD_MARKER) y lo actualiza/borra a él mismo — nunca
        toca IDs reales existentes, salvo para PUT/DELETE de verificación
        cuando la creación falla, que se dirigen a un ID inventado."""
        import requests
        headers = self._auth_headers()
        cookies = self._auth_cookies()
        created_id = None

        # CREATE
        try:
            r = requests.post(root_url, json=self._crud_payload(), headers=headers, cookies=cookies, timeout=10)
            status = r.status_code
            try:
                body = r.json()
            except Exception:
                body = {}

            if status in (200, 201):
                if isinstance(body, dict):
                    created_id = body.get("id") or body.get("_id") or body.get("uuid")
                self.issues.append(Issue(
                    url=page_ref, kind="api", severity="info",
                    message=f"✅ POST creó registro de prueba: {root_url[:100]} → {status}",
                    details=f"ID creado: {created_id or '(sin id en la respuesta)'}",
                ))
                self._crud_created.append({"url": root_url, "id": created_id, "deleted": False})
            else:
                self.issues.append(Issue(
                    url=page_ref, kind="api", severity="info",
                    message=f"POST {root_url[:100]} → {status}",
                    details=str(body)[:300],
                ))
        except Exception as error:
            self.issues.append(Issue(url=page_ref, kind="api", severity="info",
                                      message=f"POST {root_url[:100]} → error: {error}"))

        item_url = f"{root_url}/{created_id}" if created_id else f"{root_url}/999999999"

        # READ (verificación de que el ciclo se aplica al objeto correcto)
        try:
            r = requests.get(item_url, headers=headers, cookies=cookies, timeout=10)
            self.issues.append(Issue(
                url=page_ref, kind="api", severity="info",
                message=f"GET {item_url[:100]} → {r.status_code}",
            ))
        except Exception:
            pass

        # UPDATE
        try:
            r = requests.put(item_url, json=self._crud_payload(), headers=headers, cookies=cookies, timeout=10)
            status = r.status_code
            unexpected = not created_id and status in (200, 204)
            sev = "warning" if unexpected else "info"
            note = " ⚠️ modificó un ID que no debería existir" if unexpected else ""
            self.issues.append(Issue(
                url=page_ref, kind="api", severity=sev,
                message=f"PUT {item_url[:100]} → {status}{note}",
            ))
        except Exception:
            pass

        # DELETE — limpia el registro propio, o verifica que un ID
        # inventado no pueda borrarse cuando no hubo creación.
        try:
            r = requests.delete(item_url, headers=headers, cookies=cookies, timeout=10)
            status = r.status_code

            if created_id:
                if status in (200, 202, 204):
                    for c in self._crud_created:
                        if c["url"] == root_url and c["id"] == created_id:
                            c["deleted"] = True
                    self.issues.append(Issue(
                        url=page_ref, kind="api", severity="info",
                        message=f"✅ DELETE limpió el registro de prueba: {item_url[:100]} → {status}",
                    ))
                else:
                    self.issues.append(Issue(
                        url=page_ref, kind="api", severity="warning",
                        message=f"⚠️ No se pudo borrar el registro de prueba: {item_url[:100]} → {status}",
                        details="Requiere limpieza manual.",
                    ))
            else:
                unexpected = status in (200, 202, 204)
                sev = "warning" if unexpected else "info"
                note = " ⚠️ aceptó DELETE sobre un ID inexistente" if unexpected else ""
                self.issues.append(Issue(
                    url=page_ref, kind="api", severity=sev,
                    message=f"DELETE {item_url[:100]} → {status}{note}",
                ))
        except Exception:
            pass

    def validate_apis(self):
        if not self.apis_found:
            return

        print(f"\n🔌 Validando {len(self.apis_found)} endpoints API descubiertos...")
        import requests

        seen = set()
        for api in self.apis_found:
            u = api["url"]
            if u in seen:
                continue
            seen.add(u)

            try:
                r = requests.get(u, timeout=10, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        try:
                            data = r.json()
                            keys = list(data.keys())[:5] if isinstance(data, dict) else f"[array:{len(data)}]"
                        except Exception:
                            keys = "(no JSON)"
                        self.issues.append(Issue(
                            url=api["page"], kind="api", severity="warning",
                            message=f"API abierta sin auth: GET {u[:120]}",
                            details=f"Status 200, keys: {keys}",
                        ))
                elif r.status_code in (401, 403):
                    self.issues.append(Issue(
                        url=api["page"], kind="api", severity="info",
                        message=f"API protegida: GET {u[:120]} → {r.status_code}",
                    ))

                cors = r.headers.get("access-control-allow-origin", "")
                if cors == "*":
                    self.issues.append(Issue(
                        url=api["page"], kind="api", severity="warning",
                        message=f"API CORS wildcard: {u[:120]}",
                        details="Access-Control-Allow-Origin: *",
                    ))
            except Exception:
                pass

            try:
                r = requests.options(u, timeout=5)
                methods = r.headers.get("allow", "") or r.headers.get("access-control-allow-methods", "")
                if methods:
                    self.issues.append(Issue(
                        url=api["page"], kind="api", severity="info",
                        message=f"API métodos soportados: {u[:100]}", details=f"Allow: {methods}",
                    ))
            except Exception:
                pass

        if not self.test_crud:
            return

        print("\n" + "⚠️ " * 3)
        print("⚠️  MODO CRUD ACTIVO: se enviarán POST/PUT/DELETE de prueba REALES.")
        print(f"⚠️  Los registros creados se marcan con «{self.CRUD_MARKER}» y se intentan borrar automáticamente.")
        print("⚠️ " * 3 + "\n")

        roots = self._collection_roots()
        print(f"🧪 Probando ciclo CRUD completo (Create→Read→Update→Delete) en {len(roots)} endpoints...")

        for root in roots:
            print(f"   🔄 {root}")
            self._test_crud_lifecycle(root, page_ref=self.base_url)

        pending = [c for c in self._crud_created if not c["deleted"]]
        if pending:
            print(f"\n⚠️ {len(pending)} registro(s) de prueba NO se pudieron limpiar automáticamente:")
            for c in pending:
                print(f"   • {c['url']}/{c['id']}  ← borrar manualmente")
        else:
            print(f"\n✅ Todos los registros de prueba creados ({len(self._crud_created)}) se limpiaron correctamente.")

    # ── Reporte HTML ─────────────────────────────────────────────

    def generate_report(self):
        clean_domain = re.sub(r"[^a-zA-Z0-9.-]", "_", self.domain)
        date_str = datetime.now().strftime("%Y-%m-%d_%H%M")
        rp = self.output / f"{clean_domain}_{date_str}.html"

        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        tp = len(self.results)
        ti = len(self.issues)
        cr = sum(1 for i in self.issues if i.severity == "critical")
        wr = sum(1 for i in self.issues if i.severity == "warning")
        inf = sum(1 for i in self.issues if i.severity == "info")
        je = sum(1 for i in self.issues if i.kind == "js_error")
        bl = sum(1 for i in self.issues if i.kind == "broken_link")
        fe = sum(1 for i in self.issues if i.kind == "form_error")
        he = sum(1 for i in self.issues if i.kind == "http_error")
        nee = sum(1 for i in self.issues if i.kind == "network")
        se = sum(1 for i in self.issues if i.kind == "security")
        ex = sum(1 for i in self.issues if i.kind == "exposure")
        ae = sum(1 for i in self.issues if i.kind == "api")
        ft = sum(r.forms_found for r in self.results)
        ftest = sum(r.forms_tested for r in self.results)
        al = int(sum(r.load_time_ms for r in self.results) / max(tp, 1))
        tr = len(self.all_net)
        fr = sum(1 for n in self.all_net if n.failed or n.status >= 400)
        tc = len(self.all_con)
        ce = sum(1 for c in self.all_con if c.level in ("error", "exception"))

        ij = json.dumps([asdict(i) for i in self.issues], ensure_ascii=False)
        pj = json.dumps([{
            "url": r.url, "status": r.status, "title": r.title, "screenshot": r.screenshot,
            "load_time_ms": r.load_time_ms, "forms_found": r.forms_found, "forms_tested": r.forms_tested,
            "links_found": r.links_found, "issues_count": len(r.issues),
        } for r in self.results], ensure_ascii=False)
        nj = json.dumps([asdict(n) for n in self.all_net], ensure_ascii=False)
        cj = json.dumps([asdict(c) for c in self.all_con], ensure_ascii=False)
        aj = json.dumps(self.apis_found, ensure_ascii=False)

        html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QA Audit — {self.domain} — {now}</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;
--critical:#ef4444;--warning:#f59e0b;--info:#3b82f6;--success:#22c55e;--purple:#a855f7;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,system-ui,sans-serif;padding:20px;}}
.ctr{{max-width:1280px;margin:0 auto;}}
h1{{font-size:1.5rem;margin-bottom:4px;}}.sub{{color:var(--muted);margin-bottom:24px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:24px;}}
.st{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center;}}
.st .n{{font-size:1.8rem;font-weight:700;}}.st .l{{color:var(--muted);font-size:.8rem;}}
.st.cr .n{{color:var(--critical);}}.st.wr .n{{color:var(--warning);}}.st.in .n{{color:var(--info);}}
.st.ok .n{{color:var(--success);}}.st.pu .n{{color:var(--purple);}}
.flt{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;}}
.flt button{{background:var(--card);border:1px solid var(--border);color:var(--text);
padding:5px 12px;border-radius:6px;cursor:pointer;font-size:.82rem;}}
.flt button.act{{background:var(--accent);color:#0f172a;border-color:var(--accent);}}
.ic{{background:var(--card);border:1px solid var(--border);border-radius:8px;
padding:12px;margin-bottom:8px;display:flex;gap:10px;align-items:flex-start;}}
.ic.hid{{display:none;}}.bd{{display:inline-block;padding:2px 7px;border-radius:4px;
font-size:.72rem;font-weight:600;text-transform:uppercase;flex-shrink:0;}}
.bd.critical{{background:var(--critical);color:#fff;}}.bd.warning{{background:var(--warning);color:#000;}}
.bd.info{{background:var(--info);color:#fff;}}.ib{{flex:1;}}
.iu{{color:var(--muted);font-size:.78rem;word-break:break-all;}}
.im{{margin-top:3px;}}.it{{color:var(--muted);font-size:.72rem;}}
.kt{{color:var(--accent);font-size:.72rem;margin-left:6px;}}
.th{{width:110px;height:65px;object-fit:cover;border-radius:4px;cursor:pointer;flex-shrink:0;}}
table.pt{{width:100%;border-collapse:collapse;margin-top:12px;}}
.pt th,.pt td{{padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);font-size:.82rem;}}
.pt th{{color:var(--muted);font-weight:600;}}.pt tr:hover{{background:rgba(56,189,248,.05);}}
.sok{{color:var(--success);}}.ser{{color:var(--critical);}}
.tb{{display:flex;gap:0;margin-bottom:18px;flex-wrap:wrap;}}
.tb button{{background:var(--card);border:1px solid var(--border);color:var(--muted);
padding:9px 16px;cursor:pointer;font-size:.85rem;}}
.tb button:first-child{{border-radius:8px 0 0 8px;}}.tb button:last-child{{border-radius:0 8px 8px 0;}}
.tb button.act{{background:var(--accent);color:#0f172a;border-color:var(--accent);font-weight:600;}}
.tc{{display:none;}}.tc.act{{display:block;}}
.mdl{{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);z-index:999;
justify-content:center;align-items:center;}}.mdl.sh{{display:flex;}}
.mdl img{{max-width:90vw;max-height:90vh;border-radius:8px;}}
.mc{{position:absolute;top:20px;right:30px;color:#fff;font-size:2rem;cursor:pointer;}}
.sr{{background:var(--card);border:1px solid var(--border);color:var(--text);
padding:7px 12px;border-radius:6px;width:300px;margin-bottom:14px;}}
</style></head><body><div class="ctr">
<h1>🔍 Auditoría QA + Seguridad</h1>
<p class="sub">{self.domain} · {now} · {tp} páginas</p>
<div class="grid">
<div class="st cr"><div class="n">{cr}</div><div class="l">Críticos</div></div>
<div class="st wr"><div class="n">{wr}</div><div class="l">Advertencias</div></div>
<div class="st in"><div class="n">{inf}</div><div class="l">Info</div></div>
<div class="st ok"><div class="n">{tp}</div><div class="l">Páginas</div></div>
<div class="st"><div class="n">{al}ms</div><div class="l">Carga prom</div></div>
<div class="st"><div class="n">{tr}</div><div class="l">Requests</div></div>
<div class="st pu"><div class="n">{se + ex}</div><div class="l">Seguridad</div></div>
<div class="st"><div class="n">{len(self.apis_found)}</div><div class="l">APIs</div></div>
</div>
<div class="tb">
<button class="act" onclick="stab('iss')">Issues ({ti})</button>
<button onclick="stab('pgs')">Páginas ({tp})</button>
<button onclick="stab('net')">Network ({tr})</button>
<button onclick="stab('con')">Consola ({tc})</button>
<button onclick="stab('api')">APIs ({len(self.apis_found)})</button>
<button onclick="stab('sum')">Resumen</button>
</div>
<div id="t-iss" class="tc act">
<input class="sr" placeholder="Buscar..." oninput="fi()">
<div class="flt" id="fl-i">
<button class="act" data-f="all" onclick="sf('all',this)">Todos ({ti})</button>
<button data-f="critical" onclick="sf('critical',this)">Críticos ({cr})</button>
<button data-f="warning" onclick="sf('warning',this)">Warnings ({wr})</button>
<button data-f="info" onclick="sf('info',this)">Info ({inf})</button>
<span style="border-left:1px solid var(--border);margin:0 3px"></span>
<button data-f="js_error" onclick="sf('js_error',this)">JS ({je})</button>
<button data-f="broken_link" onclick="sf('broken_link',this)">Links ({bl})</button>
<button data-f="form_error" onclick="sf('form_error',this)">Forms ({fe})</button>
<button data-f="network" onclick="sf('network',this)">Net ({nee})</button>
<button data-f="security" onclick="sf('security',this)">OWASP ({se})</button>
<button data-f="exposure" onclick="sf('exposure',this)">Exposición ({ex})</button>
<button data-f="api" onclick="sf('api',this)">API ({ae})</button>
</div>
<div id="il"></div>
</div>
<div id="t-pgs" class="tc">
<table class="pt"><thead><tr><th>URL</th><th>Status</th><th>Título</th><th>Carga</th><th>Forms</th><th>Issues</th></tr></thead>
<tbody id="pb"></tbody></table>
</div>
<div id="t-net" class="tc">
<input class="sr" id="ns" placeholder="Filtrar URL, status..." oninput="fn()">
<div class="flt" id="fl-n">
<button class="act" onclick="snf('all',this)">Todas ({tr})</button>
<button onclick="snf('fail',this)">Fallidas ({fr})</button>
<button onclick="snf('xhr',this)">XHR/Fetch</button>
<button onclick="snf('doc',this)">Document</button>
</div>
<table class="pt"><thead><tr><th>Método</th><th>URL</th><th>Status</th><th>Tipo</th><th>Tamaño</th><th>ms</th><th>Página</th></tr></thead>
<tbody id="nb"></tbody></table>
</div>
<div id="t-con" class="tc">
<input class="sr" id="cs" placeholder="Filtrar..." oninput="fc()">
<div class="flt" id="fl-c">
<button class="act" onclick="scf('all',this)">Todas ({tc})</button>
<button onclick="scf('err',this)">Errors ({ce})</button>
<button onclick="scf('warn',this)">Warnings</button>
<button onclick="scf('log',this)">Logs</button>
</div>
<div id="cl"></div>
</div>
<div id="t-api" class="tc">
<table class="pt"><thead><tr><th>Método</th><th>URL</th><th>Tipo</th><th>Descubierta en</th></tr></thead>
<tbody id="ab"></tbody></table>
</div>
<div id="t-sum" class="tc">
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-top:8px;">
<h3 style="margin-bottom:12px;">Resumen ejecutivo</h3>
<p><strong>{tp}</strong> páginas auditadas en <strong>{self.domain}</strong>.</p>
<p style="margin-top:8px;"><strong>{ti}</strong> problemas:
<span style="color:var(--critical)">{cr} críticos</span>,
<span style="color:var(--warning)">{wr} advertencias</span>,
<span style="color:var(--info)">{inf} info</span>.</p>
<p style="margin-top:8px;">Desglose: {je} JS, {bl} links, {fe} forms, {he} HTTP, {nee} network, {se} OWASP, {ex} exposición, {ae} API.</p>
<p style="margin-top:8px;">{ft} formularios ({ftest} probados). Carga promedio: {al}ms.</p>
<p style="margin-top:8px;">Red: {tr} requests, {fr} fallidos. Consola: {tc} mensajes, {ce} errores.</p>
<p style="margin-top:8px;">APIs descubiertas: {len(self.apis_found)}.</p>
</div></div>
<div id="mdl" class="mdl" onclick="this.classList.remove('sh')"><span class="mc">&times;</span><img id="mi" src=""></div>
<script>
const I={ij};const P={pj};const N={nj};const C={cj};const A={aj};
let af='all',nf='all',cf='all';
function stab(id){{document.querySelectorAll('.tc').forEach(t=>t.classList.remove('act'));
document.querySelectorAll('.tb button').forEach(b=>b.classList.remove('act'));
document.getElementById('t-'+id).classList.add('act');event.target.classList.add('act');}}
function ri(){{document.getElementById('il').innerHTML=I.map(i=>`
<div class="ic" data-s="${{i.severity}}" data-k="${{i.kind}}">
<span class="bd ${{i.severity}}">${{i.severity}}</span>
<div class="ib"><div class="iu">${{i.url}}<span class="kt">${{i.kind}}</span></div>
<div class="im">${{i.message}}</div>
${{i.details?`<div style="color:var(--muted);font-size:.78rem;margin-top:2px;">${{i.details}}</div>`:''}}
<div class="it">${{i.timestamp}}</div></div>
${{i.screenshot?`<img class="th" src="screenshots/${{i.screenshot}}" onclick="om('screenshots/${{i.screenshot}}')" onerror="this.style.display='none'">`:''}}
</div>`).join('');}}
function sf(f,b){{af=f;document.querySelectorAll('#fl-i button').forEach(x=>x.classList.remove('act'));b.classList.add('act');fi();}}
function fi(){{const q=(document.querySelector('#t-iss .sr')||{{}}).value?.toLowerCase()||'';
document.querySelectorAll('#il .ic').forEach(c=>{{const s=c.dataset.s,k=c.dataset.k,t=c.textContent.toLowerCase();
c.classList.toggle('hid',!((af==='all'||s===af||k===af)&&(!q||t.includes(q))));
}});}}
function rp(){{document.getElementById('pb').innerHTML=P.map(p=>`<tr>
<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
<a href="${{p.url}}" target="_blank" style="color:var(--accent);text-decoration:none;">${{p.url}}</a></td>
<td class="${{p.status<400?'sok':'ser'}}">${{p.status}}</td><td>${{p.title}}</td>
<td>${{p.load_time_ms}}ms</td><td>${{p.forms_found}}</td><td>${{p.issues_count||'—'}}</td></tr>`).join('');}}
function fsz(b){{if(!b)return'—';if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(0)+'K';return(b/1048576).toFixed(1)+'M';}}
function rn(){{document.getElementById('nb').innerHTML=N.map(n=>`<tr class="nr" data-t="${{n.resource_type}}"
data-f="${{n.failed||n.status>=400}}" style="${{(n.failed||n.status>=400)?'color:var(--critical)':''}}">
<td>${{n.method}}</td><td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
title="${{n.url}}">${{n.url}}</td>
<td class="${{n.status>=400||n.failed?'ser':'sok'}}">${{n.failed?'❌'+n.error_text.slice(0,25):n.status}}</td>
<td>${{n.resource_type}}</td><td>${{fsz(n.size_bytes)}}</td><td>${{n.duration_ms||'—'}}</td>
<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)">${{n.page_url}}</td></tr>`).join('');}}
function snf(f,b){{nf=f;document.querySelectorAll('#fl-n button').forEach(x=>x.classList.remove('act'));b.classList.add('act');fn();}}
function fn(){{const q=(document.getElementById('ns')||{{}}).value?.toLowerCase()||'';
document.querySelectorAll('.nr').forEach(r=>{{const t=r.dataset.t,f=r.dataset.f==='true',tx=r.textContent.toLowerCase();
let s=true;if(nf==='fail')s=f;else if(nf==='xhr')s=t==='xhr'||t==='fetch';else if(nf==='doc')s=t==='document';
if(q&&!tx.includes(q))s=false;r.style.display=s?'':'none';}});}}
const lc={{'error':'var(--critical)','exception':'var(--critical)','warning':'var(--warning)',
'log':'var(--text)','info':'var(--info)','debug':'var(--muted)'}};
function rc(){{document.getElementById('cl').innerHTML=C.map(c=>`<div class="ic cr" data-l="${{c.level}}"
style="border-left:3px solid ${{lc[c.level]||'var(--border)'}}">
<span class="bd" style="background:${{lc[c.level]||'var(--muted)'}};color:#fff;min-width:65px;text-align:center">${{c.level}}</span>
<div class="ib"><div style="font-family:monospace;font-size:.82rem;white-space:pre-wrap;word-break:break-all;">${{c.text}}</div>
<div class="iu">${{c.page_url}} · ${{c.timestamp}}</div></div></div>`).join('');}}
function scf(f,b){{cf=f;document.querySelectorAll('#fl-c button').forEach(x=>x.classList.remove('act'));b.classList.add('act');fc();}}
function fc(){{const q=(document.getElementById('cs')||{{}}).value?.toLowerCase()||'';
document.querySelectorAll('.cr').forEach(r=>{{const l=r.dataset.l,t=r.textContent.toLowerCase();
let s=true;if(cf==='err')s=l==='error'||l==='exception';else if(cf==='warn')s=l==='warning';
else if(cf==='log')s=l==='log'||l==='info'||l==='debug';
if(q&&!t.includes(q))s=false;r.style.display=s?'':'none';}});}}
function ra(){{document.getElementById('ab').innerHTML=A.map(a=>`<tr>
<td>${{a.method}}</td><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
title="${{a.url}}">${{a.url}}</td><td>${{a.type}}</td>
<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)">${{a.page}}</td></tr>`).join('');}}
function om(s){{document.getElementById('mi').src=s;document.getElementById('mdl').classList.add('sh');}}
ri();rp();rn();rc();ra();
</script></div></body></html>"""

        rp.write_text(html, encoding="utf-8")
        return rp

    # ── Fuente para diagrama de arquitectura (archify) ──────────

    def generate_architecture_source(self):
        """Vuelca el crawl (páginas, APIs descubiertas, hosts externos) como
        Mermaid flowchart. No dibuja el HTML final: ese lo genera el skill
        `archify` (Claude) leyendo este archivo, para producir
        `architecture-diagram.html` junto al reporte."""
        clean_domain = re.sub(r"[^a-zA-Z0-9.-]", "_", self.domain)
        mp = self.output / f"{clean_domain}_architecture-source.mmd"

        def nid(s):
            return re.sub(r"[^a-zA-Z0-9_]", "_", s)[:60]

        pages = sorted({r.url for r in self.results})
        hosts = {}
        for n in self.all_net:
            try:
                host = re.match(r"https?://([^/]+)", n.url).group(1)
            except AttributeError:
                continue
            if host and host != self.domain:
                hosts.setdefault(host, 0)
                hosts[host] += 1
        apis = sorted({(a.get("method", "GET"), a.get("url", "")) for a in self.apis_found})

        lines = ["flowchart LR", f'  subgraph SITE["{self.domain}"]']
        for p in pages[:60]:
            path = p.replace(self.base_url, "") or "/"
            lines.append(f'    {nid(p)}["{path}"]')
        lines.append("  end")

        if apis:
            lines.append('  subgraph APIS["APIs descubiertas"]')
            for method, url in list(apis)[:60]:
                lines.append(f'    {nid(method + url)}["{method} {url}"]')
            lines.append("  end")
            lines.append("  SITE --> APIS")

        if hosts:
            lines.append('  subgraph EXT["Hosts externos"]')
            for h, count in sorted(hosts.items(), key=lambda x: -x[1])[:30]:
                lines.append(f'    {nid(h)}["{h} ({count} req)"]')
            lines.append("  end")
            lines.append("  SITE --> EXT")

        mp.write_text("\n".join(lines), encoding="utf-8")
        return mp


# ── Config desde .env-web ────────────────────────────────────────

def load_env_web():
    """Lee .env-web del directorio actual. Formato KEY=VALUE por línea.
    Si no existe, crea una plantilla automáticamente."""
    cfg = {}
    candidates = [Path(".env-web"), Path(__file__).resolve().parent / ".env-web"]

    env_path = None
    for p in candidates:
        if p.exists():
            env_path = p
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
            break

    if not env_path:
        env_path = Path(__file__).resolve().parent / ".env-web"
        template = """# Configuración Web Audit QA
AUDIT_URL=
AUDIT_OUTPUT=./audit_output
AUDIT_MAX_PAGES=0
AUDIT_HEADED=true
AUDIT_LOGIN_URL=
AUDIT_EMAIL=
AUDIT_PASSWORD=
AUDIT_SSO=false
AUDIT_ALLOW_DOMAINS=
# true = prueba POST/PUT/DELETE reales (crea+borra registros propios marcados
# como QA-TEST-AUDIT). Solo usar en staging, NUNCA en producción.
AUDIT_TEST_CRUD=false
"""
        env_path.write_text(template, encoding="utf-8")
        print(f"✅ Creado: {env_path}")
        print("   Edita los valores y vuelve a ejecutar, o pasa todo por CLI.\n")

    return cfg


# ── Main ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Web Audit QA v4 — pasa la URL o usa .env-web")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--headed", action="store_true", default=None)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--max-pages", type=int, default=None, help="0 = sin límite")
    ap.add_argument("--login-url", default=None)
    ap.add_argument("--email", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--sso", action="store_true", default=None)
    ap.add_argument("--no-sso", action="store_true")
    ap.add_argument("--allow-domain", action="append", default=None)
    ap.add_argument("--test-crud", action="store_true", default=None,
                     help="Prueba POST/PUT/DELETE reales (crea+borra registros propios). Solo staging.")
    ap.add_argument("--no-test-crud", action="store_true")
    ap.add_argument("url", nargs="?", default=None, help="URL base (o AUDIT_URL en .env-web)")
    args = ap.parse_args()

    env = load_env_web()

    url = args.url or env.get("AUDIT_URL", "")
    output = args.output or env.get("AUDIT_OUTPUT", "./audit_output")
    headed = True if args.headed else (False if args.headless else env.get("AUDIT_HEADED", "true").lower() in ("true", "1", "yes"))
    max_pages = args.max_pages if args.max_pages is not None else int(env.get("AUDIT_MAX_PAGES", "0"))
    login_url = args.login_url if args.login_url is not None else env.get("AUDIT_LOGIN_URL", "")
    email = args.email if args.email is not None else env.get("AUDIT_EMAIL", "")
    password = args.password if args.password is not None else env.get("AUDIT_PASSWORD", "")
    sso = True if args.sso else (False if args.no_sso else env.get("AUDIT_SSO", "false").lower() in ("true", "1", "yes"))
    extra_dom = args.allow_domain or [d.strip() for d in env.get("AUDIT_ALLOW_DOMAINS", "").split(",") if d.strip()]
    test_crud = True if args.test_crud else (False if args.no_test_crud else env.get("AUDIT_TEST_CRUD", "false").lower() in ("true", "1", "yes"))

    if not url:
        print("❌ Falta URL. Pásala como argumento o pon AUDIT_URL en .env-web")
        sys.exit(1)

    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)

    print("=" * 50)
    print("  WEB AUDIT QA v4")
    print("  Funcional + OWASP + API + SSO + Pausa")
    print("=" * 50)
    print(f"🌐 {url}")
    print(f"📁 {out}")
    print(f"📄 Máx: {max_pages if max_pages else 'sin límite'} páginas")
    if sso:
        print("🔐 Modo SSO manual")
    if login_url:
        print(f"🔑 Login: {login_url}")
    if extra_dom:
        print(f"🌐 Dominios extra: {', '.join(extra_dom)}")
    if test_crud:
        print("🧪 CRUD activo: se probarán POST/PUT/DELETE reales")
    print()

    a = WebAuditor(url, out, headed, max_pages, login_url, email, password, sso, extra_dom, test_crud)
    a.start()

    try:
        if login_url:
            if not a.do_login():
                print("⚠️ Sin auth...\n")
        a.crawl()
        a.validate_apis()
        print(f"\n{'=' * 50}\n  GENERANDO REPORTE\n{'=' * 50}")
        report = a.generate_report()
        arch_src = a.generate_architecture_source()
        ti = len(a.issues)
        cr = sum(1 for i in a.issues if i.severity == "critical")
        print(f"\n📊 {len(a.results)} páginas, {ti} issues ({cr} críticos)")
        print(f"🔌 {len(a.apis_found)} APIs descubiertas")
        print(f"📄 {report}")
        print(f'   open "{report}"\n')
        print(f"🗺️  Fuente de arquitectura: {arch_src}")
        print(f'   Generar diagrama: skill "archify" → leer "{arch_src}" → escribir '
              f'"{arch_src.parent}/architecture-diagram.html"\n')
    except KeyboardInterrupt:
        try:
            print("\n⏸️ Parcial...")
            report = a.generate_report()
            arch_src = a.generate_architecture_source()
            print(f"📄 {report}")
            print(f"🗺️  {arch_src}\n")
        except Exception:
            pass
    finally:
        try:
            a.stop()
        except KeyboardInterrupt:
            pass
        except Exception:
            pass


if __name__ == "__main__":
    main()
