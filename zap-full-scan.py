#!/usr/bin/env python3
# =============================================================================
#  ZAP Full Scan Automation — github.com/iric-Sauldc
#  Versión : 3.0 (2026) — Reportes 100% vía HTTP, sin paths Docker
#  Req.    : Python 3.10+, Docker, ZAP 2.17+
#
#  Uso rápido:
#    python3 zap_fullscan.py --target https://staging.miapp.com
#
#  Uso completo:
#    python3 zap_fullscan.py \
#      --target   https://staging.miapp.com \
#      --login    https://staging.miapp.com/login \
#      --user     admin@miapp.com \
#      --password "password123" \
#      --openapi  ./docs/openapi.yaml \
#      --output   ./reports \
#      --timeout  120
# =============================================================================

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER = """
███████╗ █████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
╚══███╔╝██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███╔╝ ███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
 ███╔╝  ██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
███████╗██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
   Full DAST Automation v3.0 // github.com/iric-Sauldc
"""

ZAP_IMAGE    = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_PORT     = 8090
ZAP_API_KEY  = "zap-fullscan-key-2026"
ZAP_BASE     = f"http://localhost:{ZAP_PORT}"
ZAP_TIMEOUT  = 30

REQUIRED_ADDONS = [
    "ascanrules", "pscanrules",
    "ascanrulesAlpha", "pscanrulesAlpha",
    "openapi", "graphql", "soap",
    "authhelper", "reports",
    "technology-detection",
    "advanced-sqlinjection-scanner",
]

# ── Helpers de log ────────────────────────────────────────────────────────────
def _ts(): return datetime.now().strftime("%H:%M:%S")
def ok(m):   console.print(f"[dim]{_ts()}[/dim] [bold green]✔[/bold green] {m}")
def err(m):  console.print(f"[dim]{_ts()}[/dim] [bold red]✘[/bold red]  {m}", style="red")
def warn(m): console.print(f"[dim]{_ts()}[/dim] [bold yellow]⚠[/bold yellow]  {m}", style="yellow")
def info(m): console.print(f"[dim]{_ts()}[/dim] [bold cyan]ℹ[/bold cyan]  {m}")
def step(n, t, m): console.print(f"\n[bold magenta]── FASE {n}/{t}: {m} ──[/bold magenta]")
def dbg(m):  console.print(f"[dim]{_ts()} DEBUG: {m}[/dim]")


# =============================================================================
class ZAPScanner:

    def __init__(self, args):
        self.target      = args.target.rstrip("/")
        self.login_url   = args.login or f"{self.target}/login"
        self.username    = args.user
        self.password    = args.password
        self.openapi     = args.openapi
        self.output_dir  = Path(args.output).resolve()
        self.report_dir  = self.output_dir / "reports"
        self.timeout_min = args.timeout
        self.no_docker   = args.no_docker
        self.threads     = args.threads
        self.keep        = args.keep          # ← NO borrar contenedor al final
        self.container_id: Optional[str] = None
        self.ctx_id      = "1"
        self.user_id     = None
        self.alerts: list = []
        self.by_risk: dict = {}
        self.total_urls  = 0
        self.scan_start  = datetime.now()
        # Sesión HTTP para todas las llamadas a ZAP API
        self.s = requests.Session()
        self.s.headers["X-ZAP-API-Key"] = ZAP_API_KEY

    # =========================================================================
    # API helpers
    # =========================================================================
    def _get(self, path: str, params: dict = None) -> dict:
        p = {"apikey": ZAP_API_KEY}
        if params:
            p.update(params)
        r = self.s.get(f"{ZAP_BASE}/JSON/{path}/", params=p, timeout=ZAP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict = None) -> dict:
        d = {"apikey": ZAP_API_KEY}
        if data:
            d.update(data)
        r = self.s.post(f"{ZAP_BASE}/JSON/{path}/", data=d, timeout=ZAP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _other_get(self, path: str, params: dict = None) -> requests.Response:
        """Llama a /OTHER/ endpoints que devuelven contenido binario/texto."""
        p = {"apikey": ZAP_API_KEY}
        if params:
            p.update(params)
        r = self.s.get(f"{ZAP_BASE}/OTHER/{path}/", params=p, timeout=120, stream=True)
        r.raise_for_status()
        return r

    def _wait_scan(self, scan_id: str, status_path: str, label: str, max_min: int):
        with Progress(SpinnerColumn(),
                      TextColumn(f"[cyan]{label}[/cyan]"),
                      BarColumn(bar_width=40),
                      TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("", total=100)
            deadline = time.time() + max_min * 60
            while time.time() < deadline:
                try:
                    pct = int(self._get(status_path, {"scanId": scan_id}).get("status", 0))
                    prog.update(task, completed=pct)
                    if pct >= 100:
                        break
                except Exception:
                    pass
                time.sleep(3)
            prog.update(task, completed=100)

    # =========================================================================
    # FASE 0 — Preparar directorios
    # =========================================================================
    def prepare(self):
        step(0, 8, "Preparación del entorno")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.output_dir), 0o777)
            os.chmod(str(self.report_dir), 0o777)
        except Exception:
            pass
        ok(f"Directorio de reportes: {self.report_dir}")

        if not self.no_docker and not shutil.which("docker"):
            err("Docker no encontrado.")
            sys.exit(1)
        ok("Docker disponible")

        try:
            r = requests.get(self.target, timeout=10, verify=False)
            ok(f"Target accesible — HTTP {r.status_code}")
        except Exception as e:
            warn(f"Target no responde: {e}")

    # =========================================================================
    # FASE 1 — Levantar ZAP en Docker
    # =========================================================================
    def start_zap(self):
        step(1, 8, "Iniciando ZAP")
        if self.no_docker:
            info("Modo --no-docker activo")
            self._wait_zap_ready()
            return

        subprocess.run(["docker", "rm", "-f", "zap-fullscan"], capture_output=True)

        work_dir = str(self.output_dir)
        cmd = [
            "docker", "run", "-d",
            "--name", "zap-fullscan",
            "--network", "host",
            "-u", "zap",
            "-v", f"{work_dir}:/zap/wrk:rw",
            ZAP_IMAGE,
            "zap.sh",
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(ZAP_PORT),
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "connection.timeoutInSecs=120",
            "-config", "scanner.maxScanDurationInMins=0",
            "-config", "api.disablekey=false",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            err(f"Docker error: {result.stderr.strip()}")
            sys.exit(1)
        self.container_id = result.stdout.strip()[:12]
        ok(f"Contenedor iniciado: {self.container_id}")
        self._wait_zap_ready()

    def _wait_zap_ready(self, max_wait: int = 180):
        info("Esperando ZAP ...")
        deadline = time.time() + max_wait
        with Progress(SpinnerColumn(), TextColumn("[cyan]Iniciando ZAP...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            while time.time() < deadline:
                try:
                    ver = self._get("core/view/version").get("version", "?")
                    ok(f"ZAP listo — v{ver}")
                    return
                except Exception:
                    time.sleep(3)
        err("ZAP no respondió. Abortando.")
        sys.exit(1)

    # =========================================================================
    # FASE 2 — Instalar add-ons
    # =========================================================================
    def install_addons(self):
        step(2, 8, "Instalando / actualizando add-ons")
        try:
            self._post("autoupdate/action/updateAllAddons")
            ok("Add-ons actualizados")
        except Exception:
            warn("No se pudo actualizar add-ons")

        try:
            installed = {
                a.get("id")
                for a in self._get("autoupdate/view/installedAddons").get("installedAddons", [])
            }
        except Exception:
            installed = set()

        for addon in REQUIRED_ADDONS:
            if addon not in installed:
                try:
                    self._post("autoupdate/action/installAddon", {"id": addon})
                    ok(f"  Instalado: {addon}")
                    time.sleep(1)
                except Exception as e:
                    warn(f"  No se pudo instalar {addon}: {e}")
            else:
                info(f"  Ya instalado: {addon}")
        time.sleep(4)

    # =========================================================================
    # FASE 3 — Configurar contexto y autenticación
    # =========================================================================
    def configure_context(self):
        step(3, 8, "Configurando contexto y autenticación")
        ctx = self._post("context/action/newContext", {"contextName": "FullScan"})
        self.ctx_id = ctx.get("contextId", "1")

        self._post("context/action/includeInContext", {
            "contextName": "FullScan",
            "regex": f"{re.escape(self.target)}.*"
        })
        for pat in [".*logout.*", ".*signout.*", ".*delete.*", ".*destroy.*",
                    r".*\.png$", r".*\.jpg$", r".*\.css$", r".*\.woff.*"]:
            try:
                self._post("context/action/excludeFromContext",
                           {"contextName": "FullScan", "regex": pat})
            except Exception:
                pass
        ok(f"Contexto creado (ID: {self.ctx_id})")

        if self.username and self.password:
            self._setup_auth()
        else:
            warn("Sin credenciales — escaneo no autenticado")

    def _setup_auth(self):
        info("Configurando autenticación browser-based ...")
        try:
            self._post("authentication/action/setAuthenticationMethod", {
                "contextId": self.ctx_id,
                "authMethodName": "browserBasedAuthentication",
                "authMethodConfigParams":
                    f"loginPageUrl={self.login_url}&loginPageWait=5&browserId=firefox-headless"
            })
            self._post("authentication/action/setLoggedInIndicator", {
                "contextId": self.ctx_id,
                "loggedInIndicatorRegex": r"\Qdashboard\E|\Qprofile\E|\Qwelcome\E"
            })
            self._post("authentication/action/setLoggedOutIndicator", {
                "contextId": self.ctx_id,
                "loggedOutIndicatorRegex": r"\Qlogin\E|\Qsign in\E|\Qunauthorized\E"
            })
            self._post("sessionManagement/action/setSessionManagementMethod", {
                "contextId": self.ctx_id,
                "methodName": "cookieBasedSessionManagement"
            })
            user = self._post("users/action/newUser",
                              {"contextId": self.ctx_id, "name": "scan-user"})
            self.user_id = user.get("userId", "0")
            self._post("users/action/setAuthenticationCredentials", {
                "contextId": self.ctx_id,
                "userId": self.user_id,
                "authCredentialsConfigParams":
                    f"username={self.username}&password={self.password}"
            })
            self._post("users/action/setUserEnabled",
                       {"contextId": self.ctx_id, "userId": self.user_id, "enabled": "true"})
            self._post("forcedUser/action/setForcedUser",
                       {"contextId": self.ctx_id, "userId": self.user_id})
            self._post("forcedUser/action/setForcedUserModeEnabled", {"boolean": "true"})
            ok(f"Autenticación configurada: {self.username}")
        except Exception as e:
            warn(f"Auth no configurada: {e}")
            self.user_id = None

    # =========================================================================
    # FASE 4 — Importar API spec
    # =========================================================================
    def import_api_spec(self):
        step(4, 8, "Importando definición de API")
        if self.openapi and Path(self.openapi).exists():
            try:
                self._post("openapi/action/importFile",
                           {"file": self.openapi, "target": self.target,
                            "contextId": self.ctx_id})
                ok(f"OpenAPI importado: {self.openapi}")
                return
            except Exception as e:
                warn(f"No se pudo importar archivo OpenAPI: {e}")

        for path in ["/openapi.json", "/api-docs", "/swagger.json", "/v1/openapi.json"]:
            url = f"{self.target}{path}"
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200 and "openapi" in r.text.lower():
                    self._post("openapi/action/importUrl",
                               {"url": url, "contextId": self.ctx_id})
                    ok(f"OpenAPI auto-descubierto: {url}")
                    return
            except Exception:
                continue
        info("No se encontró OpenAPI spec — crawl único")

    # =========================================================================
    # FASE 5 — Spider + AJAX Spider + Passive Scan
    # =========================================================================
    def run_spider(self):
        step(5, 8, "Descubrimiento de URLs")

        info("Spider tradicional ...")
        sp = self._post("spider/action/scan", {
            "url": self.target, "contextName": "FullScan",
            "recurse": "true", "maxChildren": "0",
        })
        self._wait_scan(sp.get("scan", "0"), "spider/view/status",
                        "Spider", max_min=25)
        sp_urls = len(self._get("spider/view/results",
                                {"scanId": sp.get("scan", "0")}).get("results", []))
        ok(f"Spider: {sp_urls} URLs")

        info("AJAX Spider (headless) ...")
        self._post("ajaxSpider/action/scan", {
            "url": self.target, "contextName": "FullScan", "subtreeOnly": "false",
        })
        with Progress(SpinnerColumn(), TextColumn("[cyan]AJAX Spider...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            deadline = time.time() + 25 * 60
            while time.time() < deadline:
                try:
                    if self._get("ajaxSpider/view/status").get("status") == "stopped":
                        break
                except Exception:
                    pass
                time.sleep(5)
        ajax_urls = len(self._get("ajaxSpider/view/results").get("results", []))
        ok(f"AJAX Spider: {ajax_urls} URLs adicionales")
        self.total_urls = sp_urls + ajax_urls

        info("Escaneo pasivo ...")
        self._post("pscan/action/enableAllScanners")
        self._post("pscan/action/setMaxAlertsPerRule", {"maxAlerts": "10"})
        deadline = time.time() + 10 * 60
        with Progress(SpinnerColumn(), TextColumn("[cyan]Pasivo...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            while time.time() < deadline:
                try:
                    if int(self._get("pscan/view/recordsToScan")
                           .get("recordsToScan", 0)) == 0:
                        break
                except Exception:
                    pass
                time.sleep(3)
        ok("Escaneo pasivo completado")

    # =========================================================================
    # FASE 6 — Escaneo activo
    # =========================================================================
    def run_active_scan(self):
        step(6, 8, "Escaneo activo — OWASP Top 10 + 2025")

        # Crear política de máxima cobertura
        try:
            self._post("ascan/action/addScanPolicy", {
                "scanPolicyName": "FullPolicy",
                "alertThreshold": "LOW",
                "attackStrength": "HIGH",
            })
        except Exception:
            try:
                self._post("ascan/action/updateScanPolicy", {
                    "scanPolicyName": "FullPolicy",
                    "alertThreshold": "LOW",
                    "attackStrength": "HIGH",
                })
            except Exception:
                pass

        self._post("ascan/action/enableAllScanners", {"policyName": "FullPolicy"})

        # Fuerza INSANE en reglas críticas
        for rid in ["40018", "40012", "40014", "90020", "40046", "90023", "90035", "6"]:
            try:
                self._post("ascan/action/setScannerAttackStrength",
                           {"id": rid, "strength": "INSANE", "policyName": "FullPolicy"})
                self._post("ascan/action/setScannerAlertThreshold",
                           {"id": rid, "threshold": "LOW", "policyName": "FullPolicy"})
            except Exception:
                pass

        params = {
            "url": self.target,
            "contextId": self.ctx_id,
            "recurse": "true",
            "scanPolicyName": "FullPolicy",
        }
        if self.user_id:
            params["userId"] = self.user_id

        scan = self._post("ascan/action/scan", params)
        scan_id = scan.get("scan", "0")
        self._wait_scan(scan_id, "ascan/view/status",
                        "Escaneo activo", max_min=self.timeout_min)
        ok(f"Escaneo activo completado (ID: {scan_id})")

    # =========================================================================
    # FASE 7 — Reportes (100% vía HTTP, sin paths Docker)
    # =========================================================================
    def collect_and_report(self):
        step(7, 8, "Generando reportes")

        # ── Recopilar alertas ─────────────────────────────────────────────────
        alerts_raw = self._get("alert/view/alerts", {
            "baseurl": self.target, "start": "0", "count": "99999",
        })
        self.alerts = alerts_raw.get("alerts", [])
        ok(f"Alertas totales: {len(self.alerts)}")

        self.by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for a in self.alerts:
            self.by_risk.setdefault(a.get("risk", "Informational"), []).append(a)

        info("Escribiendo reportes ...")
        generated = {}

        # ── 1) JSON — escrito directamente por Python ─────────────────────────
        json_path = self.report_dir / "zap-alerts.json"
        payload = {
            "scan_info": {
                "target":     self.target,
                "start_time": self.scan_start.isoformat(),
                "end_time":   datetime.now().isoformat(),
                "total_urls": self.total_urls,
                "author":     "github.com/iric-Sauldc",
            },
            "summary": {
                "total":  len(self.alerts),
                "high":   len(self.by_risk["High"]),
                "medium": len(self.by_risk["Medium"]),
                "low":    len(self.by_risk["Low"]),
                "info":   len(self.by_risk["Informational"]),
            },
            "alerts": self.alerts,
        }
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        generated["JSON"] = json_path

        # ── 2) HTML — /OTHER/core/other/htmlreport/ devuelve HTML en el body ──
        #    Es el endpoint más estable de ZAP, existe desde v2.4
        html_path = self.report_dir / "zap-report.html"
        try:
            resp = self._other_get("core/other/htmlreport")
            html_path.write_bytes(resp.content)
            if html_path.stat().st_size > 200:
                generated["HTML"] = html_path
            else:
                warn("  HTML vacío, intentando con add-on reports ...")
                raise ValueError("vacío")
        except Exception:
            # Fallback: add-on reports → docker cp
            html_path = self._addon_report_via_cp(
                "traditional-html-plus", "zap-report-html", ".html"
            )
            if html_path:
                generated["HTML"] = html_path

        # ── 3) XML — /OTHER/core/other/xmlreport/ ─────────────────────────────
        xml_path = self.report_dir / "zap-report.xml"
        try:
            resp = self._other_get("core/other/xmlreport")
            xml_path.write_bytes(resp.content)
            if xml_path.stat().st_size > 200:
                generated["XML"] = xml_path
            else:
                raise ValueError("vacío")
        except Exception:
            xml_path = self._addon_report_via_cp(
                "traditional-xml", "zap-report-xml", ".xml"
            )
            if xml_path:
                generated["XML"] = xml_path

        # ── 4) SARIF — solo disponible vía add-on reports + docker cp ─────────
        sarif_path = self._addon_report_via_cp(
            "sarif-json", "zap-report-sarif", ".sarif"
        )
        if sarif_path:
            generated["SARIF"] = sarif_path

        # ── 5) Markdown — escrito por Python directamente ─────────────────────
        md_path = self._write_markdown()
        generated["Markdown"] = md_path

        # ── Tabla de resultados ───────────────────────────────────────────────
        console.print()
        t = Table(title="📁 Reportes generados", box=box.ROUNDED,
                  header_style="bold cyan")
        t.add_column("Formato", style="bold")
        t.add_column("Archivo")
        t.add_column("Tamaño", justify="right")
        t.add_column("Estado", justify="center")

        all_formats = ["JSON", "HTML", "XML", "SARIF", "Markdown"]
        for fmt in all_formats:
            if fmt in generated and generated[fmt].exists():
                size = generated[fmt].stat().st_size
                t.add_row(fmt, generated[fmt].name,
                          f"{max(size // 1024, 1)} KB",
                          "[bold green]✔ OK[/bold green]")
            else:
                t.add_row(fmt, "—", "—", "[red]✘ No generado[/red]")
        console.print(t)

    def _addon_report_via_cp(self, template: str, basename: str, ext: str) -> Optional[Path]:
        """
        Genera reporte con el add-on 'reports', obtiene la ruta interna
        que devuelve ZAP y la copia al host con 'docker cp'.
        """
        if self.no_docker:
            return None
        try:
            # ZAP escribe en /tmp dentro del contenedor (evita problemas de permisos)
            result = self._post("reports/action/generate", {
                "title":       f"ZAP {template}",
                "template":    template,
                "reportDir":   "/tmp",
                "reportFile":  basename,
                "description": f"DAST — {self.target}",
                "contexts":    "FullScan",
            })
            # ZAP devuelve la ruta absoluta del archivo generado
            internal = result.get("generate", "")
            dbg(f"  Ruta interna ZAP ({template}): '{internal}'")
            if not internal:
                warn(f"  ZAP no devolvió ruta para {template}")
                return None

            dest = self.report_dir / f"{basename}{ext}"
            cp = subprocess.run(
                ["docker", "cp", f"zap-fullscan:{internal}", str(dest)],
                capture_output=True, text=True
            )
            if cp.returncode != 0:
                warn(f"  docker cp falló ({template}): {cp.stderr.strip()}")
                return None

            if dest.exists() and dest.stat().st_size > 100:
                return dest
            warn(f"  Archivo copiado pero vacío: {dest.name}")
            return None
        except Exception as e:
            warn(f"  Error add-on {template}: {e}")
            return None

    def _write_markdown(self) -> Path:
        md = self.report_dir / "zap-report.md"
        elapsed = str(datetime.now() - self.scan_start).split(".")[0]
        lines = [
            "# 🔒 ZAP Security Report",
            "",
            f"| Campo | Valor |",
            f"|-------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Fecha** | {self.scan_start.strftime('%Y-%m-%d %H:%M')} |",
            f"| **Duración** | {elapsed} |",
            f"| **URLs** | {self.total_urls} |",
            f"| **Autor** | [iric-Sauldc](https://github.com/iric-Sauldc) |",
            "",
            "## Resumen",
            "",
            "| Severidad | # |",
            "|-----------|---|",
            f"| 🔴 Alta | {len(self.by_risk['High'])} |",
            f"| 🟡 Media | {len(self.by_risk['Medium'])} |",
            f"| 🔵 Baja | {len(self.by_risk['Low'])} |",
            f"| ⚪ Info | {len(self.by_risk['Informational'])} |",
            f"| **Total** | **{len(self.alerts)}** |",
            "",
        ]
        for risk, icon in [("High","🔴"),("Medium","🟡"),("Low","🔵"),("Informational","⚪")]:
            items = self.by_risk.get(risk, [])
            if not items:
                continue
            lines.append(f"## {icon} {risk}\n")
            seen: dict = {}
            for a in items:
                name = a.get("name", "Unknown")
                if name not in seen:
                    seen[name] = {"count": 0, "urls": [], "a": a}
                seen[name]["count"] += 1
                u = a.get("url", "")
                if u and u not in seen[name]["urls"]:
                    seen[name]["urls"].append(u)
            for name, d in seen.items():
                a = d["a"]
                lines += [
                    f"### {name}",
                    f"- **CWE:** {a.get('cweid','N/A')}  "
                    f"**Confianza:** {a.get('confidence','N/A')}  "
                    f"**Instancias:** {d['count']}",
                    f"- **Descripción:** {a.get('description','')[:300]}",
                    f"- **Solución:** {a.get('solution','')[:300]}",
                ]
                for u in d["urls"][:5]:
                    lines.append(f"  - `{u}`")
                lines.append("")
        md.write_text("\n".join(lines), encoding="utf-8")
        return md

    # =========================================================================
    # FASE 8 — Resumen en terminal
    # =========================================================================
    def print_summary(self) -> int:
        step(8, 8, "Resumen final")
        elapsed = str(datetime.now() - self.scan_start).split(".")[0]

        t = Table(title="🔍 Resultados", box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Severidad", style="bold", width=14)
        t.add_column("Cantidad", justify="right", width=9)
        t.add_column("Ejemplos", width=55)

        for label, risk, color in [
            ("🔴 Alta",  "High",          "red"),
            ("🟡 Media", "Medium",        "yellow"),
            ("🔵 Baja",  "Low",           "cyan"),
            ("⚪ Info",  "Informational", "dim"),
        ]:
            items = self.by_risk.get(risk, [])
            names = list({a.get("name","") for a in items})[:3]
            t.add_row(Text(label, style=color),
                      Text(str(len(items)), style=f"bold {color}"),
                      ", ".join(names) + ("..." if len(names)==3 else ""))
        t.add_section()
        t.add_row("[bold]TOTAL[/bold]", f"[bold]{len(self.alerts)}[/bold]",
                  f"URLs escaneadas: {self.total_urls}")
        console.print(); console.print(t)

        high = len(self.by_risk.get("High", []))
        color, icon, msg = (
            ("green", "✅", "Sin vulnerabilidades críticas") if high == 0 else
            ("yellow", "⚠️ ", f"{high} vulnerabilidades ALTAS — revisar") if high <= 3 else
            ("red", "🚨", f"{high} vulnerabilidades ALTAS — acción inmediata")
        )
        keep_note = "\n[dim]El contenedor ZAP sigue corriendo (--keep activo)[/dim]" if self.keep else ""
        console.print(Panel(
            f"{icon}  {msg}\n"
            f"[dim]Duración: {elapsed}  |  Reportes: {self.report_dir}[/dim]{keep_note}",
            title="[bold]Estado de Seguridad[/bold]",
            border_style=color, padding=(1, 4),
        ))
        return 1 if high > 0 else 0

    # =========================================================================
    # Limpieza — respeta --keep
    # =========================================================================
    def cleanup(self):
        if self.container_id and not self.no_docker:
            if self.keep:
                console.print()
                info(f"Contenedor ZAP mantenido: [bold]zap-fullscan[/bold]")
                info(f"  Para detenerlo: [bold cyan]docker rm -f zap-fullscan[/bold cyan]")
                info(f"  Para acceder:   [bold cyan]docker exec -it zap-fullscan bash[/bold cyan]")
            else:
                info("Deteniendo contenedor ZAP ...")
                subprocess.run(["docker", "rm", "-f", "zap-fullscan"], capture_output=True)
                ok("Contenedor eliminado")

    # =========================================================================
    # Orquestador
    # =========================================================================
    def run(self) -> int:
        console.print(f"[bold green]{BANNER}[/bold green]")
        console.print(Panel(
            f"[bold]Target:[/bold]  {self.target}\n"
            f"[bold]Login:[/bold]   {self.login_url}\n"
            f"[bold]User:[/bold]    {self.username or 'No autenticado'}\n"
            f"[bold]Output:[/bold]  {self.report_dir}\n"
            f"[bold]Timeout:[/bold] {self.timeout_min} min  "
            f"[bold]Keep:[/bold] {'Sí' if self.keep else 'No'}",
            title="⚙️  Configuración",
            border_style="cyan",
        ))
        exit_code = 0
        try:
            self.prepare()
            self.start_zap()
            self.install_addons()
            self.configure_context()
            self.import_api_spec()
            self.run_spider()
            self.run_active_scan()
            self.collect_and_report()
            exit_code = self.print_summary()
        except KeyboardInterrupt:
            warn("\nInterrumpido por el usuario")
            exit_code = 130
        except Exception as e:
            err(f"Error fatal: {e}")
            console.print_exception()
            exit_code = 1
        finally:
            self.cleanup()
        return exit_code


# =============================================================================
# CLI
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="ZAP Full Scan Automation v3.0 — github.com/iric-Sauldc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Básico (sin auth)
  python3 zap_fullscan.py --target https://staging.miapp.com

  # Completo con auth + mantener contenedor
  python3 zap_fullscan.py \\
    --target   https://staging.miapp.com \\
    --login    https://staging.miapp.com/login \\
    --user     admin@miapp.com \\
    --password "MiPass123" \\
    --output   ./mis-reportes \\
    --timeout  120 \\
    --keep

  # ZAP ya corriendo (sin Docker)
  python3 zap_fullscan.py --target https://miapp.com --no-docker
        """
    )
    p.add_argument("--target",    required=True)
    p.add_argument("--login",     default=None)
    p.add_argument("--user",      default=None)
    p.add_argument("--password",  default=None)
    p.add_argument("--openapi",   default=None)
    p.add_argument("--output",    default="./zap-reports")
    p.add_argument("--timeout",   type=int, default=90)
    p.add_argument("--threads",   type=int, default=4)
    p.add_argument("--zap-host",  default="localhost")
    p.add_argument("--no-docker", action="store_true",
                   help="ZAP ya está corriendo, no usar Docker")
    p.add_argument("--keep",      action="store_true",
                   help="NO borrar el contenedor Docker al finalizar")
    return p.parse_args()


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    args = parse_args()
    sys.exit(ZAPScanner(args).run())
