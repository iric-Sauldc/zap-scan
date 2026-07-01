#!/usr/bin/env python3
# =============================================================================
#  ZAP Full Scan Automation — iric-Sauldc
#  Autor   : github.com/iric-Sauldc
#  Versión : 2.0 (2026)
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
#      --password MiPassSegura123 \
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

# ── Consola global con colores ────────────────────────────────────────────────
console = Console()

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = """
███████╗ █████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
╚══███╔╝██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███╔╝ ███████║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
 ███╔╝  ██╔══██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
███████╗██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        Full DAST Automation // github.com/iric-Sauldc
"""

# ── Configuración ZAP ─────────────────────────────────────────────────────────
ZAP_IMAGE    = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_PORT     = 8090
ZAP_API_KEY  = "zap-fullscan-secret-key-2026"
ZAP_BASE_URL = f"http://localhost:{ZAP_PORT}"
ZAP_TIMEOUT  = 30          # segundos para requests a la API de ZAP

# Add-ons esenciales para escaneo completo
REQUIRED_ADDONS = [
    "ascanrules",           # Reglas escaneo activo (obligatorio)
    "pscanrules",           # Reglas escaneo pasivo (obligatorio)
    "ascanrulesAlpha",      # Reglas alpha (experimental pero potente)
    "pscanrulesAlpha",      # Reglas pasivas alpha
    "openapi",              # Soporte OpenAPI/Swagger
    "graphql",              # Soporte GraphQL
    "soap",                 # Soporte SOAP/WSDL
    "authhelper",           # Helper de autenticación avanzada
    "automation",           # Automation Framework
    "reports",              # Generador de reportes
    "technology-detection", # Detección de tecnologías (Wappalyzer)
    "advanced-sqlinjection-scanner",  # SQLi avanzado
    "revisit",              # Re-escaneo de URLs
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def log(msg: str, style: str = "white"):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[dim]{ts}[/dim] {msg}", style=style)

def ok(msg: str):   log(f"[bold green]✔[/bold green] {msg}")
def err(msg: str):  log(f"[bold red]✘[/bold red]  {msg}", "red")
def warn(msg: str): log(f"[bold yellow]⚠[/bold yellow]  {msg}", "yellow")
def info(msg: str): log(f"[bold cyan]ℹ[/bold cyan]  {msg}")
def step(n: int, total: int, msg: str):
    console.print(f"\n[bold magenta]── FASE {n}/{total}: {msg} ──[/bold magenta]")


# =============================================================================
#  CLASE PRINCIPAL
# =============================================================================
class ZAPFullScanner:
    def __init__(self, args):
        self.target      = args.target.rstrip("/")
        self.login_url   = args.login or f"{self.target}/login"
        self.username    = args.user
        self.password    = args.password
        self.openapi     = args.openapi
        self.output_dir  = Path(args.output)
        self.timeout_min = args.timeout
        self.zap_host    = args.zap_host
        self.no_docker   = args.no_docker
        self.threads     = args.threads
        self.container_id: Optional[str] = None
        self.session      = requests.Session()
        self.session.headers["X-ZAP-API-Key"] = ZAP_API_KEY
        self.scan_start   = datetime.now()
        self.alerts: list = []

    # ── Utilidades de API ─────────────────────────────────────────────────────
    def _get(self, endpoint: str, params: dict = {}) -> dict:
        url = f"{ZAP_BASE_URL}/JSON/{endpoint}/"
        params["apikey"] = ZAP_API_KEY
        try:
            r = self.session.get(url, params=params, timeout=ZAP_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ConnectionError:
            raise ConnectionError(f"No se puede conectar a ZAP en {ZAP_BASE_URL}")
        except Exception as e:
            raise RuntimeError(f"Error en ZAP API [{endpoint}]: {e}")

    def _post(self, endpoint: str, data: dict = {}) -> dict:
        url = f"{ZAP_BASE_URL}/JSON/{endpoint}/"
        data["apikey"] = ZAP_API_KEY
        try:
            r = self.session.post(url, data=data, timeout=ZAP_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            raise RuntimeError(f"Error en ZAP API POST [{endpoint}]: {e}")

    def _wait_for_scan(self, scan_id: str, endpoint_status: str,
                       label: str, max_minutes: int):
        """Espera a que un escaneo (spider/activo) llegue al 100%."""
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]{label}[/cyan]"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("", total=100)
            deadline = time.time() + max_minutes * 60
            while time.time() < deadline:
                try:
                    data = self._get(endpoint_status, {"scanId": scan_id})
                    pct  = int(data.get("status", 0))
                    progress.update(task, completed=pct)
                    if pct >= 100:
                        break
                except Exception:
                    pass
                time.sleep(3)
            progress.update(task, completed=100)

    # ── FASE 0: Preparación del entorno ───────────────────────────────────────
    def prepare(self):
        step(0, 8, "Preparación del entorno")

        # Crear directorios de salida
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        info(f"Directorio de salida: {self.output_dir.resolve()}")

        # Verificar Docker
        if not self.no_docker:
            if not shutil.which("docker"):
                err("Docker no encontrado. Instálalo o usa --no-docker con ZAP ya corriendo.")
                sys.exit(1)
            ok("Docker disponible")

        # Verificar conectividad al target
        info(f"Verificando acceso a {self.target} ...")
        try:
            r = requests.get(self.target, timeout=15, verify=False)
            ok(f"Target accesible (HTTP {r.status_code})")
        except Exception as e:
            warn(f"Target no responde: {e} — continuando de todas formas")

    # ── FASE 1: Levantar ZAP en Docker ────────────────────────────────────────
    def start_zap(self):
        step(1, 8, "Iniciando ZAP")

        if self.no_docker:
            info("Modo --no-docker: asumiendo ZAP corriendo en localhost")
            self._wait_zap_ready()
            return

        # Detener contenedor previo si existe
        subprocess.run(
            ["docker", "rm", "-f", "zap-fullscan"],
            capture_output=True
        )

        # Construir comando Docker
        work_dir = str(self.output_dir.resolve())
        cmd = [
            "docker", "run", "-d",
            "--name", "zap-fullscan",
            "--network", "host",
            "-v", f"{work_dir}:/zap/wrk:rw",
            ZAP_IMAGE,
            "zap.sh",
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(ZAP_PORT),
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "connection.timeoutInSecs=60",
            "-config", "scanner.maxScanDurationInMins=0",
        ]

        info(f"Pulling imagen ZAP: {ZAP_IMAGE} ...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            err(f"Error iniciando Docker: {result.stderr}")
            sys.exit(1)

        self.container_id = result.stdout.strip()[:12]
        ok(f"Contenedor ZAP iniciado: {self.container_id}")
        self._wait_zap_ready()

    def _wait_zap_ready(self, max_wait: int = 120):
        info("Esperando que ZAP esté listo ...")
        deadline = time.time() + max_wait
        with Progress(SpinnerColumn(), TextColumn("[cyan]Iniciando ZAP...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            while time.time() < deadline:
                try:
                    data = self._get("core/view/version")
                    ver  = data.get("version", "?")
                    ok(f"ZAP listo — versión {ver}")
                    return
                except Exception:
                    time.sleep(2)
        err("ZAP no respondió en el tiempo esperado. Revisa Docker.")
        self.cleanup()
        sys.exit(1)

    # ── FASE 2: Instalar add-ons ──────────────────────────────────────────────
    def install_addons(self):
        step(2, 8, "Instalando add-ons")

        # Obtener add-ons instalados
        try:
            installed_data = self._get("autoupdate/view/installedAddons")
            installed = {
                a.get("id") for a in installed_data.get("installedAddons", [])
            }
        except Exception:
            installed = set()

        # Actualizar los existentes primero
        try:
            self._post("autoupdate/action/updateAllAddons")
            ok("Add-ons actualizados")
        except Exception:
            warn("No se pudo actualizar add-ons (¿sin internet?)")

        # Instalar los faltantes
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

        # Pequeña pausa para que los add-ons carguen
        time.sleep(3)

    # ── FASE 3: Configurar contexto y autenticación ───────────────────────────
    def configure_context(self):
        step(3, 8, "Configurando contexto y autenticación")

        # Crear contexto
        ctx = self._post("context/action/newContext", {"contextName": "FullScan"})
        self.ctx_id = ctx.get("contextId", "1")

        # Incluir el target en scope
        self._post("context/action/includeInContext", {
            "contextName": "FullScan",
            "regex": f"{re.escape(self.target)}.*"
        })

        # Excluir rutas peligrosas
        dangerous = [
            ".*logout.*", ".*signout.*", ".*delete.*", ".*remove.*",
            ".*destroy.*", ".*reset-password.*", ".*unsubscribe.*",
            r".*\.png$", r".*\.jpg$", r".*\.css$", r".*\.woff.*",
        ]
        for pattern in dangerous:
            self._post("context/action/excludeFromContext", {
                "contextName": "FullScan",
                "regex": pattern
            })
        ok(f"Contexto creado (ID: {self.ctx_id}) con {len(dangerous)} exclusiones")

        # Configurar autenticación si hay credenciales
        if self.username and self.password:
            self._setup_auth()
        else:
            warn("Sin credenciales — escaneo solo en modo no autenticado")

    def _setup_auth(self):
        info("Configurando autenticación Browser-Based ...")
        try:
            # Método browser-based (el más robusto para apps modernas)
            self._post("authentication/action/setAuthenticationMethod", {
                "contextId": self.ctx_id,
                "authMethodName": "browserBasedAuthentication",
                "authMethodConfigParams": (
                    f"loginPageUrl={self.login_url}"
                    f"&loginPageWait=5"
                    f"&browserId=firefox-headless"
                )
            })
            # Configurar verificación de sesión
            self._post("authentication/action/setLoggedInIndicator", {
                "contextId": self.ctx_id,
                "loggedInIndicatorRegex": r"\Qdashboard\E|\Qprofile\E|\Qwelcome\E"
            })
            self._post("authentication/action/setLoggedOutIndicator", {
                "contextId": self.ctx_id,
                "loggedOutIndicatorRegex": r"\Qlogin\E|\Qsign in\E|\Qunauthorized\E"
            })
            # Manejo de sesión por cookie
            self._post("sessionManagement/action/setSessionManagementMethod", {
                "contextId": self.ctx_id,
                "methodName": "cookieBasedSessionManagement"
            })
            # Crear usuario
            user = self._post("users/action/newUser", {
                "contextId": self.ctx_id,
                "name": "scan-user"
            })
            self.user_id = user.get("userId", "0")
            self._post("users/action/setAuthenticationCredentials", {
                "contextId": self.ctx_id,
                "userId":    self.user_id,
                "authCredentialsConfigParams": (
                    f"username={self.username}&password={self.password}"
                )
            })
            self._post("users/action/setUserEnabled", {
                "contextId": self.ctx_id,
                "userId":    self.user_id,
                "enabled":   "true"
            })
            self._post("forcedUser/action/setForcedUser", {
                "contextId": self.ctx_id,
                "userId":    self.user_id
            })
            self._post("forcedUser/action/setForcedUserModeEnabled", {
                "boolean": "true"
            })
            ok(f"Autenticación configurada para: {self.username}")
        except Exception as e:
            warn(f"No se pudo configurar autenticación avanzada: {e}")
            warn("Continuando sin autenticación ...")
            self.user_id = None

    # ── FASE 4: Importar API Spec (OpenAPI/GraphQL) ───────────────────────────
    def import_api_spec(self):
        step(4, 8, "Importando definición de API")
        if self.openapi and Path(self.openapi).exists():
            try:
                self._post("openapi/action/importFile", {
                    "file":      self.openapi,
                    "target":    self.target,
                    "contextId": self.ctx_id
                })
                ok(f"OpenAPI spec importado: {self.openapi}")
            except Exception as e:
                warn(f"No se pudo importar OpenAPI spec: {e}")
        else:
            # Intentar descubrir OpenAPI desde URL común
            for spec_path in ["/openapi.json", "/api-docs", "/swagger.json", "/v1/openapi.json"]:
                spec_url = f"{self.target}{spec_path}"
                try:
                    r = requests.get(spec_url, timeout=5, verify=False)
                    if r.status_code == 200 and "openapi" in r.text.lower():
                        self._post("openapi/action/importUrl", {
                            "url":       spec_url,
                            "contextId": self.ctx_id
                        })
                        ok(f"OpenAPI spec auto-descubierto en: {spec_url}")
                        break
                except Exception:
                    continue
            else:
                info("No se encontró OpenAPI spec — escaneo por crawl únicamente")

    # ── FASE 5: Spider + AJAX Spider ─────────────────────────────────────────
    def run_spider(self):
        step(5, 8, "Descubrimiento de URLs (Spider + AJAX)")

        # 5a) Spider tradicional
        info("Iniciando Spider tradicional ...")
        spider = self._post("spider/action/scan", {
            "url":             self.target,
            "contextName":     "FullScan",
            "recurse":         "true",
            "subtreeOnly":     "false",
            "maxChildren":     "0",
        })
        spider_id = spider.get("scan", "0")
        self._wait_for_scan(spider_id, "spider/view/status",
                            "Spider tradicional", max_minutes=25)
        urls = self._get("spider/view/results", {"scanId": spider_id})
        spider_count = len(urls.get("results", []))
        ok(f"Spider tradicional completado — {spider_count} URLs descubiertas")

        # 5b) AJAX Spider (para SPAs y JavaScript)
        info("Iniciando AJAX Spider (headless browser) ...")
        self._post("ajaxSpider/action/scan", {
            "url":         self.target,
            "contextName": "FullScan",
            "subtreeOnly": "false",
        })
        # AJAX Spider no devuelve scan_id, usa estado distinto
        with Progress(SpinnerColumn(),
                      TextColumn("[cyan]AJAX Spider corriendo...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            deadline = time.time() + 25 * 60
            while time.time() < deadline:
                try:
                    status = self._get("ajaxSpider/view/status")
                    if status.get("status") == "stopped":
                        break
                except Exception:
                    pass
                time.sleep(5)

        ajax_urls = self._get("ajaxSpider/view/results")
        ajax_count = len(ajax_urls.get("results", []))
        ok(f"AJAX Spider completado — {ajax_count} URLs adicionales")
        self.total_urls = spider_count + ajax_count

        # Escaneo pasivo del tráfico capturado
        info("Ejecutando escaneo pasivo sobre tráfico capturado ...")
        self._post("pscan/action/enableAllScanners")
        self._post("pscan/action/setMaxAlertsPerRule", {"maxAlerts": "10"})
        deadline = time.time() + 10 * 60
        with Progress(SpinnerColumn(),
                      TextColumn("[cyan]Escaneo pasivo...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            while time.time() < deadline:
                try:
                    rec = self._get("pscan/view/recordsToScan")
                    remaining = int(rec.get("recordsToScan", 0))
                    if remaining == 0:
                        break
                except Exception:
                    pass
                time.sleep(3)
        ok("Escaneo pasivo completado")

    # ── FASE 6: Escaneo activo completo ──────────────────────────────────────
    def run_active_scan(self):
        step(6, 8, "Escaneo activo (OWASP Top 10 2025 + más)")

        # Configurar política máxima: Threshold LOW, Strength HIGH
        self._configure_scan_policy()

        # Habilitar TODOS los scanners activos
        self._post("ascan/action/enableAllScanners", {"policyName": "FullPolicy"})

        # Strength INSANE para las categorías críticas
        critical_rules = [
            "40018",  # SQL Injection
            "40012",  # XSS Reflected
            "40014",  # XSS Persistent
            "90020",  # Remote OS Command Injection
            "40046",  # SSRF
            "90023",  # XXE
            "90035",  # SSTI
            "6",      # Path Traversal
        ]
        for rule_id in critical_rules:
            try:
                self._post("ascan/action/setScannerAttackStrength", {
                    "id":       rule_id,
                    "strength": "INSANE",
                    "policyName": "FullPolicy"
                })
                self._post("ascan/action/setScannerAlertThreshold", {
                    "id":        rule_id,
                    "threshold": "LOW",
                    "policyName": "FullPolicy"
                })
            except Exception:
                pass

        # Lanzar escaneo activo
        scan_params = {
            "url":          self.target,
            "contextId":    self.ctx_id,
            "recurse":      "true",
            "scanPolicyName": "FullPolicy",
            "method":       "",
            "postData":     "",
        }
        if hasattr(self, "user_id") and self.user_id:
            scan_params["userId"] = self.user_id

        scan = self._post("ascan/action/scan", scan_params)
        scan_id = scan.get("scan", "0")

        self._wait_for_scan(scan_id, "ascan/view/status",
                            "Escaneo activo", max_minutes=self.timeout_min)
        ok(f"Escaneo activo completado (ID: {scan_id})")

    def _configure_scan_policy(self):
        try:
            self._post("ascan/action/addScanPolicy", {
                "scanPolicyName": "FullPolicy",
                "alertThreshold": "LOW",
                "attackStrength": "HIGH"
            })
        except Exception:
            # La política ya existe, actualizar
            try:
                self._post("ascan/action/updateScanPolicy", {
                    "scanPolicyName": "FullPolicy",
                    "alertThreshold": "LOW",
                    "attackStrength": "HIGH"
                })
            except Exception:
                pass

    # ── FASE 7: Recopilar alertas y generar reportes ──────────────────────────
    def collect_and_report(self):
        step(7, 8, "Recopilando alertas y generando reportes")

        # Obtener TODAS las alertas
        alerts_data = self._get("alert/view/alerts", {
            "baseurl": self.target,
            "start":   "0",
            "count":   "999999",
        })
        self.alerts = alerts_data.get("alerts", [])
        ok(f"Total de alertas encontradas: {len(self.alerts)}")

        # Clasificar por riesgo
        self.by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for alert in self.alerts:
            risk = alert.get("risk", "Informational")
            self.by_risk.get(risk, self.by_risk["Informational"]).append(alert)

        # Guardar JSON completo
        report_path = self.output_dir / "reports"
        json_file = report_path / "zap-alerts.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "scan_info": {
                    "target":     self.target,
                    "start_time": self.scan_start.isoformat(),
                    "end_time":   datetime.now().isoformat(),
                    "total_urls": getattr(self, "total_urls", 0),
                    "scanner":    "ZAP 2.17 — github.com/iric-Sauldc",
                },
                "summary": {
                    "total":  len(self.alerts),
                    "high":   len(self.by_risk["High"]),
                    "medium": len(self.by_risk["Medium"]),
                    "low":    len(self.by_risk["Low"]),
                    "info":   len(self.by_risk["Informational"]),
                },
                "alerts": self.alerts
            }, f, indent=2, ensure_ascii=False)
        ok(f"Reporte JSON: {json_file}")

        # Generar reporte HTML via API de ZAP
        try:
            self._post("reports/action/generate", {
                "title":       "ZAP Full Scan Report",
                "template":    "traditional-html-plus",
                "reportDir":   "/zap/wrk/reports",
                "reportFile":  "zap-report-full",
                "description": f"DAST Full Scan — {self.target}",
                "contexts":    "FullScan",
            })
            ok("Reporte HTML generado")
        except Exception as e:
            warn(f"No se pudo generar HTML via API: {e}")

        # Reporte SARIF (para GitHub Security)
        try:
            self._post("reports/action/generate", {
                "title":      "ZAP SARIF",
                "template":   "sarif-json",
                "reportDir":  "/zap/wrk/reports",
                "reportFile": "zap-report",
            })
            ok("Reporte SARIF generado")
        except Exception as e:
            warn(f"SARIF no disponible: {e}")

        # Generar reporte Markdown custom
        self._generate_markdown_report(report_path)

    def _generate_markdown_report(self, report_dir: Path):
        md_file = report_dir / "zap-report.md"
        elapsed = datetime.now() - self.scan_start
        lines = [
            f"# 🔒 ZAP Security Report",
            f"",
            f"| Campo | Valor |",
            f"|-------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Fecha** | {self.scan_start.strftime('%Y-%m-%d %H:%M')} |",
            f"| **Duración** | {str(elapsed).split('.')[0]} |",
            f"| **URLs descubiertas** | {getattr(self, 'total_urls', 'N/A')} |",
            f"| **Scanner** | ZAP 2.17 · github.com/iric-Sauldc |",
            f"",
            f"## Resumen de Vulnerabilidades",
            f"",
            f"| Severidad | Cantidad |",
            f"|-----------|---------|",
            f"| 🔴 Alta   | {len(self.by_risk['High'])} |",
            f"| 🟡 Media  | {len(self.by_risk['Medium'])} |",
            f"| 🔵 Baja   | {len(self.by_risk['Low'])} |",
            f"| ⚪ Info   | {len(self.by_risk['Informational'])} |",
            f"| **Total** | **{len(self.alerts)}** |",
            f"",
        ]

        for risk, color in [("High", "🔴"), ("Medium", "🟡"),
                             ("Low", "🔵"), ("Informational", "⚪")]:
            items = self.by_risk[risk]
            if not items:
                continue
            lines.append(f"## {color} Vulnerabilidades de Severidad {risk}\n")
            # Deduplicar por nombre
            seen = {}
            for a in items:
                name = a.get("name", "Unknown")
                if name not in seen:
                    seen[name] = {"count": 0, "urls": [], "alert": a}
                seen[name]["count"] += 1
                url = a.get("url", "")
                if url not in seen[name]["urls"]:
                    seen[name]["urls"].append(url)

            for name, data in seen.items():
                a = data["alert"]
                lines += [
                    f"### {name}",
                    f"",
                    f"- **CWE:** {a.get('cweid', 'N/A')}",
                    f"- **Instancias:** {data['count']}",
                    f"- **Confianza:** {a.get('confidence', 'N/A')}",
                    f"- **Descripción:** {a.get('description', '')[:300]}...",
                    f"- **Solución:** {a.get('solution', '')[:300]}...",
                    f"- **URLs afectadas:**",
                ]
                for url in data["urls"][:5]:
                    lines.append(f"  - `{url}`")
                lines.append("")

        with open(md_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        ok(f"Reporte Markdown: {md_file}")

    # ── FASE 8: Mostrar resumen en terminal ───────────────────────────────────
    def print_summary(self):
        step(8, 8, "Resumen final")
        elapsed = datetime.now() - self.scan_start

        # Tabla de resultados
        table = Table(
            title="🔍 Resultados del Escaneo ZAP",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Severidad",  style="bold",   width=15)
        table.add_column("Cantidad",   justify="right", width=10)
        table.add_column("Vulnerabilidades encontradas", width=50)

        risk_config = [
            ("🔴 Alta",  "High",          "red"),
            ("🟡 Media", "Medium",        "yellow"),
            ("🔵 Baja",  "Low",           "cyan"),
            ("⚪ Info",  "Informational", "dim"),
        ]
        for label, risk, color in risk_config:
            items = self.by_risk[risk]
            unique = list({a.get("name", "") for a in items})[:3]
            names  = ", ".join(unique) + ("..." if len(unique) >= 3 else "")
            table.add_row(
                Text(label, style=color),
                Text(str(len(items)), style=f"bold {color}"),
                names or "—"
            )

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{len(self.alerts)}[/bold]",
            f"URLs escaneadas: {getattr(self, 'total_urls', 'N/A')}"
        )

        console.print()
        console.print(table)

        # Panel de estado
        high_count = len(self.by_risk["High"])
        if high_count == 0:
            status_color = "green"
            status_icon  = "✅"
            status_msg   = "Sin vulnerabilidades críticas encontradas"
        elif high_count <= 3:
            status_color = "yellow"
            status_icon  = "⚠️ "
            status_msg   = f"{high_count} vulnerabilidades ALTAS — requieren atención"
        else:
            status_color = "red"
            status_icon  = "🚨"
            status_msg   = f"{high_count} vulnerabilidades ALTAS — acción inmediata requerida"

        console.print(Panel(
            f"{status_icon}  {status_msg}\n\n"
            f"[dim]Duración: {str(elapsed).split('.')[0]}  |  "
            f"Reportes en: {self.output_dir / 'reports'}[/dim]",
            title="[bold]Estado de Seguridad[/bold]",
            border_style=status_color,
            padding=(1, 4),
        ))

        # Exit code para CI/CD
        return 1 if high_count > 0 else 0

    # ── Limpieza ──────────────────────────────────────────────────────────────
    def cleanup(self):
        if self.container_id and not self.no_docker:
            info("Deteniendo contenedor ZAP ...")
            subprocess.run(
                ["docker", "rm", "-f", "zap-fullscan"],
                capture_output=True
            )
            ok("Contenedor eliminado")

    # ── Orquestador principal ─────────────────────────────────────────────────
    def run(self) -> int:
        console.print(f"[bold green]{BANNER}[/bold green]")
        console.print(Panel(
            f"[bold]Target:[/bold] {self.target}\n"
            f"[bold]Login:[/bold]  {self.login_url}\n"
            f"[bold]User:[/bold]   {self.username or 'No autenticado'}\n"
            f"[bold]Output:[/bold] {self.output_dir}",
            title="⚙️  Configuración del escaneo",
            border_style="cyan"
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
            warn("\nEscaneo interrumpido por el usuario")
            exit_code = 130
        except Exception as e:
            err(f"Error fatal: {e}")
            import traceback
            console.print_exception()
            exit_code = 1
        finally:
            self.cleanup()

        return exit_code


# =============================================================================
#  CLI
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="ZAP Full Scan Automation — github.com/iric-Sauldc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Escaneo básico sin autenticación
  python3 zap_fullscan.py --target https://staging.miapp.com

  # Escaneo completo con autenticación
  python3 zap_fullscan.py \\
    --target   https://staging.miapp.com \\
    --login    https://staging.miapp.com/login \\
    --user     admin@miapp.com \\
    --password "MiPass123" \\
    --openapi  ./docs/openapi.yaml \\
    --output   ./reports \\
    --timeout  120

  # Con ZAP ya corriendo (sin Docker)
  python3 zap_fullscan.py --target https://miapp.com --no-docker
        """
    )
    p.add_argument("--target",    required=True,           help="URL objetivo del escaneo")
    p.add_argument("--login",     default=None,            help="URL de la página de login")
    p.add_argument("--user",      default=None,            help="Usuario para autenticación")
    p.add_argument("--password",  default=None,            help="Contraseña para autenticación")
    p.add_argument("--openapi",   default=None,            help="Ruta al archivo OpenAPI/Swagger")
    p.add_argument("--output",    default="./zap-reports", help="Directorio de salida de reportes")
    p.add_argument("--timeout",   type=int, default=90,    help="Timeout del escaneo activo en minutos")
    p.add_argument("--threads",   type=int, default=4,     help="Hilos paralelos del scanner")
    p.add_argument("--zap-host",  default="localhost",     help="Host donde corre ZAP")
    p.add_argument("--no-docker", action="store_true",     help="No usar Docker (ZAP ya corriendo)")
    return p.parse_args()


if __name__ == "__main__":
    # Suprimir warnings de SSL (entornos de prueba con cert autofirmado)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    args   = parse_args()
    scanner = ZAPFullScanner(args)
    sys.exit(scanner.run())
