#!/usr/bin/env python3
# =============================================================================
#  ZAP Full Scan Automation — github.com/iric-Sauldc
#  Versión : 4.0 (2026)
#  Fixes   : Watchdog de contenedor, reconexión automática, checkpoint de
#             alertas cada 5 min, límite de memoria Docker, diagnóstico OOM
#
#  Uso rápido:
#    python3 zap_fullscan.py --target https://staging.miapp.com
#
#  Completo:
#    python3 zap_fullscan.py \
#      --target   https://staging.miapp.com  \
#      --login    https://staging.miapp.com/login \
#      --user     admin@miapp.com \
#      --password "MiPass123" \
#      --output   ./reports \
#      --timeout  120 \
#      --memory   4g \
#      --keep
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
from rich.progress import (Progress, SpinnerColumn, TextColumn,
                           BarColumn, TimeElapsedColumn)
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
   Full DAST Automation v4.0 // github.com/iric-Sauldc
"""

ZAP_CONTAINER = "zap-fullscan"
ZAP_IMAGE     = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_PORT      = 8090
ZAP_API_KEY   = "zap-fullscan-key-2026"
ZAP_BASE      = f"http://localhost:{ZAP_PORT}"
ZAP_TIMEOUT   = 30          # segundos timeout HTTP normal
ZAP_LONG_TO   = 120         # timeout para reportes grandes

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
def dbg(m):  console.print(f"[dim]{_ts()} DBG: {m}[/dim]")
def step(n, t, m):
    console.print(f"\n[bold magenta]── FASE {n}/{t}: {m} ──[/bold magenta]")


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
        self.memory      = args.memory          # límite RAM Docker, ej: "4g"
        self.no_docker   = args.no_docker
        self.threads     = args.threads
        self.keep        = args.keep
        self.container_id: Optional[str] = None
        self.ctx_id      = "1"
        self.user_id     = None
        self.alerts: list = []
        self.by_risk: dict = {"High":[], "Medium":[], "Low":[], "Informational":[]}
        self.total_urls  = 0
        self.scan_start  = datetime.now()
        # Archivo checkpoint — guarda alertas parciales durante el escaneo
        self.checkpoint_file = self.output_dir / ".zap_checkpoint.json"

        self.s = requests.Session()
        self.s.headers["X-ZAP-API-Key"] = ZAP_API_KEY

    # =========================================================================
    # API helpers con reconexión automática
    # =========================================================================
    def _get(self, path: str, params: dict = None, timeout: int = None) -> dict:
        p = {"apikey": ZAP_API_KEY}
        if params:
            p.update(params)
        t = timeout or ZAP_TIMEOUT
        r = self.s.get(f"{ZAP_BASE}/JSON/{path}/", params=p, timeout=t)
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
        p = {"apikey": ZAP_API_KEY}
        if params:
            p.update(params)
        r = self.s.get(f"{ZAP_BASE}/OTHER/{path}/", params=p,
                       timeout=ZAP_LONG_TO, stream=True)
        r.raise_for_status()
        return r

    # ── Verificar que el contenedor Docker sigue vivo ─────────────────────────
    def _container_alive(self) -> bool:
        if self.no_docker:
            return True
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", ZAP_CONTAINER],
            capture_output=True, text=True
        )
        return r.returncode == 0 and r.stdout.strip() == "running"

    def _container_exit_reason(self) -> str:
        """Devuelve el motivo de muerte del contenedor (OOMKilled, error, etc.)"""
        r = subprocess.run(
            ["docker", "inspect", "--format",
             "ExitCode={{.State.ExitCode}} OOM={{.State.OOMKilled}} Error={{.State.Error}}",
             ZAP_CONTAINER],
            capture_output=True, text=True
        )
        return r.stdout.strip() if r.returncode == 0 else "contenedor no encontrado"

    # ── Guardar alertas parciales en checkpoint ───────────────────────────────
    def _save_checkpoint(self, alerts: list):
        try:
            data = {
                "saved_at":   datetime.now().isoformat(),
                "target":     self.target,
                "total_urls": self.total_urls,
                "alerts":     alerts,
            }
            self.checkpoint_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            warn(f"No se pudo guardar checkpoint: {e}")

    def _load_checkpoint(self) -> list:
        try:
            if self.checkpoint_file.exists():
                data = json.loads(self.checkpoint_file.read_text(encoding="utf-8"))
                saved = data.get("saved_at", "?")
                alerts = data.get("alerts", [])
                warn(f"Checkpoint encontrado ({saved}) — {len(alerts)} alertas recuperadas")
                return alerts
        except Exception:
            pass
        return []

    # ── Esperar escaneo con watchdog del contenedor ───────────────────────────
    def _wait_scan(self, scan_id: str, status_path: str,
                   label: str, max_min: int,
                   checkpoint_interval: int = 300):  # checkpoint cada 5 min
        last_checkpoint = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]{label}[/cyan]"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(), console=console
        ) as prog:
            task = prog.add_task("", total=100)
            deadline = time.time() + max_min * 60

            while time.time() < deadline:
                # ── Watchdog: ¿sigue vivo el contenedor? ─────────────────────
                if not self._container_alive():
                    reason = self._container_exit_reason()
                    prog.stop()
                    err(f"Contenedor ZAP muerto durante '{label}'")
                    err(f"  Diagnóstico: {reason}")
                    if "OOM=true" in reason:
                        err("  CAUSA: Out of Memory — usa --memory con más RAM (ej: --memory 6g)")
                    raise RuntimeError(f"Contenedor muerto: {reason}")

                # ── Progreso ──────────────────────────────────────────────────
                try:
                    pct = int(self._get(status_path,
                                        {"scanId": scan_id}).get("status", 0))
                    prog.update(task, completed=pct)
                    if pct >= 100:
                        break
                except requests.exceptions.ConnectionError:
                    # ZAP puede desconectarse brevemente bajo carga
                    prog.update(task)
                except Exception:
                    pass

                # ── Checkpoint periódico de alertas ───────────────────────────
                if time.time() - last_checkpoint > checkpoint_interval:
                    try:
                        raw = self._get("alert/view/alerts", {
                            "baseurl": self.target, "start": "0", "count": "99999"
                        })
                        self._save_checkpoint(raw.get("alerts", []))
                        last_checkpoint = time.time()
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

        if not self.no_docker:
            if not shutil.which("docker"):
                err("Docker no encontrado.")
                sys.exit(1)
            ok("Docker disponible")
            # Mostrar RAM disponible del sistema
            try:
                mem = subprocess.run(["free", "-h"], capture_output=True, text=True)
                lines = [l for l in mem.stdout.splitlines() if "Mem:" in l]
                if lines:
                    info(f"RAM sistema: {lines[0]}")
                info(f"Límite Docker para ZAP: {self.memory}")
            except Exception:
                pass

        try:
            r = requests.get(self.target, timeout=10, verify=False)
            ok(f"Target accesible — HTTP {r.status_code}")
        except Exception as e:
            warn(f"Target no responde: {e}")

    # =========================================================================
    # FASE 1 — Levantar ZAP en Docker con límite de memoria
    # =========================================================================
    def start_zap(self):
        step(1, 8, "Iniciando ZAP")
        if self.no_docker:
            info("Modo --no-docker activo")
            self._wait_zap_ready()
            return

        subprocess.run(["docker", "rm", "-f", ZAP_CONTAINER], capture_output=True)

        work_dir = str(self.output_dir)
        cmd = [
            "docker", "run", "-d",
            "--name", ZAP_CONTAINER,
            "--network", "host",
            "-u", "zap",
            # Límite de memoria — evita OOMKill silencioso
            "--memory", self.memory,
            "--memory-swap", self.memory,   # sin swap (falla limpio)
            # Opciones JVM para ZAP: heap máximo proporcional a RAM asignada
            "-e", f"JAVA_OPTS=-Xmx{self._jvm_heap()}",
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
        ok(f"Contenedor iniciado: {self.container_id} (RAM: {self.memory})")
        self._wait_zap_ready()

    def _jvm_heap(self) -> str:
        """Calcula heap JVM como 75% del límite Docker."""
        mem = self.memory.lower()
        try:
            if mem.endswith("g"):
                gb = float(mem[:-1])
                return f"{int(gb * 0.75)}g"
            if mem.endswith("m"):
                mb = float(mem[:-1])
                return f"{int(mb * 0.75)}m"
        except Exception:
            pass
        return "3g"

    def _wait_zap_ready(self, max_wait: int = 180):
        info("Esperando ZAP API ...")
        deadline = time.time() + max_wait
        with Progress(SpinnerColumn(), TextColumn("[cyan]Iniciando ZAP...[/cyan]"),
                      TimeElapsedColumn(), console=console) as p:
            p.add_task("")
            while time.time() < deadline:
                if not self.no_docker and not self._container_alive():
                    reason = self._container_exit_reason()
                    err(f"Contenedor murió al iniciar: {reason}")
                    sys.exit(1)
                try:
                    ver = self._get("core/view/version").get("version", "?")
                    ok(f"ZAP listo — v{ver}")
                    return
                except Exception:
                    time.sleep(3)
        err("ZAP no respondió en el tiempo esperado.")
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
                for a in self._get("autoupdate/view/installedAddons")
                              .get("installedAddons", [])
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
    # FASE 3 — Contexto y autenticación
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
                    f"loginPageUrl={self.login_url}&loginPageWait=5"
                    f"&browserId=firefox-headless"
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
            self._post("users/action/setUserEnabled", {
                "contextId": self.ctx_id, "userId": self.user_id, "enabled": "true"
            })
            self._post("forcedUser/action/setForcedUser", {
                "contextId": self.ctx_id, "userId": self.user_id
            })
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
            try:
                r = requests.get(f"{self.target}{path}", timeout=5, verify=False)
                if r.status_code == 200 and "openapi" in r.text.lower():
                    self._post("openapi/action/importUrl",
                               {"url": f"{self.target}{path}", "contextId": self.ctx_id})
                    ok(f"OpenAPI auto-descubierto: {self.target}{path}")
                    return
            except Exception:
                continue
        info("No se encontró OpenAPI spec — crawl único")

    # =========================================================================
    # FASE 5 — Spider + AJAX + Passive
    # =========================================================================
    def run_spider(self):
        step(5, 8, "Descubrimiento de URLs")

        info("Spider tradicional ...")
        sp = self._post("spider/action/scan", {
            "url": self.target, "contextName": "FullScan",
            "recurse": "true", "maxChildren": "0",
        })
        sp_id = sp.get("scan", "0")
        self._wait_scan(sp_id, "spider/view/status", "Spider", max_min=25)
        sp_urls = len(self._get("spider/view/results",
                                {"scanId": sp_id}).get("results", []))
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
                if not self._container_alive():
                    err("Contenedor muerto durante AJAX Spider")
                    raise RuntimeError("Contenedor ZAP muerto")
                try:
                    if self._get("ajaxSpider/view/status").get("status") == "stopped":
                        break
                except Exception:
                    pass
                time.sleep(5)

        ajax_urls = 0
        try:
            ajax_urls = len(self._get("ajaxSpider/view/results").get("results", []))
        except Exception:
            pass
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
        step(6, 8, "Escaneo activo — OWASP Top 10 2025")

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

        for rid in ["40018", "40012", "40014", "90020", "40046", "90023", "90035", "6"]:
            try:
                self._post("ascan/action/setScannerAttackStrength",
                           {"id": rid, "strength": "INSANE", "policyName": "FullPolicy"})
                self._post("ascan/action/setScannerAlertThreshold",
                           {"id": rid, "threshold": "LOW", "policyName": "FullPolicy"})
            except Exception:
                pass

        params = {
            "url": self.target, "contextId": self.ctx_id,
            "recurse": "true", "scanPolicyName": "FullPolicy",
        }
        if self.user_id:
            params["userId"] = self.user_id

        scan = self._post("ascan/action/scan", params)
        scan_id = scan.get("scan", "0")

        # _wait_scan incluye watchdog + checkpoint cada 5 min
        self._wait_scan(scan_id, "ascan/view/status",
                        "Escaneo activo", max_min=self.timeout_min)
        ok(f"Escaneo activo completado (ID: {scan_id})")

    # =========================================================================
    # FASE 7 — Reportes resilientes
    # =========================================================================
    def collect_and_report(self):
        step(7, 8, "Generando reportes")

        # ── Verificar contenedor antes de intentar reportes ──────────────────
        if not self._container_alive():
            reason = self._container_exit_reason()
            err(f"ZAP no está disponible al generar reportes")
            err(f"  Diagnóstico: {reason}")
            if "OOM=true" in reason:
                err("  CAUSA: Out of Memory — reinicia con --memory más alto (ej: --memory 6g)")
            warn("Intentando recuperar alertas del checkpoint ...")
            self.alerts = self._load_checkpoint()
            if not self.alerts:
                err("Sin checkpoint disponible. No hay alertas que reportar.")
                err(f"  Usa --memory para dar más RAM (actualmente: {self.memory})")
                return
            warn(f"Usando {len(self.alerts)} alertas del checkpoint (parciales)")
        else:
            # Contenedor vivo — recopilar alertas en tiempo real
            info("Recopilando alertas ...")
            try:
                raw = self._get("alert/view/alerts", {
                    "baseurl": self.target, "start": "0", "count": "99999",
                }, timeout=60)
                self.alerts = raw.get("alerts", [])
                ok(f"Alertas totales: {len(self.alerts)}")
            except Exception as e:
                err(f"No se pudieron obtener alertas en tiempo real: {e}")
                self.alerts = self._load_checkpoint()
                if self.alerts:
                    warn(f"Usando checkpoint: {len(self.alerts)} alertas")
                else:
                    err("Sin checkpoint. Abortando reporte.")
                    return

        # Clasificar
        self.by_risk = {"High":[], "Medium":[], "Low":[], "Informational":[]}
        for a in self.alerts:
            self.by_risk.setdefault(a.get("risk", "Informational"), []).append(a)

        generated = {}
        info("Escribiendo archivos de reporte ...")

        # ── JSON (siempre funciona — Python escribe directo) ──────────────────
        json_path = self.report_dir / "zap-alerts.json"
        try:
            json_path.write_text(json.dumps({
                "scan_info": {
                    "target":     self.target,
                    "start_time": self.scan_start.isoformat(),
                    "end_time":   datetime.now().isoformat(),
                    "total_urls": self.total_urls,
                    "memory_limit": self.memory,
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
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            generated["JSON"] = json_path
            ok(f"  JSON — {json_path.stat().st_size // 1024} KB")
        except Exception as e:
            err(f"  JSON falló: {e}")

        # ── Markdown (Python escribe directo — no depende de ZAP) ─────────────
        try:
            md_path = self._write_markdown()
            generated["Markdown"] = md_path
            ok(f"  Markdown — {md_path.stat().st_size // 1024} KB")
        except Exception as e:
            err(f"  Markdown falló: {e}")

        # ── HTML y XML vía /OTHER/ (ZAP devuelve contenido en HTTP body) ──────
        if self._container_alive():
            for fmt, endpoint, fname in [
                ("HTML", "core/other/htmlreport",  "zap-report.html"),
                ("XML",  "core/other/xmlreport",   "zap-report.xml"),
            ]:
                dest = self.report_dir / fname
                try:
                    resp = self._other_get(endpoint)
                    dest.write_bytes(resp.content)
                    size = dest.stat().st_size
                    if size > 500:
                        generated[fmt] = dest
                        ok(f"  {fmt} — {size // 1024} KB")
                    else:
                        warn(f"  {fmt} vacío ({size} bytes) — intentando fallback")
                        raise ValueError("vacío")
                except Exception:
                    # Fallback: add-on reports → docker cp
                    ext = ".html" if fmt == "HTML" else ".xml"
                    tpl = "traditional-html-plus" if fmt == "HTML" else "traditional-xml"
                    p = self._addon_via_cp(tpl, f"zap-rep-{fmt.lower()}", ext)
                    if p:
                        generated[fmt] = p
                        ok(f"  {fmt} (fallback cp) — {p.stat().st_size // 1024} KB")
                    else:
                        warn(f"  {fmt} no generado")

            # ── SARIF (solo add-on) ───────────────────────────────────────────
            p = self._addon_via_cp("sarif-json", "zap-rep-sarif", ".sarif")
            if p:
                generated["SARIF"] = p
                ok(f"  SARIF — {p.stat().st_size // 1024} KB")
        else:
            warn("ZAP no disponible — HTML/XML/SARIF omitidos (usar JSON+Markdown)")

        # ── Limpiar checkpoint si todo fue bien ───────────────────────────────
        if generated and self.checkpoint_file.exists():
            try:
                self.checkpoint_file.unlink()
            except Exception:
                pass

        # ── Tabla de archivos generados ───────────────────────────────────────
        console.print()
        t = Table(title="📁 Reportes generados", box=box.ROUNDED,
                  header_style="bold cyan")
        t.add_column("Formato",  style="bold", width=10)
        t.add_column("Archivo",  width=35)
        t.add_column("Tamaño",   justify="right", width=10)
        t.add_column("Estado",   justify="center", width=12)

        for fmt in ["JSON", "HTML", "XML", "SARIF", "Markdown"]:
            if fmt in generated and generated[fmt].exists():
                size = generated[fmt].stat().st_size
                t.add_row(fmt, generated[fmt].name,
                          f"{max(size//1024,1)} KB",
                          "[bold green]✔ OK[/bold green]")
            else:
                t.add_row(fmt, "—", "—", "[red]✘ No generado[/red]")
        console.print(t)

    # ── Add-on reports + docker cp ────────────────────────────────────────────
    def _addon_via_cp(self, template: str, basename: str, ext: str) -> Optional[Path]:
        if self.no_docker:
            return None
        try:
            r = self._post("reports/action/generate", {
                "title":       f"ZAP {template}",
                "template":    template,
                "reportDir":   "/tmp",
                "reportFile":  basename,
                "description": f"DAST — {self.target}",
                "contexts":    "FullScan",
            })
            internal = r.get("generate", "")
            dbg(f"Ruta interna ZAP ({template}): '{internal}'")
            if not internal:
                return None

            dest = self.report_dir / f"{basename}{ext}"
            cp = subprocess.run(
                ["docker", "cp", f"{ZAP_CONTAINER}:{internal}", str(dest)],
                capture_output=True, text=True
            )
            if cp.returncode != 0:
                dbg(f"docker cp error: {cp.stderr.strip()}")
                return None

            if dest.exists() and dest.stat().st_size > 200:
                return dest
            return None
        except Exception as e:
            dbg(f"addon_via_cp error ({template}): {e}")
            return None

    # ── Reporte Markdown ──────────────────────────────────────────────────────
    def _write_markdown(self) -> Path:
        md = self.report_dir / "zap-report.md"
        elapsed = str(datetime.now() - self.scan_start).split(".")[0]
        lines = [
            "# 🔒 ZAP Security Report",
            "",
            "| Campo | Valor |",
            "|-------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Fecha** | {self.scan_start.strftime('%Y-%m-%d %H:%M')} |",
            f"| **Duración** | {elapsed} |",
            f"| **URLs escaneadas** | {self.total_urls} |",
            f"| **Memoria Docker** | {self.memory} |",
            f"| **Autor** | [iric-Sauldc](https://github.com/iric-Sauldc) |",
            "",
            "## Resumen",
            "",
            "| Severidad | # |",
            "|-----------|---|",
            f"| 🔴 Alta | {len(self.by_risk.get('High', []))} |",
            f"| 🟡 Media | {len(self.by_risk.get('Medium', []))} |",
            f"| 🔵 Baja | {len(self.by_risk.get('Low', []))} |",
            f"| ⚪ Info | {len(self.by_risk.get('Informational', []))} |",
            f"| **Total** | **{len(self.alerts)}** |",
            "",
        ]
        for risk, icon in [("High","🔴"),("Medium","🟡"),
                            ("Low","🔵"),("Informational","⚪")]:
            items = self.by_risk.get(risk, [])
            if not items:
                continue
            lines.append(f"## {icon} {risk}\n")
            seen: dict = {}
            for a in items:
                n = a.get("name", "Unknown")
                if n not in seen:
                    seen[n] = {"count": 0, "urls": [], "a": a}
                seen[n]["count"] += 1
                u = a.get("url", "")
                if u and u not in seen[n]["urls"]:
                    seen[n]["urls"].append(u)
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

        t = Table(title="🔍 Resultados del escaneo",
                  box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Severidad",  style="bold", width=14)
        t.add_column("Cantidad",   justify="right", width=9)
        t.add_column("Ejemplos",   width=55)

        for label, risk, color in [
            ("🔴 Alta",  "High",          "red"),
            ("🟡 Media", "Medium",        "yellow"),
            ("🔵 Baja",  "Low",           "cyan"),
            ("⚪ Info",  "Informational", "dim"),
        ]:
            items = self.by_risk.get(risk, [])
            names = list({a.get("name","") for a in items})[:3]
            t.add_row(
                Text(label, style=color),
                Text(str(len(items)), style=f"bold {color}"),
                ", ".join(names) + ("..." if len(names) == 3 else "")
            )
        t.add_section()
        t.add_row("[bold]TOTAL[/bold]", f"[bold]{len(self.alerts)}[/bold]",
                  f"URLs: {self.total_urls}  |  Memoria: {self.memory}")
        console.print(); console.print(t)

        high = len(self.by_risk.get("High", []))
        color, icon, msg = (
            ("green",  "✅",  "Sin vulnerabilidades críticas") if high == 0 else
            ("yellow", "⚠️ ", f"{high} vulnerabilidades ALTAS — revisar") if high <= 3 else
            ("red",    "🚨",  f"{high} vulnerabilidades ALTAS — acción inmediata")
        )
        keep_note = (
            "\n[dim]Contenedor ZAP mantenido (--keep)[/dim]"
            if self.keep else ""
        )
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
                info(f"Contenedor ZAP mantenido: [bold]{ZAP_CONTAINER}[/bold]")
                info(f"  Ver logs:    [bold cyan]docker logs {ZAP_CONTAINER}[/bold cyan]")
                info(f"  Acceder:     [bold cyan]docker exec -it {ZAP_CONTAINER} bash[/bold cyan]")
                info(f"  Detener:     [bold cyan]docker rm -f {ZAP_CONTAINER}[/bold cyan]")
            else:
                info("Deteniendo contenedor ZAP ...")
                subprocess.run(["docker", "rm", "-f", ZAP_CONTAINER], capture_output=True)
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
            f"[bold]RAM:[/bold] {self.memory}  "
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
            warn("\nInterrumpido — intentando guardar reportes parciales ...")
            try:
                self.collect_and_report()
            except Exception:
                pass
            exit_code = 130
        except RuntimeError as e:
            # Contenedor muerto — intentar reportes de todas formas
            err(f"Error de runtime: {e}")
            warn("Intentando generar reportes con datos disponibles ...")
            try:
                self.collect_and_report()
                self.print_summary()
            except Exception as e2:
                err(f"Reporte parcial también falló: {e2}")
            exit_code = 1
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
        description="ZAP Full Scan Automation v4.0 — github.com/iric-Sauldc",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Básico
  python3 zap_fullscan.py --target https://staging.miapp.com

  # Completo — más RAM para evitar OOM en scans largos
  python3 zap_fullscan.py \\
    --target   https://staging.miapp.com \\
    --login    https://staging.miapp.com/login \\
    --user     admin@miapp.com \\
    --password "MiPass123" \\
    --output   ./mis-reportes \\
    --timeout  120 \\
    --memory   6g \\
    --keep

  # Si el contenedor murió: re-ejecutar SOLO reportes con checkpoint
  python3 zap_fullscan.py --target https://staging.miapp.com --no-docker
        """
    )
    p.add_argument("--target",    required=True,           help="URL objetivo")
    p.add_argument("--login",     default=None,            help="URL de login")
    p.add_argument("--user",      default=None,            help="Usuario")
    p.add_argument("--password",  default=None,            help="Contraseña")
    p.add_argument("--openapi",   default=None,            help="Ruta al spec OpenAPI")
    p.add_argument("--output",    default="./zap-reports", help="Directorio de salida")
    p.add_argument("--timeout",   type=int, default=90,    help="Timeout escaneo activo (min)")
    p.add_argument("--threads",   type=int, default=4,     help="Hilos del scanner")
    p.add_argument("--memory",    default="4g",
                   help="Límite de RAM para Docker (default: 4g). Aumentar si hay OOM.")
    p.add_argument("--no-docker", action="store_true",
                   help="ZAP ya está corriendo — no usar Docker")
    p.add_argument("--keep",      action="store_true",
                   help="NO borrar el contenedor Docker al finalizar")
    return p.parse_args()


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    args = parse_args()
    sys.exit(ZAPScanner(args).run())
