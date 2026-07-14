#!/usr/bin/env bash
# Vulnerability Feed Aggregator — avvio + configurazione
#
# Uso:
#   ./start.sh                 primo avvio: wizard, poi lancia
#   ./start.sh                 avvio normale se config.json esiste
#   ./start.sh update          modifica configurazione esistente via CLI
#   ./start.sh --no-supabase   salta Supabase (qualunque altro arg combinabile)
#   PORT=9000 ./start.sh       porta diversa per FastAPI
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
WITH_SUPABASE=1
MODE="normal"
LAUNCH_APP=1
CONFIG_FILE="config.json"

for _arg in "$@"; do
  case "$_arg" in
    update)        MODE="update"   ;;
    --no-supabase) WITH_SUPABASE=0 ;;
  esac
done

# ── Preflight: dipendenze di sistema richieste da wizard/encdec/venv ─────────
# Se mancano, tenta l'installazione automatica col package manager della
# distro (apt/dnf/yum/apk/pacman/zypper). Fallback: hint manuale.

_pkg_mgr() {
  local _m
  for _m in apt-get dnf yum apk pacman zypper; do
    command -v "$_m" >/dev/null 2>&1 && { echo "$_m"; return 0; }
  done
  return 1
}

_pkg_map() {
  # _pkg_map MGR nome-logico → nome pacchetto per quel manager.
  # I nomi logici usati nello script sono quelli Debian.
  local _mgr="$1" _p="$2"
  case "$_mgr:$_p" in
    apt-get:*)                    echo "$_p" ;;
    pacman:python3|pacman:python3-venv)
                                  echo "python" ;;
    *:python3-venv)               echo "python3" ;;  # venv incluso fuori da Debian
    dnf:golang|yum:golang)        echo "golang" ;;
    *:golang)                     echo "go" ;;
    dnf:docker.io|yum:docker.io)  echo "moby-engine" ;;
    *:docker.io)                  echo "docker" ;;
    apk:docker-compose-plugin|apk:docker-compose-v2)
                                  echo "docker-cli-compose" ;;
    *:docker-compose-plugin|*:docker-compose-v2)
                                  echo "docker-compose" ;;
    *)                            echo "$_p" ;;
  esac
}

_pkg_install() {
  # _pkg_install pkg... (nomi logici stile Debian) → true se installazione riuscita
  local _mgr _sudo="" _p _pkgs=()
  if ! _mgr="$(_pkg_mgr)"; then
    printf 'No known package manager (apt/dnf/yum/apk/pacman/zypper) — install manually: %s\n' "$*" >&2
    return 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      _sudo="sudo"
    else
      printf 'Root privileges required and sudo is not installed — run as root: %s install %s\n' "$_mgr" "$*" >&2
      return 1
    fi
  fi
  for _p in "$@"; do _pkgs+=("$(_pkg_map "$_mgr" "$_p")"); done
  printf '==> auto-installing (%s): %s\n' "$_mgr" "${_pkgs[*]}" >&2
  case "$_mgr" in
    apt-get) $_sudo apt-get update -qq >&2 || true
             $_sudo apt-get install -y "${_pkgs[@]}" >&2 ;;
    dnf|yum) $_sudo "$_mgr" install -y "${_pkgs[@]}" >&2 ;;
    apk)     $_sudo apk add "${_pkgs[@]}" >&2 ;;
    pacman)  $_sudo pacman -Sy --noconfirm "${_pkgs[@]}" >&2 ;;
    zypper)  $_sudo zypper --non-interactive install "${_pkgs[@]}" >&2 ;;
  esac
}

# retrocompatibilità con i call-site esistenti
_apt_install() { _pkg_install "$@"; }

_install_go_tarball() {
  # Installa l'ultima release ufficiale di Go in /usr/local/go.
  # Fallback quando il package manager non offre Go >= 1.21 (es. Debian 12).
  local _sudo="" _v _arch _tmp
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && _sudo="sudo" || return 1
  fi
  case "$(uname -m)" in
    x86_64)        _arch=amd64 ;;
    aarch64|arm64) _arch=arm64 ;;
    *)             return 1 ;;
  esac
  _v=$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1)
  case "$_v" in go[0-9]*) ;; *) return 1 ;; esac   # sanity: atteso "go1.XX.Y"
  printf '==> installing %s from go.dev into /usr/local/go\n' "$_v" >&2
  _tmp=$(mktemp)
  curl -fsSL "https://go.dev/dl/${_v}.linux-${_arch}.tar.gz" -o "$_tmp" || { rm -f "$_tmp"; return 1; }
  $_sudo rm -rf /usr/local/go
  $_sudo tar -C /usr/local -xzf "$_tmp" || { rm -f "$_tmp"; return 1; }
  rm -f "$_tmp"
  export PATH="/usr/local/go/bin:$PATH"
  hash -r 2>/dev/null || true   # invalida path cache di bash (es. /usr/bin/go di apt)
}

_install_compose_plugin() {
  # Installa il plugin 'docker compose' v2 da GitHub releases.
  # Fallback quando il package manager non lo offre (es. Debian 12 senza repo Docker).
  local _sudo="" _arch _dir=/usr/local/lib/docker/cli-plugins
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && _sudo="sudo" || return 1
  fi
  case "$(uname -m)" in
    x86_64)        _arch=x86_64 ;;
    aarch64|arm64) _arch=aarch64 ;;
    *)             return 1 ;;
  esac
  printf '==> installing docker compose v2 from GitHub releases into %s\n' "$_dir" >&2
  $_sudo mkdir -p "$_dir"
  $_sudo curl -fsSL \
    "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${_arch}" \
    -o "$_dir/docker-compose" || return 1
  $_sudo chmod +x "$_dir/docker-compose"
}

_preflight() {
  local _missing=()
  for _b in python3 curl git; do
    command -v "$_b" >/dev/null 2>&1 || _missing+=("$_b")
  done
  # 'import venv' passa anche senza python3-venv (Debian): serve ensurepip
  command -v python3 >/dev/null 2>&1 && ! python3 -c 'import venv, ensurepip' 2>/dev/null \
    && _missing+=("python3-venv")
  [ "${#_missing[@]}" -eq 0 ] && return 0

  printf 'Missing system dependencies: %s\n' "${_missing[*]}" >&2
  if ! _apt_install "${_missing[@]}"; then
    printf 'ERROR: installation failed. Install manually with your distro package manager: %s\n' "${_missing[*]}" >&2
    exit 1
  fi
  # ricontrollo post-install
  for _b in python3 curl git; do
    if ! command -v "$_b" >/dev/null 2>&1; then
      printf 'ERROR: %s still missing after installation.\n' "$_b" >&2
      exit 1
    fi
  done
  if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
    printf 'ERROR: venv/ensurepip module still missing (python3-venv).\n' >&2
    exit 1
  fi
  printf '✓ Dependencies installed.\n' >&2
}
_preflight

# ── Ollama: installazione, avvio e verifica modello (LLM di default) ─────────
# Usata dal wizard AI e dal precheck a ogni avvio. Se URL locale: installa
# ollama (script ufficiale) e avvia il server se serve. In ogni caso: pull del
# modello se assente e verifica finale via /api/tags.

_ensure_ollama() {
  # _ensure_ollama URL MODEL [INSTALL]
  # INSTALL=1 (default): installa ollama se assente. INSTALL=0: non installare
  # (scelta dell'utente nel wizard, salvata in ai.ollama_autoinstall).
  local _url="$1" _model="$2" _install="${3:-1}"
  local _base="${_url%/api/generate}"
  local _is_local=0
  case "$_base" in *localhost*|*127.0.0.1*) _is_local=1 ;; esac

  # URL locale + binario assente -> installazione (script ufficiale), se consentita
  if [ "$_is_local" = "1" ] && ! command -v ollama >/dev/null 2>&1; then
    if [ "$_install" = "1" ]; then
      printf '  Ollama not installed — installing (official ollama.com script, sudo required).\n' >&2
      # l'installer ollama richiede zstd per estrarre l'archivio
      command -v zstd >/dev/null 2>&1 || _pkg_install zstd || true
      curl -fsSL https://ollama.com/install.sh | sh >&2 \
        || printf '  ⚠  Installation failed — install manually: https://ollama.com/download\n' >&2
    else
      printf '  ⚠  Ollama missing and auto-install disabled (wizard choice).\n' >&2
      printf '     To change: ./start.sh update -> AI provider.\n' >&2
    fi
  fi

  # server locale installato ma non attivo -> avvialo in background
  if [ "$_is_local" = "1" ] && command -v ollama >/dev/null 2>&1 \
     && ! curl -sf --max-time 3 "$_base" >/dev/null 2>&1; then
    printf '  ==> starting ollama serve (background)...\n' >&2
    (ollama serve >/dev/null 2>&1 &)
    sleep 2
  fi

  # verifica raggiungibilità + presenza modello (via /api/tags)
  if curl -sf --max-time 3 "$_base" >/dev/null 2>&1; then
    printf '  ✓  Ollama reachable.\n' >&2
    if ! curl -sf --max-time 5 "$_base/api/tags" 2>/dev/null | grep -q "\"$_model"; then
      if command -v ollama >/dev/null 2>&1; then
        printf '  ==> ollama pull %s\n' "$_model" >&2
        ollama pull "$_model" >&2 \
          || printf '  ⚠  pull failed — run manually: ollama pull %s\n' "$_model" >&2
      else
        printf '  ⚠  Model missing on remote server: run "ollama pull %s" there.\n' "$_model" >&2
      fi
    fi
    if curl -sf --max-time 5 "$_base/api/tags" 2>/dev/null | grep -q "\"$_model"; then
      printf '  ✓  Model %s present.\n' "$_model" >&2
    else
      printf '  ⚠  Model %s NOT verified — AI features will fail until it is available.\n' "$_model" >&2
    fi
  else
    printf '  ⚠  Ollama not reachable at %s\n     Make sure it is running before using AI features.\n' "$_base" >&2
  fi
}

# ── UI helpers ────────────────────────────────────────────────────────────────

_ask() {
  # _ask "Prompt" "default" → stampa la risposta su stdout
  printf "  %s [%s]: " "$1" "$2" >&2
  read -r _ans
  printf '%s' "${_ans:-$2}"
}

_ask_secret() {
  printf "  %s: " "$1" >&2
  read -rs _secret
  printf '\n' >&2
  printf '%s' "$_secret"
}

_choose() {
  # _choose "Titolo" opt1 opt2 ... → stampa numero scelto (1-based) su stdout
  local _title="$1"; shift
  local _opts=("$@")
  printf '\n' >&2
  printf '  %s\n' "$_title" >&2
  local _i=1
  for _o in "${_opts[@]}"; do
    printf '    %d) %s\n' "$_i" "$_o" >&2
    ((_i++))
  done
  while true; do
    printf '  Choice [1]: ' >&2
    read -r _sel
    _sel="${_sel:-1}"
    if [[ "$_sel" =~ ^[0-9]+$ ]] && [ "$_sel" -ge 1 ] && [ "$_sel" -le "${#_opts[@]}" ]; then
      printf '%s' "$_sel"
      return
    fi
    printf '  Invalid choice.\n' >&2
  done
}

_sep() { printf '\n  %-44s\n' "── $1 " | tr ' ' '─' | head -c 48; printf '\n' >&2; }

# ── JSON helpers (python3 di sistema, non serve il venv) ──────────────────────

_json_read() {
  # _json_read section key
  python3 -c "
import json, pathlib
d = {}
p = pathlib.Path('$CONFIG_FILE')
if p.exists():
    try: d = json.loads(p.read_text())
    except Exception: pass
print(d.get('$1', {}).get('$2', ''))
"
}

_json_write() {
  # _json_write section.key=value ...
  python3 - "$@" <<'PYEOF'
import json, sys, pathlib

CONFIG = pathlib.Path("config.json")
DEFAULTS = {
    "search_engine": {
        "provider": "duckduckgo", "serper_api_key": "",
        "min_osint_hits": 2, "min_osint_query": 4,
    },
    "ai": {
        "provider": "ollama",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:7b", "ollama_autoinstall": True,
        "claude_api_key": "", "claude_model": "claude-haiku-4-5-20251001",
        "summary_timeout": 60, "advisory_timeout": 60,
        "extract_timeout": 30, "remediation_timeout": 30,
        "triage_timeout": 60, "ai_remediation": False,
    },
    "scanner": {"simulate_auth": True, "socket_timeout": 4},
    "osv": {"url": "https://api.osv.dev/v1/query", "timeout": 15},
}
data = {k: dict(v) for k, v in DEFAULTS.items()}
if CONFIG.exists():
    try:
        raw = json.loads(CONFIG.read_text())
        for sec in DEFAULTS:
            data[sec].update(raw.get(sec, {}))
    except Exception:
        pass

for arg in sys.argv[1:]:
    sec, rest = arg.split(".", 1)
    key, val  = rest.split("=", 1)
    if val.lower() in ("true", "false"):
        val = val.lower() == "true"
    else:
        try:    val = int(val)
        except ValueError:
            try: val = float(val)
            except ValueError: pass
    data[sec][key] = val

CONFIG.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
}

# ── Wizard: AI ────────────────────────────────────────────────────────────────

_wizard_ai() {
  _sep "AI Configuration" >&2
  local _c
  _c=$(_choose "AI model type:" \
    "Local  — Ollama (model runs on your machine)" \
    "Remote — Claude API (Anthropic, requires API key)")

  if [ "$_c" = "1" ]; then
    local _url _model _install=1
    _url=$(_ask "Ollama URL" "http://localhost:11434/api/generate")

    # scelta modello LLM: default qwen2.5:7b, alternative comuni o nome libero
    local _mc
    _mc=$(_choose "Which LLM model to use? (default: qwen2.5:7b)" \
      "qwen2.5:7b   — Qwen 2.5 7B (recommended, ~4.7 GB)" \
      "llama3.1:8b  — Meta Llama 3.1 8B (~4.9 GB)" \
      "mistral:7b   — Mistral 7B (~4.1 GB)" \
      "Other        — enter the model name (e.g. gemma2:9b)")
    case "$_mc" in
      1) _model="qwen2.5:7b"  ;;
      2) _model="llama3.1:8b" ;;
      3) _model="mistral:7b"  ;;
      4) _model=$(_ask "Ollama model name" "qwen2.5:7b") ;;
    esac

    # se URL locale e ollama assente: chiedi se installarlo
    case "$_url" in
      *localhost*|*127.0.0.1*)
        if ! command -v ollama >/dev/null 2>&1; then
          local _yn
          _yn=$(_ask "Ollama is not installed. Install it now? (y/n)" "y")
          case "$_yn" in
            s|S|y|Y) _install=1 ;;
            *)       _install=0
                     printf '  ⚠  Installation skipped — AI features inactive while Ollama is missing.\n' >&2 ;;
          esac
        fi
        ;;
    esac

    local _auto="false"; [ "$_install" = "1" ] && _auto="true"
    _json_write "ai.provider=ollama" "ai.ollama_url=$_url" \
                "ai.ollama_model=$_model" "ai.ollama_autoinstall=$_auto"
    printf '  ✓  Provider: Ollama (%s)\n' "$_model" >&2
    _ensure_ollama "$_url" "$_model" "$_install"
  else
    local _key _model
    _key=$(_ask_secret "Claude API Key")
    _model=$(_ask "Claude model" "claude-haiku-4-5-20251001")
    _json_write "ai.provider=claude" "ai.claude_api_key=$_key" "ai.claude_model=$_model"
    printf '  ✓  Provider: Claude API (%s)\n' "$_model" >&2
  fi
}

# ── Wizard: Search Engine ─────────────────────────────────────────────────────

_wizard_search() {
  _sep "Search Engine Configuration" >&2
  local _c
  _c=$(_choose "OSINT search engine:" \
    "DuckDuckGo — free, no API key" \
    "Serper     — Google results, requires API key")

  if [ "$_c" = "1" ]; then
    _json_write "search_engine.provider=duckduckgo"
    printf '  ✓  Search engine: DuckDuckGo\n' >&2
  else
    local _key
    _key=$(_ask_secret "Serper API Key")
    _json_write "search_engine.provider=serper" "search_engine.serper_api_key=$_key"
    printf '  ✓  Search engine: Serper\n' >&2
  fi
}

# ── Helper: aggiunta asset all'inventario Supabase (cifrata/chiaro/no) ────────

_add_to_assets() {
  # _add_to_assets IP OSTYPE OSVER
  local _ip="$1" _os="$2" _osver="$3"
  local _add
  _add=$(_choose "Add to asset inventory?" \
    "Yes — add with encrypted credentials" \
    "Yes — add with plaintext password" \
    "No")
  [ "$_add" = "3" ] && return
  local _stored_pw="admin"
  if [ "$_add" = "1" ]; then
    if [ -x "${ENCDEC_BIN:-}" ]; then
      local _enc
      _enc=$("$ENCDEC_BIN" ENC "admin" 2>/dev/null | sed 's/^encrypted : //')
      if [ -n "$_enc" ]; then
        _stored_pw="ENC:$_enc"
      else
        printf '  ⚠  Encryption failed — password stored in plaintext.\n' >&2
      fi
    else
      printf '  ⚠  Encryption not configured (encdec) — password stored in plaintext.\n' >&2
    fi
  fi
  # Inserimento nella tabella 'assets' via PostgREST (Supabase locale).
  local _sb_url="${SUPABASE_URL:-http://localhost:8001}"
  local _sb_key="${SUPABASE_SERVICE_KEY:-}"
  if [ -z "$_sb_key" ] && [ -f supabase/.env ]; then
    _sb_key=$(grep -m1 '^SERVICE_ROLE_KEY=' supabase/.env | cut -d= -f2-)
  fi
  local _payload
  _payload=$(printf '{"ip":"%s","username":"admin","password":"%s","os_type":"%s","os_major_version":"%s","enabled":true}' \
    "$_ip" "$_stored_pw" "$_os" "$_osver")
  if curl -sf -X POST "$_sb_url/rest/v1/assets" \
       -H "apikey: $_sb_key" -H "Authorization: Bearer $_sb_key" \
       -H "Content-Type: application/json" \
       -d "$_payload" >/dev/null 2>&1; then
    printf '  ✓  Added to inventory (Supabase): %s (os=%s)\n' "$_ip" "$_os" >&2
  else
    printf '  ⚠  Supabase not reachable — asset NOT added: %s\n' "$_ip" >&2
  fi
}

# ── Wizard: scelta macchina di test (Linux | Windows) ─────────────────────────

_wizard_test_machine() {
  _sep "Test machine (Docker)" >&2
  if ! docker info >/dev/null 2>&1; then
    printf '  ⚠  Docker not running — wizard skipped.\n' >&2
    return
  fi
  local _c
  _c=$(_choose "Which test machine do you want to create?" \
    "Linux   — Ubuntu 20.04 + SSH + Python 3.6 (outdated)" \
    "Windows — Win 11 (KVM) + Notepad++ 7.8.1 + PuTTY 0.70 (vulnerable)" \
    "None    — skip")
  case "$_c" in
    1) _wizard_test_machine_linux   ;;
    2) _wizard_test_machine_windows ;;
    *) return ;;
  esac
}

# ── Wizard: macchina Linux Docker di test ────────────────────────────────────

_wizard_test_machine_linux() {
  _sep "Linux test machine (Docker)" >&2

  local _dir="$PWD/docker-test-machine"
  mkdir -p "$_dir"

  cat > "$_dir/Dockerfile" << 'DOCKEREOF'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server sudo software-properties-common gnupg binutils && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.6 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash admin && \
    echo 'admin:admin' | chpasswd && \
    adduser admin sudo

RUN mkdir /var/run/sshd && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
DOCKEREOF

  printf '\n  ==> building vuln-test-linux image (ubuntu:20.04 + python3.6 + sshd)...\n' >&2
  docker build -t vuln-test-linux "$_dir" >&2 || {
    printf '  ERROR: image build failed.\n' >&2; return
  }

  docker rm -f vuln-test-linux-1 >/dev/null 2>&1 || true

  printf '  ==> starting container vuln-test-linux-1...\n' >&2
  docker run -d --name vuln-test-linux-1 vuln-test-linux >/dev/null || {
    printf '  ERROR: container start failed.\n' >&2; return
  }

  sleep 1
  local _ip
  _ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-test-linux-1 2>/dev/null)

  printf '\n  ✓  Container started\n' >&2
  printf '     IP  : %s\n' "$_ip" >&2
  printf '     SSH : ssh admin@%s  (password: admin)\n' "$_ip" >&2
  printf '     Test: ssh admin@%s python3.6 --version\n\n' "$_ip" >&2

  if [ -n "$_ip" ]; then
    _add_to_assets "$_ip" linux ""
  fi
}

# ── Guida: abilitare la virtualizzazione (SVM/VT-x) nel BIOS/UEFI ────────────
# Stampata SOLO quando KVM non e' attivo (vedi _wizard_test_machine_windows).

_bios_virt_help() {
  local _vendor="${1:-VT-x / AMD-V}"
  printf '\n  >> Enable virtualization in BIOS/UEFI (%s):\n' "$_vendor" >&2
  printf '     1. FULLY restart the PC (not suspend).\n' >&2
  printf '     2. At power-on press F2 (Lenovo: F2 or Fn+F2; alternatively the\n' >&2
  printf '        "Novo" pinhole/button -> "BIOS Setup").\n' >&2
  printf '     3. Go to "Configuration" (or "Advanced").\n' >&2
  printf '     4. Set "SVM Mode" (alias: AMD-V / Virtualization / VT-x) = Enabled.\n' >&2
  printf '     5. F10 -> Save and Exit -> confirm. Let the system restart.\n\n' >&2
}

# ── Wizard: macchina Windows di test (Docker + KVM, dockurr/windows) ──────────
# Windows non gira come container nativo su Linux: si usa dockurr/windows, che
# avvia una VM Windows via QEMU/KVM dentro un container. Richiede /dev/kvm.
# La VM espone SSH (OpenSSH) per la scansione autenticata PowerShell e installa
# versioni vulnerabili di Notepad++ e PuTTY tramite gli script in ./oem.

_wizard_test_machine_windows() {
  _sep "Windows test machine (Docker + KVM)" >&2

  # KVM non attivo -> la VM Windows non puo' partire. Mostra una guida coerente
  # (compresa l'abilitazione della virtualizzazione nel BIOS) SOLO in questo caso.
  if [ ! -e /dev/kvm ]; then
    local _mod="kvm_intel" _vendor="VT-x"
    if grep -qi "AuthenticAMD" /proc/cpuinfo; then _mod="kvm_amd"; _vendor="AMD-V (SVM)"; fi

    printf '  ⚠  KVM not active: /dev/kvm missing. The Windows VM cannot start.\n' >&2
    printf '     (Native Windows nanoserver/servercore does NOT run on a Linux Docker host;\n' >&2
    printf '      a real VM via QEMU/KVM is required, which needs HW virtualization.)\n\n' >&2

    if ! grep -qiE "vmx|svm" /proc/cpuinfo; then
      # Caso A: nessun flag -> virtualizzazione spenta a livello BIOS.
      printf '  The CPU exposes no virtualization flag: it is DISABLED in the BIOS.\n' >&2
      _bios_virt_help "$_vendor"
    else
      # Caso B: flag presente ma /dev/kvm assente -> modulo non caricato OPPURE
      # virtualizzazione bloccata/lockata nel BIOS (modprobe: "Operation not supported").
      printf '  Step 1 — load the KVM module:\n' >&2
      printf '       sudo modprobe %s\n' "$_mod" >&2
      printf '       ls -l /dev/kvm                 # must appear\n\n' >&2
      printf '  If "modprobe" says "Operation not supported", virtualization is\n' >&2
      printf '  locked in the BIOS (flag visible but SVM/VT-x locked): enable it.\n' >&2
      _bios_virt_help "$_vendor"
      printf '  Step 2 — make it persistent and grant permissions:\n' >&2
      printf '       echo "%s" | sudo tee /etc/modules-load.d/kvm.conf\n' "$_mod" >&2
      printf '       sudo usermod -aG kvm "$USER"   # then logout/login\n\n' >&2
    fi

    printf '  Then retry:  ./start.sh update  ->  3  ->  2 (Windows)\n' >&2
    printf '  Alternatively, without BIOS: software emulation (slow) by setting\n' >&2
    printf '  KVM:"N" in the compose file, or an external Windows host (see README).\n' >&2
    return
  fi

  local _dir="$PWD/docker-test-machine-windows"
  mkdir -p "$_dir/oem"

  # docker-compose: VM Windows 11, utente admin/admin, SSH (22) e RDP (3389).
  cat > "$_dir/compose.yml" << 'COMPOSEEOF'
services:
  windows:
    image: dockurr/windows
    container_name: vuln-test-windows-1
    environment:
      VERSION: "11"
      USERNAME: "admin"
      PASSWORD: "admin"
      RAM_SIZE: "4G"
      CPU_CORES: "2"
    devices:
      - /dev/kvm
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    ports:
      - "8006:8006/tcp"   # viewer web installazione dockurr
      - "3389:3389/tcp"   # RDP
      - "2222:22/tcp"     # SSH (host:2222 -> guest:22)
    volumes:
      - ./storage:/storage
      - ./oem:/oem        # script eseguiti al primo boot di Windows
    stop_grace_period: 2m
    restart: on-failure
COMPOSEEOF

  # Script post-install (eseguito da dockurr al primo boot): abilita OpenSSH con
  # shell PowerShell e installa Notepad++ 7.8.1 + PuTTY 0.70 (vulnerabili).
  cat > "$_dir/oem/install.bat" << 'BATEOF'
@echo off
REM --- OpenSSH Server con shell PowerShell (per winget / Get-ItemProperty) ---
powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
powershell -Command "Set-Service -Name sshd -StartupType Automatic; Start-Service sshd"
powershell -Command "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force"

REM --- Notepad++ 7.8.1 (vulnerabile) ---
powershell -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.8.1/npp.7.8.1.Installer.x64.exe' -OutFile C:\npp.exe"
C:\npp.exe /S

REM --- PuTTY 0.70 (vulnerabile) ---
powershell -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://the.earth.li/~sgtatham/putty/0.70/w64/putty-64bit-0.70-installer.msi' -OutFile C:\putty.msi"
msiexec /i C:\putty.msi /quiet /norestart
BATEOF

  docker rm -f vuln-test-windows-1 >/dev/null 2>&1 || true

  printf '\n  ==> starting Windows VM (dockurr/windows). The first boot downloads and\n' >&2
  printf '      installs Windows: it may take quite a few minutes.\n' >&2
  ( cd "$_dir" && docker compose up -d ) >&2 || {
    printf '  ERROR: Windows container start failed.\n' >&2; return
  }

  sleep 2
  local _ip
  _ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-test-windows-1 2>/dev/null)

  printf '\n  ✓  Windows container started (installation in progress)\n' >&2
  printf '     IP   : %s\n' "$_ip" >&2
  printf '     RDP  : localhost:3389        (admin / admin)\n' >&2
  printf '     SSH  : ssh admin@%s     (password: admin, after install)\n' "$_ip" >&2
  printf '     Web  : http://localhost:8006 (dockurr install viewer)\n\n' >&2
  printf '  Note: authenticated scanning only works once installation completes\n' >&2
  printf '        (OpenSSH active + Notepad++/PuTTY installed).\n' >&2

  if [ -n "$_ip" ]; then
    _add_to_assets "$_ip" windows 11
  fi
}

# ── Aggiornamento applicazione (check tag GitHub + download sorgenti) ────────

GITHUB_REPO="${VFA_GITHUB_REPO:-daniloritarossi/vuln.scan.io}"

_local_version() {
  # Tag base locale: 'v1.0.11-alfa-3-gabc' -> 'v1.0.11-alfa'. 'dev' se niente git.
  git describe --tags --always 2>/dev/null | sed -E 's/-[0-9]+-g[0-9a-f]+$//' || printf 'dev'
}

_latest_version() {
  # Tag piu' recente su GitHub (ordinato per versione). Vuoto se irraggiungibile.
  curl -fsS --max-time 8 \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${GITHUB_REPO}/tags?per_page=30" 2>/dev/null \
  | python3 -c "
import json, re, sys
try:
    tags = [t['name'] for t in json.load(sys.stdin)]
except Exception:
    sys.exit(0)
def ver(t):
    m = re.match(r'v?(\d+)\.(\d+)(?:\.(\d+))?', t)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None
parsed = [(ver(t), t) for t in tags if ver(t)]
if parsed:
    print(max(parsed)[1])
"
}

_download_update() {
  # Scarica i sorgenti del tag indicato e li applica alla directory corrente.
  # Preferisce git (storia + rollback); fallback tarball GitHub se .git assente.
  # I file runtime (config.json, .venv, .encdec, segreti, dati Supabase) NON
  # vengono toccati in entrambi i percorsi.
  local _tag="$1"
  if [ -d .git ]; then
    printf '  ==> git fetch --tags && checkout %s\n' "$_tag" >&2
    if ! git diff --quiet 2>/dev/null; then
      printf '  WARNING: uncommitted local changes. Update cancelled.\n' >&2
      printf '  Commit or discard the changes, then retry.\n' >&2
      return 1
    fi
    git fetch --tags origin >&2 || { printf '  ERROR: git fetch failed.\n' >&2; return 1; }
    git checkout "$_tag" >&2 || { printf '  ERROR: checkout %s failed.\n' "$_tag" >&2; return 1; }
  else
    printf '  ==> downloading tarball %s from GitHub...\n' "$_tag" >&2
    local _tmp
    _tmp=$(mktemp -d)
    if ! curl -fsSL --max-time 120 \
        "https://github.com/${GITHUB_REPO}/archive/refs/tags/${_tag}.tar.gz" \
        -o "$_tmp/src.tar.gz"; then
      printf '  ERROR: download failed.\n' >&2; rm -rf "$_tmp"; return 1
    fi
    tar -xzf "$_tmp/src.tar.gz" -C "$_tmp" || { rm -rf "$_tmp"; return 1; }
    local _srcdir
    _srcdir=$(find "$_tmp" -maxdepth 1 -mindepth 1 -type d | head -1)
    printf '  ==> applying sources (runtime files preserved)...\n' >&2
    rsync -a \
      --exclude 'config.json' \
      --exclude '.venv/' \
      --exclude '.encdec/' \
      --exclude '.vfa_auth_secret' \
      --exclude 'assets.txt*' \
      --exclude 'supabase/volumes/db/data/' \
      --exclude '*.log' --exclude '*.pid' \
      "$_srcdir/" ./ || { rm -rf "$_tmp"; return 1; }
    rm -rf "$_tmp"
  fi
  return 0
}

_check_app_update() {
  _sep "Update Check" >&2
  local _cur _new
  _cur=$(_local_version)
  printf '  Local version   : %s\n' "$_cur" >&2
  printf '  Checking GitHub (%s)...\n' "$GITHUB_REPO" >&2
  _new=$(_latest_version)
  if [ -z "$_new" ]; then
    printf '  GitHub unreachable or no tags found.\n' >&2
    return
  fi
  printf '  Latest version  : %s\n' "$_new" >&2
  if [ "$_new" = "$_cur" ]; then
    printf '\n  ✓ You are already on the latest version.\n' >&2
    return
  fi
  printf '\n  New version available: %s -> %s\n' "$_cur" "$_new" >&2
  local _ok
  _ok=$(_ask "Download and install now? (y/n)" "y")
  case "$_ok" in
    s|S|y|Y)
      if _download_update "$_new"; then
        printf '\n  ✓ Updated to %s.\n' "$_new" >&2
        printf '  Relaunch with ./start.sh to apply (dependencies and DB schema\n' >&2
        printf '  are realigned automatically at startup).\n' >&2
      fi
      ;;
    *) printf '  Update cancelled.\n' >&2 ;;
  esac
}

# ── Update menu ───────────────────────────────────────────────────────────────

_update_menu() {
  while true; do
    _sep "Edit Configuration" >&2
    local _ai _se
    _ai=$(_json_read ai provider)
    _se=$(_json_read search_engine provider)
    printf '  Current AI     : %s\n' "$_ai" >&2
    printf '  Current search : %s\n\n' "$_se" >&2

    local _c
    _c=$(_choose "What do you want to change?" \
      "AI provider (local/remote)" \
      "Search engine (DuckDuckGo/Serper)" \
      "Docker test machine (Linux/Windows)" \
      "Check application updates (GitHub)" \
      "Save and exit (configuration only, does not launch)" \
      "Save and launch the app")
    case "$_c" in
      1) _wizard_ai           ;;
      2) _wizard_search        ;;
      3) _wizard_test_machine  ;;
      4) _check_app_update     ;;
      5) LAUNCH_APP=0; break  ;;
      6) break                ;;
    esac
  done
}

# ── encdec: setup cifratura password ─────────────────────────────────────────
# Il segreto viene chiesto UNA SOLA VOLTA, compilato dentro il binario tramite
# patch di defaultSecretKeyPrefix in lib/lib.go, poi nessun file o env var lo
# contiene — il segreto esiste solo nel binario .encdec/encdec.

ENCDEC_BIN="$PWD/.encdec/encdec"
ENCDEC_DIR="$PWD/.encdec"

if [ ! -x "$ENCDEC_BIN" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════════╗\n'
  printf '  ║   encdec — password encryption setup         ║\n'
  printf '  ╚══════════════════════════════════════════════╝\n'
  printf '\n  encdec binary not found. One-time operation: compilation.\n'
  printf '  The secret prefix will be compiled into the binary and will\n'
  printf '  never be asked again nor stored on disk.\n\n'

  _go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local _maj _min
    read -r _maj _min <<< "$(go version | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1 \2/')"
    [ "$_maj" -gt 1 ] || { [ "$_maj" -eq 1 ] && [ "$_min" -ge 21 ]; }
  }
  if ! _go_ok; then
    printf '  Go >= 1.21 not found — trying automatic install (package manager).\n' >&2
    _apt_install golang || true
    if ! _go_ok; then
      printf '  Go from package manager missing or too old — trying official go.dev tarball.\n' >&2
      _install_go_tarball || true
    fi
    if ! _go_ok; then
      printf '  ERROR: Go >= 1.21 not available. Install manually from https://go.dev/dl/\n' >&2
      exit 1
    fi
  fi

  _PFX1=$(_ask_secret "Secret prefix for encryption (entered only once)")
  _PFX2=$(_ask_secret "Confirm secret prefix")
  if [ "$_PFX1" != "$_PFX2" ]; then
    printf '\n  ERROR: prefixes do not match.\n' >&2
    unset _PFX1 _PFX2
    exit 1
  fi

  mkdir -p "$ENCDEC_DIR"
  _TMP_ENCDEC=$(mktemp -d)

  printf '\n  ==> cloning encdec...\n' >&2
  git clone --depth 1 https://github.com/daniloritarossi/encdec "$_TMP_ENCDEC/encdec" >&2

  # Patch: sostituisce defaultSecretKeyPrefix con il segreto scelto
  python3 - "$_TMP_ENCDEC/encdec/lib/lib.go" "$_PFX1" << 'PYEOF'
import sys, re
path, secret = sys.argv[1], sys.argv[2]
src = open(path).read()
src = re.sub(
    r'(defaultSecretKeyPrefix\s*=\s*)"[^"]*"',
    lambda m: m.group(1) + '"' + secret.replace('\\', '\\\\').replace('"', '\\"') + '"',
    src
)
open(path, 'w').write(src)
PYEOF
  unset _PFX1 _PFX2

  printf '  ==> building encdec (secret prefix compiled in)...\n' >&2
  ( cd "$_TMP_ENCDEC/encdec" && go build -o "$ENCDEC_BIN" . ) >&2
  rm -rf "$_TMP_ENCDEC"
  printf '  ✓  encdec built with embedded secret: %s\n\n' "$ENCDEC_BIN" >&2
fi

# ── MAIN: config phase ────────────────────────────────────────────────────────

if [ "$MODE" = "update" ]; then
  if [ ! -f "$CONFIG_FILE" ]; then
    printf '\n  No config.json. Starting first-run wizard...\n\n' >&2
    _wizard_ai
    _wizard_search
    _wizard_test_machine
  else
    _update_menu
  fi
elif [ ! -f "$CONFIG_FILE" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════╗\n'
  printf '  ║  Vulnerability Feed Aggregator — Setup   ║\n'
  printf '  ╚══════════════════════════════════════════╝\n'
  printf '\n  First-time setup. Enter = default value.\n'
  _wizard_ai
  _wizard_search
  _wizard_test_machine
  printf '\n  ✓ config.json created.\n\n'
fi

[ "$LAUNCH_APP" = "0" ] && exit 0

# ── 0b) Precheck AI: ollama + LLM di default presenti a ogni avvio ────────────

AI_PROV=$(_json_read ai provider)
if [ "$AI_PROV" = "ollama" ] || [ -z "$AI_PROV" ]; then
  _OLL_URL=$(_json_read ai ollama_url)
  _OLL_MODEL=$(_json_read ai ollama_model)
  _OLL_URL="${_OLL_URL:-http://localhost:11434/api/generate}"
  _OLL_MODEL="${_OLL_MODEL:-qwen2.5:7b}"
  # rispetta la scelta fatta nel wizard (ai.ollama_autoinstall)
  _OLL_INST=1
  [ "$(_json_read ai ollama_autoinstall)" = "False" ] && _OLL_INST=0
  echo "==> AI precheck: ollama + model ${_OLL_MODEL}"
  _ensure_ollama "$_OLL_URL" "$_OLL_MODEL" "$_OLL_INST"
fi

# ── 1) Virtualenv + dipendenze ────────────────────────────────────────────────

PYBIN=".venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "==> creating virtualenv .venv"
  python3 -m venv .venv
fi
export PATH="$PWD/.venv/bin:$PATH"
echo "==> installing/updating dependencies (requirements.txt)"
"$PYBIN" -m pip install -q --upgrade pip
"$PYBIN" -m pip install -q -r requirements.txt

# ── 2) Stack Supabase (Docker) ────────────────────────────────────────────────

if [ "$WITH_SUPABASE" = "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not installed — trying automatic install (package manager)." >&2
    _apt_install docker.io || true
    if ! command -v docker >/dev/null 2>&1; then
      echo "ERROR: Docker could not be installed automatically. See https://docs.docker.com/engine/install/" >&2
      exit 1
    fi
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "==> Docker daemon stopped — trying to start it" >&2
    _sv=""; [ "$(id -u)" -ne 0 ] && _sv="sudo"
    if command -v systemctl >/dev/null 2>&1; then
      $_sv systemctl start docker >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
      $_sv rc-service docker start >/dev/null 2>&1 || true
      $_sv rc-update add docker default >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
      $_sv service docker start >/dev/null 2>&1 || true
    fi
    # attesa avvio: fino a 20s
    for _i in 1 2 3 4 5 6 7 8 9 10; do
      docker info >/dev/null 2>&1 && break
      sleep 2
    done
    # nessun init system utilizzabile (container/WSL) -> dockerd diretto
    if ! docker info >/dev/null 2>&1 && command -v dockerd >/dev/null 2>&1; then
      echo "==> no init system available — starting dockerd in background (log: /var/log/dockerd.log)" >&2
      $_sv sh -c 'nohup dockerd >/var/log/dockerd.log 2>&1 &' || true
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        docker info >/dev/null 2>&1 && break
        sleep 2
      done
    fi
    if ! docker info >/dev/null 2>&1; then
      echo "ERROR: Docker not running or missing permissions." >&2
      echo "  If the daemon is running but access is denied: sudo usermod -aG docker \$USER  (then logout/login)" >&2
      echo "  If the daemon does not start: check /var/log/dockerd.log or 'journalctl -u docker'." >&2
      if [ "$(id -u)" -eq 0 ] && [ -f /var/log/dockerd.log ] \
         && grep -q "you must be root\|Permission denied" /var/log/dockerd.log 2>/dev/null; then
        echo "" >&2
        echo "  Confined environment detected: the kernel denies iptables/nftables even to root." >&2
        echo "  You are probably in an unprivileged container (e.g. LXC). Options:" >&2
        echo "    - Proxmox LXC (from host): pct set <ID> --features nesting=1,keyctl=1  then restart the container" >&2
        echo "    - use a VM instead of a container" >&2
        echo "    - skip Docker/Supabase: ./start.sh --no-supabase" >&2
      fi
      exit 1
    fi
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "'docker compose' plugin (v2) missing — trying automatic install." >&2
    _apt_install docker-compose-plugin || _apt_install docker-compose-v2 || _install_compose_plugin || true
    if ! docker compose version >/dev/null 2>&1; then
      echo "ERROR: 'docker compose' v2 plugin could not be installed. Install the compose v2 plugin for your distro manually." >&2
      exit 1
    fi
  fi
  echo "==> starting local Supabase (Docker)"
  ( cd supabase && ./setup.sh )
else
  echo "==> skipping Supabase (--no-supabase)"
fi

# ── 3) Server FastAPI (foreground) ────────────────────────────────────────────

AI_PROV=$(_json_read ai provider)
SE_PROV=$(_json_read search_engine provider)

cat <<EOF

============================================================
  App        : http://127.0.0.1:${PORT}
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/
  AI         : ${AI_PROV}
  Search     : ${SE_PROV}
============================================================
  Ctrl+C stops the app. Supabase stays running → ./stop.sh

EOF

# Niente --reload: uvicorn entrerebbe in supabase/volumes/db/data (uid 100,
# perms 700) e crasherebbe con PermissionError.
exec "$PYBIN" -m uvicorn app:app --host 127.0.0.1 --port "${PORT}"
