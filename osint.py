"""
osint.py
--------
Estrazione del "Software Target" da una descrizione testuale di vulnerabilita'.

L'input dell'utente puo' essere libero e privo di CVE, es:
    "Remote Code Execution in Python 3.10 via HTTP component"
    "Buffer overflow affecting OpenSSH 8.4"

Strategia:
1) Estrazione LOCALE (primaria, sempre attiva): matching su un dizionario di
   prodotti noti + regex per la versione. Veloce e offline.
2) Arricchimento OSINT (opzionale): query a DuckDuckGo (HTML endpoint) con
   BeautifulSoup per confermare/identificare il prodotto quando l'estrazione
   locale fallisce. Disattivabile (e attivo solo se 'requests' e' disponibile).

L'OSINT online e' best-effort: se la rete non e' disponibile o DDG cambia
markup, il sistema ricade sull'estrazione locale senza errori.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    from bs4 import BeautifulSoup
    _NET_AVAILABLE = True
except Exception:  # pragma: no cover - dipendenze opzionali
    _NET_AVAILABLE = False


# Dizionario prodotti noti -> alias riconosciuti nel testo.
# La chiave e' il nome canonico usato dallo scanner per il fingerprinting.
KNOWN_PRODUCTS = {
    "python": ["python", "cpython", "pypi", "pip"],
    "openssh": ["openssh", "ssh", "sshd"],
    "apache": ["apache", "httpd", "apache2"],
    "nginx": ["nginx"],
    "openssl": ["openssl"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres"],
    "php": ["php"],
    "nodejs": ["node.js", "nodejs", "node"],
    "log4j": ["log4j", "log4shell"],
    "wordpress": ["wordpress", "wp"],
    "tomcat": ["tomcat", "catalina"],
    "redis": ["redis"],
    "vsftpd": ["vsftpd"],
    "exim": ["exim"],
}

# Dipendenze note per prodotto canonico. Servono a costruire il grafo
# "DETECTED PRODUCTS NETWORK": nodo centrale = prodotto, nodi figli = librerie
# da cui dipende (rilevanti per la superficie di attacco).
PRODUCT_DEPENDENCIES = {
    "python": ["openssl", "libffi", "zlib", "sqlite"],
    "openssh": ["openssl", "zlib", "pam"],
    "nginx": ["openssl", "pcre", "zlib"],
    "apache": ["openssl", "pcre", "apr"],
    "php": ["openssl", "pcre", "zlib", "libxml2"],
    "nodejs": ["openssl", "v8", "libuv", "zlib"],
    "openssl": ["zlib"],
    "mysql": ["openssl", "zlib"],
    "postgresql": ["openssl", "zlib", "readline"],
    "tomcat": ["java", "apr"],
    "redis": ["jemalloc", "lua"],
    "log4j": ["java"],
    "wordpress": ["php", "mysql"],
    "vsftpd": ["openssl", "pam"],
    "exim": ["openssl", "pcre"],
}

# Versione: numeri tipo 3.10, 8.4, 1.1.1k, 2.4.49 ...
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3}[a-z]?)\b")


@dataclass
class TargetInfo:
    """Risultato dell'identificazione del software."""
    product: Optional[str]            # nome canonico, es. "python"
    version: Optional[str]            # es. "3.10" se presente
    matched_alias: Optional[str]      # alias effettivamente trovato nel testo
    source: str                       # "local" | "osint" | "none"
    candidates: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "version": self.version,
            "matched_alias": self.matched_alias,
            "source": self.source,
            "candidates": self.candidates,
            "dependencies": PRODUCT_DEPENDENCIES.get(self.product or "", []),
        }


def extract_version(text: str) -> Optional[str]:
    """Restituisce la prima versione numerica trovata nel testo, se presente."""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def extract_local(text: str) -> TargetInfo:
    """
    Estrazione offline: cerca alias di prodotti noti nel testo (case-insensitive)
    e una eventuale versione. Ritorna il primo prodotto con match piu' lungo.
    """
    lowered = text.lower()
    best_product = None
    best_alias = None
    best_len = 0
    candidates: List[str] = []

    for product, aliases in KNOWN_PRODUCTS.items():
        for alias in aliases:
            # \b per evitare falsi positivi (es. "ssh" dentro altre parole).
            if re.search(rf"\b{re.escape(alias)}\b", lowered):
                candidates.append(product)
                if len(alias) > best_len:
                    best_len = len(alias)
                    best_product = product
                    best_alias = alias

    version = extract_version(text)
    return TargetInfo(
        product=best_product,
        version=version,
        matched_alias=best_alias,
        source="local" if best_product else "none",
        candidates=sorted(set(candidates)),
    )


def _ddg_search(query: str, timeout: int = 6) -> str:
    """
    Interroga l'endpoint HTML di DuckDuckGo e ritorna il testo dei risultati.
    Best-effort: in caso di errore ritorna stringa vuota.
    """
    if not _NET_AVAILABLE:
        return ""
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (VulnFeedAggregator OSINT)"},
            timeout=timeout,
        )
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        snippets = soup.select(".result__snippet, .result__title")
        return " ".join(s.get_text(" ", strip=True) for s in snippets)
    except Exception:
        return ""


# Quante volte il prodotto dedotto deve comparire nei risultati DDG per
# essere considerato attendibile. Evita falsi positivi su citazioni isolate
# senza pretendere (come prima) che il nome sia gia' presente nell'input:
# cosi' query come "PyPI ..." possono correttamente risolvere a "python".
_MIN_OSINT_HITS = 2


def _count_product_hits(product: str, text: str) -> int:
    """Numero di occorrenze (parola intera) degli alias del prodotto nel testo."""
    text_l = text.lower()
    total = 0
    for alias in KNOWN_PRODUCTS.get(product, [product]):
        total += len(re.findall(rf"\b{re.escape(alias)}\b", text_l))
    return total


def extract_osint(text: str) -> TargetInfo:
    """
    Arricchimento online: se l'estrazione locale non trova il prodotto,
    interroga DuckDuckGo e ri-applica il matching locale sul testo dei risultati.

    Si fida del prodotto dedotto solo se compare almeno _MIN_OSINT_HITS volte
    nei risultati (soglia anti-falsi-positivi).
    """
    results_text = _ddg_search(text)
    if not results_text:
        return TargetInfo(None, extract_version(text), None, "none")

    # Ri-usa il matching locale sul corpus restituito dalla ricerca.
    info = extract_local(results_text)
    if not info.product:
        return TargetInfo(None, extract_version(text), None, "none")

    if _count_product_hits(info.product, results_text) < _MIN_OSINT_HITS:
        return TargetInfo(None, extract_version(text), None, "none")

    info.source = "osint"
    # Versione SOLO dall'input originale: i numeri nei risultati web sono
    # spesso spuri (citazioni, anni, ecc.).
    info.version = extract_version(text)
    return info


# Lunghezza minima della query (solo alfanumerici) per fidarsi dell'OSINT.
# Sotto questa soglia un input e' troppo ambiguo (es. typo "pyp") e l'OSINT
# tenderebbe a "indovinare" un prodotto non pertinente.
_MIN_OSINT_QUERY = 4


def identify_product(text: str, use_osint: bool = True) -> TargetInfo:
    """
    Punto di ingresso unico per il backend.

    1. Prova l'estrazione locale.
    2. Se fallisce e use_osint=True, tenta l'arricchimento via DuckDuckGo, ma
       solo se la query e' abbastanza specifica. L'attendibilita' del prodotto
       dedotto e' gestita da extract_osint (soglia di occorrenze nei risultati).
    """
    local = extract_local(text)
    if local.product or not use_osint:
        return local

    # Query troppo corta/ambigua: non fidarsi dell'OSINT.
    if len(re.sub(r"[^a-z0-9]", "", text.lower())) < _MIN_OSINT_QUERY:
        return local

    return extract_osint(text)


if __name__ == "__main__":
    for sample in [
        "Remote Code Execution in Python 3.10 via HTTP component",
        "Buffer overflow affecting OpenSSH 8.4",
        "Some weird issue in nginx 1.21",
    ]:
        info = identify_product(sample, use_osint=False)
        print(f"{sample!r} -> {info.to_dict()}")
