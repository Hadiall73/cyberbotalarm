import httpx
import asyncio
import logging
from functools import lru_cache

logger = logging.getLogger("ip_intel")

TOR_EXIT_NODES: set[str] = set()
_tor_loaded = False

async def load_tor_nodes():
    global TOR_EXIT_NODES, _tor_loaded
    if _tor_loaded:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://check.torproject.org/torbulkexitlist")
            TOR_EXIT_NODES = set(r.text.strip().splitlines())
            _tor_loaded = True
            logger.info(f"Tor-Exitnodes geladen: {len(TOR_EXIT_NODES)}")
    except Exception as e:
        logger.warning(f"Tor-Liste nicht geladen: {e}")

async def get_ip_info(ip: str) -> dict:
    result = {
        "ip": ip, "country": "?", "country_code": "??",
        "city": "?", "org": "?", "isp": "?",
        "lat": 0.0, "lon": 0.0,
        "is_tor": ip in TOR_EXIT_NODES,
        "is_vpn": False, "abuse_score": 0,
        "asn": "?", "timezone": "?",
    }
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,isp,lat,lon,as,timezone,proxy,hosting")
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    result.update({
                        "country":      d.get("country", "?"),
                        "country_code": d.get("countryCode", "??"),
                        "city":         d.get("city", "?"),
                        "org":          d.get("org", "?"),
                        "isp":          d.get("isp", "?"),
                        "lat":          d.get("lat", 0.0),
                        "lon":          d.get("lon", 0.0),
                        "asn":          d.get("as", "?"),
                        "timezone":     d.get("timezone", "?"),
                        "is_vpn":       d.get("proxy", False) or d.get("hosting", False),
                    })
    except Exception as e:
        logger.warning(f"IP-Info Fehler für {ip}: {e}")
    return result

async def get_abuse_score(ip: str, api_key: str) -> int:
    if not api_key:
        return 0
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if r.status_code == 200:
                return r.json().get("data", {}).get("abuseConfidenceScore", 0)
    except Exception:
        pass
    return 0

def detect_tool(user_agent: str = "", payload: str = "", banner: str = "") -> list[str]:
    tools = []
    combined = (user_agent + payload + banner).lower()
    signatures = {
        "nmap":          ["nmap", "masscan"],
        "sqlmap":        ["sqlmap"],
        "nikto":         ["nikto"],
        "metasploit":    ["metasploit", "msfvenom", "msf"],
        "hydra":         ["hydra"],
        "zgrab":         ["zgrab"],
        "shodan":        ["shodan"],
        "mirai":         ["mirai", "/bin/busybox"],
        "curl":          ["curl/"],
        "python_scanner":["python-requests", "python-urllib"],
        "go_scanner":    ["go-http-client"],
        "masscan":       ["masscan"],
    }
    for tool, sigs in signatures.items():
        if any(s in combined for s in sigs):
            tools.append(tool)
    return tools
