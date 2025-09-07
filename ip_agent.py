from dotenv import load_dotenv
import os
import psutil
import secrets
import ipaddress
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Set, List, Tuple

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ip_agent")

def parse_bool(val: str) -> bool:
    return str(val).lower() in ("1", "true", "yes", "on")

API_USER = os.getenv("API_USER", "admin")
API_PASS = os.getenv("API_PASS", "password")
API_LISTEN_PORT = int(os.getenv("API_LISTEN_PORT", "8000"))
MONITOR_PORT = int(os.getenv("MONITOR_PORT", "22"))

COUNT_IPV4 = parse_bool(os.getenv("COUNT_IPV4", "true"))
COUNT_IPV6 = parse_bool(os.getenv("COUNT_IPV6", "true"))

TRUSTED_IPS_RAW = os.getenv("TRUSTED_IPS", "").strip()

def parse_trusted_ips(raw: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    if not raw:
        return nets
    for part in raw.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
            nets.append(net)
        except Exception:
            logger.warning("Failed to parse TRUSTED_IP entry: %s", p)
            continue
    return nets

TRUSTED_NETWORKS = parse_trusted_ips(TRUSTED_IPS_RAW)

security = HTTPBasic()
app = FastAPI(title="ip_agent", version="0.1")

@app.on_event("startup")
def _startup_log():
    if TRUSTED_NETWORKS:
        logger.info("TRUSTED_NETWORKS: %s", [str(n) for n in TRUSTED_NETWORKS])
    else:
        logger.info("TRUSTED_NETWORKS: (none configured)")
    logger.info("TRUSTED_IPS_RAW: %s", TRUSTED_IPS_RAW)

def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host
    return ""

def is_trusted_client(remote_ip: str) -> bool:
    if not TRUSTED_NETWORKS or not remote_ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(remote_ip)
    except Exception:
        return False
    for net in TRUSTED_NETWORKS:
        if ip_obj in net:
            return True
        if ip_obj.version == 6 and getattr(ip_obj, "ipv4_mapped", None) is not None:
            if ip_obj.ipv4_mapped in net:
                return True
    return False

async def verify_credentials(request: Request):
    client_ip = get_client_ip(request)
    if client_ip and is_trusted_client(client_ip):
        return "trusted:" + client_ip

    credentials: HTTPBasicCredentials = await security(request)
    correct_user = secrets.compare_digest(credentials.username, API_USER)
    correct_pass = secrets.compare_digest(credentials.password, API_PASS)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def get_connection_stats(port: int, count_ipv4: bool = True, count_ipv6: bool = True) -> Tuple[Set[str], int]:
    """
    Возвращает кортеж из множества уникальных IP и общего количества соединений
    с учётом настроек count_ipv4/count_ipv6
    """
    ips = set()
    count_all = 0
    if not (count_ipv4 or count_ipv6):
        return ips, count_all
    try:
        conns = psutil.net_connections(kind='tcp')
    except Exception:
        conns = []
    for c in conns:
        if not c.laddr:
            continue
        try:
            lport = c.laddr.port
        except Exception:
            continue
        if lport != port:
            continue
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        if not c.raddr:
            continue
        try:
            rip = c.raddr.ip
        except Exception:
            continue
        if not rip:
            continue

        if '%' in rip:
            rip = rip.split('%', 1)[0]

        try:
            ip_obj = ipaddress.ip_address(rip)
        except Exception:
            continue

        # Увеличиваем счётчик с учётом настроек IPv4/IPv6
        if ip_obj.version == 6 and getattr(ip_obj, "ipv4_mapped", None) is not None:
            mapped = str(ip_obj.ipv4_mapped)
            if not count_ipv4:
                continue
            ips.add(mapped)
            count_all += 1
            continue

        if ip_obj.version == 4:
            if not count_ipv4:
                continue
            ips.add(str(ip_obj))
            count_all += 1
            continue

        if ip_obj.version == 6:
            if not count_ipv6:
                continue
            ips.add(str(ip_obj))
            count_all += 1

    return ips, count_all

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/connections")
def connections(user: str = Depends(verify_credentials)):
    unique_ips, count_all = get_connection_stats(MONITOR_PORT, COUNT_IPV4, COUNT_IPV6)
    return {
        "count": len(unique_ips),
        "count_all": count_all,
        "ips": sorted(unique_ips),
        "port": MONITOR_PORT,
        "count_ipv4_enabled": COUNT_IPV4,
        "count_ipv6_enabled": COUNT_IPV6,
        "trusted_ips_configured": TRUSTED_IPS_RAW,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ip_agent:app", host="0.0.0.0", port=API_LISTEN_PORT, log_level="info")