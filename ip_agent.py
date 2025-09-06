from dotenv import load_dotenv
import os
import psutil
import secrets
import ipaddress
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Set

load_dotenv()

def parse_bool(val: str) -> bool:
    return str(val).lower() in ("1", "true", "yes", "on")

API_USER = os.getenv("API_USER", "admin")
API_PASS = os.getenv("API_PASS", "password")
API_LISTEN_PORT = int(os.getenv("API_LISTEN_PORT", "8000"))
MONITOR_PORT = int(os.getenv("MONITOR_PORT", "22"))

COUNT_IPV4 = parse_bool(os.getenv("COUNT_IPV4", "true"))
COUNT_IPV6 = parse_bool(os.getenv("COUNT_IPV6", "true"))

security = HTTPBasic()
app = FastAPI(title="ip_agent", version="0.1")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, API_USER)
    correct_pass = secrets.compare_digest(credentials.password, API_PASS)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def get_unique_remote_ips(port: int, count_ipv4: bool = True, count_ipv6: bool = True) -> Set[str]:
    ips = set()
    if not (count_ipv4 or count_ipv6):
        return ips
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

        if ip_obj.version == 6 and getattr(ip_obj, "ipv4_mapped", None) is not None:
            mapped = str(ip_obj.ipv4_mapped)
            if not count_ipv4:
                continue
            ips.add(mapped)
            continue

        if ip_obj.version == 4:
            if not count_ipv4:
                continue
            ips.add(str(ip_obj))
            continue

        # Чистый IPv6
        if ip_obj.version == 6:
            if not count_ipv6:
                continue
            ips.add(str(ip_obj))

    return ips

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/connections")
def connections(user: str = Depends(verify_credentials)):
    ips = sorted(get_unique_remote_ips(MONITOR_PORT, COUNT_IPV4, COUNT_IPV6))
    return {
        "count": len(ips),
        "ips": ips,
        "port": MONITOR_PORT,
        "count_ipv4_enabled": COUNT_IPV4,
        "count_ipv6_enabled": COUNT_IPV6,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ip_agent:app", host="0.0.0.0", port=API_LISTEN_PORT, log_level="info")