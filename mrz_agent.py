from dotenv import load_dotenv
import os
import psutil
import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Set, List

load_dotenv()

API_USER = os.getenv("API_USER", "admin")
API_PASS = os.getenv("API_PASS", "password")
API_LISTEN_PORT = int(os.getenv("API_LISTEN_PORT", "8000"))
MONITOR_PORT = int(os.getenv("MONITOR_PORT", "22"))

security = HTTPBasic()
app = FastAPI(title="mrz_agent", version="0.1")

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

def get_unique_remote_ips(port: int) -> Set[str]:
    ips = set()
    try:
        conns = psutil.net_connections(kind='tcp')
    except Exception:
        # В некоторых окружениях psutil может требовать повышенных прав.
        conns = []
    for c in conns:
        # laddr and raddr are psutil._common.addr tuples; raddr may be empty
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
        if rip:
            ips.add(rip)
    return ips

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/connections")
def connections(user: str = Depends(verify_credentials)):
    ips = sorted(get_unique_remote_ips(MONITOR_PORT))
    return {"count": len(ips), "ips": ips, "port": MONITOR_PORT}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("mrz_agent:app", host="0.0.0.0", port=API_LISTEN_PORT, log_level="info")
