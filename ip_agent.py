from dotenv import load_dotenv
import os
import psutil
import secrets
import ipaddress
import logging
import importlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Set, List, Tuple, Optional

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ip_agent")

# Попытка динамически импортировать xray protobuf модули
XRAY_API_AVAILABLE = False
_xray_modules = []
for mod in (
    "xray.app.stats.command_pb2",
    "xray.app.stats.command_pb2_grpc",
    "xray.app.proxyman.command_pb2",
    "xray.app.proxyman.command_pb2_grpc",
):
    try:
        _ = importlib.import_module(mod)
        _xray_modules.append(mod)
    except Exception:
        # не фатально — логируем ниже в lifespan
        pass

if len(_xray_modules) == 4:
    XRAY_API_AVAILABLE = True

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

# Xray API config
XRAY_API_ENABLED = parse_bool(os.getenv("XRAY_API_ENABLED", "false"))
XRAY_API_HOST = os.getenv("XRAY_API_HOST", "127.0.0.1")
XRAY_API_PORT = int(os.getenv("XRAY_API_PORT", "10085"))

security = HTTPBasic()
app = FastAPI(title="ip_agent", version="0.1")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    if TRUSTED_NETWORKS:
        logger.info("TRUSTED_NETWORKS: %s", [str(n) for n in TRUSTED_NETWORKS])
    else:
        logger.info("TRUSTED_NETWORKS: (none configured)")
    logger.info("TRUSTED_IPS_RAW: %s", TRUSTED_IPS_RAW)

    if XRAY_API_ENABLED:
        if XRAY_API_AVAILABLE:
            logger.info("Xray API modules available: %s", _xray_modules)
            logger.info("Xray API enabled at %s:%s", XRAY_API_HOST, XRAY_API_PORT)
        else:
            logger.error("Xray API enabled in config but protobuf modules not available; install package that provides xray.app.* modules (e.g. xray-python) and rebuild image")
    else:
        logger.info("Xray API integration disabled (XRAY_API_ENABLED=false)")

    yield
    # shutdown (если нужно) — ничего не делаем

app.router.lifespan_context = lifespan

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

def get_xray_connections() -> Optional[Tuple[Set[str], int]]:
    """
    Получает данные о подключениях из Xray API
    Возвращает кортеж (уникальные IP, количество подключений)
    """
    if not XRAY_API_ENABLED or not XRAY_API_AVAILABLE:
        return None
    
    ips = set()
    count_all = 0
    
    try:
        channel = grpc.insecure_channel(f"{XRAY_API_HOST}:{XRAY_API_PORT}")
        
        # Получение статистики
        stats_stub = stats_pb2_grpc.StatsServiceStub(channel)
        response = stats_stub.QueryStats(stats_pb2.QueryStatsRequest())
        
        # Паттерн для извлечения IP из строки вида user>>>[ip]
        ip_pattern = re.compile(r"user>>>([^>]+)")
        
        for stat in response.stat:
            if "user>>>" in stat.name and "uplink" in stat.name:
                match = ip_pattern.search(stat.name)
                if match:
                    ip = match.group(1)
                    
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        
                        # Проверяем версию IP и настройки
                        if ip_obj.version == 4 and not COUNT_IPV4:
                            continue
                        if ip_obj.version == 6 and not COUNT_IPV6:
                            continue
                        
                        ips.add(ip)
                        count_all += 1
                    except Exception as e:
                        logger.warning(f"Failed to parse Xray IP: {ip} - {e}")
                        continue
    
    except Exception as e:
        logger.error(f"Error connecting to Xray API: {e}")
        return None
    
    return ips, count_all

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/connections")
def connections(user: str = Depends(verify_credentials)):
    # Получаем данные из системных соединений
    system_ips, system_count = get_connection_stats(MONITOR_PORT, COUNT_IPV4, COUNT_IPV6)
    
    # Если включена интеграция с Xray, пытаемся получить данные оттуда
    xray_result = get_xray_connections() if XRAY_API_ENABLED and XRAY_API_AVAILABLE else None
    
    result = {
        "count": len(system_ips),
        "count_all": system_count,
        "ips": sorted(system_ips),
        "port": MONITOR_PORT,
        "count_ipv4_enabled": COUNT_IPV4,
        "count_ipv6_enabled": COUNT_IPV6,
        "trusted_ips_configured": TRUSTED_IPS_RAW,
    }
    
    # Добавляем данные Xray, если они доступны
    if xray_result is not None:
        xray_ips, xray_count = xray_result
        result["xray_enabled"] = True
        result["xray_count"] = len(xray_ips)
        result["xray_count_all"] = xray_count
        result["xray_ips"] = sorted(xray_ips)
        
        # Объединяем множества для получения общего числа уникальных IP
        all_ips = system_ips.union(xray_ips)
        result["total_count"] = len(all_ips)
        result["total_count_all"] = system_count + xray_count
        result["total_ips"] = sorted(all_ips)
    else:
        result["xray_enabled"] = False
    
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ip_agent:app", host="0.0.0.0", port=API_LISTEN_PORT, log_level="info")