# ip_agent

Небольшой сервис для подсчёта уникальных удалённых IP, подключённых к указанному порту. Ответ предоставляется по API (запрос → ответ). Конфигурация через `.env`.

## Кратко
- Подсчитываются только уникальные IP (дубликаты исключаются).
- Можно включать/выключать подсчёт IPv4/IPv6 через переменные окружения.
- Доступ к API защищён HTTP Basic (логин/пароль в `.env`) или TRUSTED_IPS=
- Рекомендуемый режим запуска в Docker — на Linux с __network_mode: "host"__ для доступа к сетевым соединениям хоста.

## Файлы
- `ip_agent.py` — приложение FastAPI.
- `Dockerfile`, `docker-compose.yml` — контейнеризация.
- `.env.example` — пример конфигурации.
- `requirements.txt` — зависимости.

## Настройка
1. Скопируйте пример:
   - cp .env.example .env
2. Отредактируйте `.env` (логин, пароль, порт API, порт мониторинга, флаги COUNT_IPV4/COUNT_IPV6).

Пример переменных:
- API_USER, API_PASS — креды для Basic Auth
- API_LISTEN_PORT — порт для uvicorn (по умолчанию 8000)
- MONITOR_PORT — порт, к которому считаются подключения (например 22)
- COUNT_IPV4, COUNT_IPV6 — true/false

## Запуск (Docker Compose)
На Linux (рекомендуется):
- docker compose build --no-cache
- docker compose up -d

Если вы не на Linux, __network_mode: "host"__ может не работать как ожидается — в таком случае запустите сервис на хосте напрямую.

## API
- GET /health
  - Ответ: {"status": "ok"}
- GET /connections
  - Требует Basic Auth.
  - Ответ:
    {
      "count": <число уникальных IP>,
      "ips": [<список IP>],
      "port": <MONITOR_PORT>,
      "count_ipv4_enabled": <true|false>,
      "count_ipv6_enabled": <true|false>
    }

Пример запроса:
- curl -u admin:changeme "http://localhost:8000/connections"
