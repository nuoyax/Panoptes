# Panoptes · 子域名全景查询

[English](README.md) | 中文

**Panoptes**（Πανόπτης，「无所不见者」）—— 自托管的子域名全景查询服务，基于 Certificate Transparency（证书透明度）日志聚合 —— 参考 [crt.name](https://crt.name) 实现。

> 🔍 查询任意 apex 域名的全部已知子域名。结果由多个公共 CT 数据源并发聚合，去重、规范化后缓存在 SQLite 中。

## 特性

- **多源聚合** —— 并发查询 crt.sh、AlienVault OTX、HackerTarget、Wayback CDX 与 Cert Spotter；单源失败不影响整体响应
- **后台任务 + 轮询** —— `POST /api/v1/scan` 立即返回任务 ID，大域名不再阻塞请求数分钟；分阶段进度可轮询，部分结果即可使用
- **分阶段持久化** —— DNS / HTTP / 端口 / 安全结果按 `(apex, 主机, 阶段)` 入库，各自独立 TTL；重扫时复用未过期结果，只补缺失部分
- **阶段依赖自动补齐** —— 勾选"安全检查"自动补 `http` 与 `dns`，并在响应中回传补齐项，不再静默返回空列
- **SQLite 缓存** —— 子域名列表 24 小时 TTL，缓存命中秒级响应，`?refresh=1` 强制刷新
- **双格式输出** —— JSON API + crt.name 风格纯文本
- **分阶段 UI** —— 阶段进度药丸、结果表随扫描增长、取消后保留部分结果、刷新页面用 `?job=` 续接
- **结果导出** —— UI 一键下载 TXT / CSV / JSON
- **实时过滤与复制** —— 输入即过滤，点击任意行复制
- **输入校验** —— 严格 apex 域名正则，且用 `fullmatch` 匹配，无注入面

## 快速开始

```bash
git clone <repo-url> && cd query-sub-domin
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

打开 **http://127.0.0.1:8000**

## API

完整参考（含任务状态机与全部响应字段）：**[docs/API.md](docs/API.md)**。

| 端点 | 说明 |
|---|---|
| `GET /api/v1/search?apex=baidu.com` | JSON：`{apex, count, cached, sources, elapsed_seconds, subdomains[]}` |
| `GET /api/v1/search?apex=baidu.com&format=text` | 纯文本，每行一个子域名 |
| `GET /api/v1/search?apex=baidu.com&refresh=1` | 绕过缓存强制刷新 |
| `GET /api/v1/search?apex=baidu.com&dns_check=1` | 子域名 + 富化结果；`202` 表示"去轮询任务" |
| `POST /api/v1/scan` | 启动后台扫描 → `202` + `{job_id, stages, poll}` |
| `GET /api/v1/jobs/{job_id}` | 任务状态、分阶段进度与结果 |
| `GET /api/v1/jobs?apex=baidu.com` | 最近任务，用于刷新后重新挂载 |
| `DELETE /api/v1/jobs/{job_id}` | 软取消运行中的任务（已终态返回 `409`） |
| `GET /api/v1/health` | 健康检查 + 任务并发数 |

示例：

```bash
curl "http://127.0.0.1:8000/api/v1/search?apex=baidu.com&format=text"
```

```text
www.baidu.com
tieba.baidu.com
image.baidu.com
...
```

带富化的扫描与轮询：

```bash
JOB=$(curl -s -X POST http://127.0.0.1:8000/api/v1/scan \
      -H "Content-Type: application/json" \
      -d '{"apex":"example.com","stages":["dns","http","sec"]}' | jq -r .job_id)
curl -s "http://127.0.0.1:8000/api/v1/jobs/$JOB" | jq '{state, progress}'
```

## 项目结构

```
├── backend/
│   ├── main.py            # FastAPI 入口：路由 + 静态托管
│   ├── config.py          # 单一配置来源：超时、TTL、上限、正则
│   ├── aggregator.py      # 多源并发聚合 + 去重
│   ├── cache.py           # aiosqlite 子域名缓存（24h TTL）
│   ├── store.py           # 子域名清单、分阶段富化与任务记录
│   ├── jobs.py            # 后台扫描注册表：阶段、依赖、进度
│   ├── dns_verify.py      # 并发 A 记录解析
│   ├── http_probe.py      # HTTP 状态码 + 网页标题
│   ├── port_scan.py       # TCP 端口扫描（38 个常见端口）
│   ├── recon.py           # 敏感路径、安全响应头、TLS 证书
│   └── sources/
│       ├── base.py        # CTSource 抽象基类
│       ├── crtsh.py       # crt.sh JSON 接口（exclude=expired 提速）
│       ├── otx.py         # AlienVault OTX passive DNS
│       ├── hackertarget.py# HackerTarget hostsearch CSV
│       ├── wayback.py     # Wayback CDX 索引（最慢的数据源）
│       └── certspotter.py # Cert Spotter v1 issuances
├── frontend/
│   ├── index.html         # 深色主题单页 UI
│   └── app.js             # 扫描、轮询、过滤、导出、复制
├── docs/API.md            # API 参考
└── data/                  # SQLite 数据库（已 gitignore）
```

## 性能说明

- 大域名冷查询（如 `baidu.com`）：约 5–20 秒（瓶颈在上游 CT 源）。Wayback CDX 是最慢的一个 —— 这也是扫描改后台任务的原因
- `backend/config.py` 中的 `CRTSH_EXCLUDE_EXPIRED` 排除过期证书 —— 上游快 10-20 倍，但只返回活跃记录；改为 `False` 可查全量历史（很慢）
- 缓存命中即时返回；重复扫描若命中的都是未过期入库行，毫秒级结束，并把对应阶段标为 `skipped` / `from_cache`
- 富化阶段有主机数上限：HTTP 探测 `MAX_HTTP_HOSTS=3000`，端口扫描与安全检查 `MAX_SCAN_HOSTS=1000`。上限来自算术而非保守：38 端口 × 1000 主机在默认并发与 1.5 秒超时下已是 4-6 分钟量级的单个阶段，2 万主机的 apex 会让它再翻二十倍，超出 900 秒的任务预算。`dns` 单机开销低得多，上限为 `MAX_DNS_HOSTS=20000`。被截断的数量会在 `truncated` 中透出。

## 配置

所有配置项集中在 [`backend/config.py`](backend/config.py)：

| 键 | 默认值 | 说明 |
|---|---|---|
| `UPSTREAM_TIMEOUT` | `120.0` | 单数据源 HTTP 超时（秒） |
| `WAYBACK_TIMEOUT` | `120.0` | CDX 超时（秒）—— 单独配置，它是最慢的上游 |
| `SOURCE_HTTP_MAX_BYTES` | `67108864` | 单次上游请求的响应体上限 |
| `CACHE_TTL_SECONDS` | `86400` | 子域名缓存 TTL（24 小时） |
| `TTL_SUBDOMAIN` | `86400` | 子域名清单 TTL（跟随缓存 TTL） |
| `TTL_DNS` | `21600` | DNS 结果 TTL（6 小时） |
| `TTL_HTTP` | `21600` | HTTP 结果 TTL（6 小时） |
| `TTL_PORTS` | `86400` | 端口扫描结果 TTL（24 小时） |
| `TTL_SECURITY` | `86400` | 安全检查结果 TTL（24 小时） |
| `CRTSH_EXCLUDE_EXPIRED` | `True` | 跳过过期证书（大幅提速） |
| `HTTP_VERIFY_TLS` | `False` | 探测目标时是否校验 TLS（目标常存在坏证书） |
| `HTTP_PROBE_TIMEOUT` | `8.0` | 单主机 HTTP 探测超时（秒） |
| `JOB_MAX_CONCURRENT` | `2` | 同时运行的扫描任务数 |
| `JOB_MAX_SECONDS` | `900` | 单任务墙钟预算 |
| `JOB_TTL_SECONDS` | `3600` | 完成任务保留时长（内存与数据库） |
| `JOB_PRUNE_INTERVAL_SECONDS` | `3600` | 数据库清理间隔 |
| `ENRICHMENT_RETENTION_DAYS` | `30` | 富化行超过该天数被清除 |
| `MAX_RESULTS` | `100000` | 返回子域名数量上限 |
| `MAX_DNS_HOSTS` | `20000` | DNS 阶段主机上限 |
| `MAX_HTTP_HOSTS` | `3000` | HTTP 阶段主机上限 |
| `MAX_SCAN_HOSTS` | `1000` | 端口扫描 / 安全检查阶段主机上限 |

## 安全

- apex 输入在发起任何上游请求前均经严格正则校验（`fullmatch`，不是 `match`）
- 上游 URL 仅由校验后的输入构造 —— 无用户可控 URL 路径
- 富化阶段会对第三方主机发起**主动连接**；自托管使用者请阅读[安全策略](SECURITY.md)确认自身授权范围
- 报告安全问题请见[安全策略](SECURITY.md)

## 变更记录

见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

[MIT](LICENSE)
