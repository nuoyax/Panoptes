# Panoptes · 子域名全景查询

[English](README.md) | 中文

**Panoptes**（Πανόπτης，「无所不见者」）—— 自托管的子域名全景查询服务，基于 Certificate Transparency（证书透明度）日志聚合 —— 参考 [crt.name](https://crt.name) 实现。

> 🔍 查询任意 apex 域名的全部已知子域名。结果由多个公共 CT 数据源并发聚合，去重、规范化后缓存在 SQLite 中。

## 特性

- **多源聚合** —— 并发查询 crt.sh 与 AlienVault OTX；单源失败不影响整体响应
- **SQLite 缓存** —— 24 小时 TTL，缓存命中秒级响应，`?refresh=1` 强制刷新
- **双格式输出** —— JSON API + crt.name 风格纯文本
- **结果导出** —— UI 一键下载 TXT / CSV / JSON
- **实时过滤与复制** —— 输入即过滤，点击任意行复制
- **输入校验** —— 严格的 apex 域名正则，无注入面

## 快速开始

```bash
git clone <repo-url> && cd query-sub-domin
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

打开 **http://127.0.0.1:8000**

## API

| 端点 | 说明 |
|---|---|
| `GET /api/v1/search?apex=baidu.com` | JSON：`{apex, count, cached, sources, elapsed_seconds, subdomains[]}` |
| `GET /api/v1/search?apex=baidu.com&format=text` | 纯文本，每行一个子域名 |
| `GET /api/v1/search?apex=baidu.com&refresh=1` | 绕过缓存强制刷新 |
| `GET /api/v1/health` | 健康检查 |

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

## 项目结构

```
├── backend/
│   ├── main.py            # FastAPI 入口：路由 + 静态托管
│   ├── config.py          # 超时、缓存 TTL、调优开关
│   ├── aggregator.py      # 多源并发聚合 + 去重
│   ├── cache.py           # aiosqlite 缓存（24h TTL）
│   └── sources/
│       ├── base.py        # CTSource 抽象基类
│       ├── crtsh.py       # crt.sh JSON 接口（exclude=expired 提速）
│       └── otx.py         # AlienVault OTX passive DNS
├── frontend/
│   ├── index.html         # 深色主题单页 UI
│   └── app.js             # 查询、过滤、导出、复制
└── data/                  # SQLite 缓存（已 gitignore）
```

## 性能说明

- 大域名冷查询（如 `baidu.com`）：约 5–20 秒（瓶颈在 crt.sh 上游）
- `backend/config.py` 中的 `CRTSH_EXCLUDE_EXPIRED` 排除过期证书 —— 上游快 10-20 倍，但只返回活跃记录；改为 `False` 可查全量历史（很慢）
- 缓存命中即时返回

## 配置

所有配置项集中在 [`backend/config.py`](backend/config.py)：

| 键 | 默认值 | 说明 |
|---|---|---|
| `UPSTREAM_TIMEOUT` | `120.0` | 单数据源 HTTP 超时（秒） |
| `CACHE_TTL_SECONDS` | `86400` | 缓存 TTL（24 小时） |
| `CRTSH_EXCLUDE_EXPIRED` | `True` | 跳过过期证书（大幅提速） |
| `MAX_RESULTS` | `100000` | 返回子域名数量上限 |

## 安全

- apex 输入在发起任何上游请求前均经严格正则校验
- 上游 URL 仅由校验后的输入构造 —— 无用户可控 URL 路径
- 报告安全问题请见[安全策略](SECURITY.md)

## 许可证

[MIT](LICENSE)
