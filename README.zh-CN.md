# 子域名查询

自托管的子域名查询服务，基于 Certificate Transparency（证书透明度）日志聚合 —— 参考 crt.name 实现。

- FastAPI 后端并发查询公共 CT 数据源，去重、规范化并用 SQLite 缓存结果。
- 轻量深色单页前端。

## 快速开始

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload
# 打开 http://127.0.0.1:8000
```

## API

```
GET /api/v1/search?apex=baidu.com               # JSON
GET /api/v1/search?apex=baidu.com&format=text   # 纯文本（crt.name 风格）
GET /api/v1/search?apex=baidu.com&refresh=1     # 绕过缓存
GET /api/v1/health
```

## 许可证

MIT

[English](README.md)
