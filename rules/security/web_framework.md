# Web 框架专项

## Django

### 配置基线

| 检查项 | 安全值 | 风险 |
|---|---|---|
| `DEBUG` | `False` | 堆栈、SQL、配置外泄 |
| `SECRET_KEY` | 环境变量/密钥服务 | 硬编码可伪造 Session |
| `ALLOWED_HOSTS` | 明确域名列表 | `["*"]` 易受 Host 头攻击 |
| `SECURE_SSL_REDIRECT` | `True` | 明文传输 |
| `SESSION_COOKIE_SECURE` | `True` | Cookie 明文传输 |
| `SESSION_COOKIE_HTTPONLY` | `True` | XSS 可读 Session |
| `SESSION_COOKIE_SAMESITE` | `Lax` / `Strict` | CSRF 风险 |
| `CSRF_COOKIE_SECURE` | `True` | CSRF Token 明文传输 |
| `SECURE_HSTS_SECONDS` | > 0 | 降级攻击 |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `True` | MIME 嗅探 |
| `X_FRAME_OPTIONS` | `DENY` | 点击劫持 |
| `CORS_ALLOW_ALL_ORIGINS` | `False` | 跨域数据泄露 |
| `DATABASES` 账号 | 最小权限 | 拖库/删库 |

### 代码审计点

```python
# 危险
Model.objects.raw(f"SELECT * FROM t WHERE id={user_id}")
Model.objects.extra(where=[f"name='{name}'"])
mark_safe(user_input)
{% autoescape off %}
@csrf_exempt
```

```python
# 安全
Model.objects.filter(id=user_id)
Model.objects.extra(where=["name=%s"], params=[name])
format_html("{}", user_input)
```

- 模板：确认 `TEMPLATES[0]["OPTIONS"]["autoescape"]` 为 `True`。
- 文件：`FileField` 的 `upload_to`、`MEDIA_ROOT` 是否在 Web 根目录外。
- DRF：每个 ViewSet 是否有 `permission_classes`、`get_queryset()` 是否按用户过滤、`serializer` 是否允许 `user`/`is_staff` 等敏感字段（Mass Assignment）。
- Admin：`/admin/` 是否公网可达、是否强制 MFA、是否改路径（改路径不等于安全）。
- 中间件顺序：认证/权限中间件是否在所有业务前生效。
- 信号与 `AppConfig.ready()`：是否在启动时执行外部调用。

## Flask

### 配置基线

| 检查项 | 安全值 |
|---|---|
| `app.run(debug=True)` | 生产禁止 |
| `SECRET_KEY` | 环境变量，强随机 |
| `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE` | 开启 |
| `PERMANENT_SESSION_LIFETIME` | 合理过期 |
| `MAX_CONTENT_LENGTH` | 限制上传大小 |
| `TRUSTED_HOSTS` | 明确域名（Flask 3.1+；旧版本在反代层校验 Host） |
| CORS | 明确 Origin，不带凭证通配 |

### 代码审计点

```python
# 危险
app.run(debug=True)
render_template_string(user_input)
send_file(os.path.join("/data", request.args["f"]))
CORS(app, origins="*", supports_credentials=True)
```

```python
# 安全
send_from_directory("/data", secure_filename(name))
render_template("page.html", value=user_input)
```

- `before_request` 鉴权是否覆盖所有 Blueprint；静态路由是否被误放行。
- `session` 是否只存 ID，不存敏感数据。
- `Flask-WTF` 的 `CSRFProtect` 是否全局启用。
- `request.headers["X-Forwarded-For"]` 是否直接当真实 IP（应使用 `ProxyFix` 并限制可信代理）。
- 上传：`secure_filename` + 白名单 + 随机名 + Web 根目录外。

## FastAPI

### 配置基线

| 检查项 | 安全值 |
|---|---|
| `docs_url` / `redoc_url` / `openapi_url` | 生产关闭或鉴权 |
| CORS | 明确 Origin，`allow_credentials` 谨慎 |
| `TrustedHostMiddleware` | 明确 allowed_hosts |
| HTTPS | 反代终止 + HSTS |
| 认证 | 每个路由显式 `Depends`，不靠全局默认 |

### 代码审计点

```python
# 危险
app = FastAPI()  # 默认 /docs /openapi.json 暴露
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
@app.get("/users/{user_id}")
def get_user(user_id: int):
    return db.get(User, user_id)  # 未校验归属
```

```python
# 安全
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
@app.get("/users/{user_id}")
def get_user(user_id: int, user=Depends(current_user)):
    return get_owned(db, User, user_id, user.id)
```

- 检查是否有路由遗漏 `Depends(current_user)`。
- Pydantic 模型是否把 `is_admin`、`role`、`balance` 暴露为可写字段。
- `BackgroundTasks` / 启动事件是否执行外部命令或网络请求。
- WebSocket 鉴权与消息校验。
- 路径参数、查询参数是否直接拼 SQL / 文件路径。

## 通用 Web 检查

1. **反代与真实 IP**：`X-Forwarded-For` 只在可信代理后使用，否则可伪造限流/审计。
2. **安全响应头**：HSTS、CSP、`X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`。
3. **限流**：登录、验证码、导出、搜索接口。
4. **错误页**：生产不返回堆栈、SQL、路径。
5. **静态文件**：禁止目录列表，禁止把上传目录当静态目录。
6. **多租户**：所有查询强制带租户条件，缓存 Key 含租户。
7. **OpenAPI/Actuator/调试端点**：公网不可达。
8. **依赖注入/全局单例**：确认认证对象不会被跨请求复用。
