# 配置基线

## 一、通用

| 检查项 | 安全值 |
|---|---|
| 调试模式 | 生产关闭 |
| 密钥 | 环境变量/密钥服务，非硬编码 |
| 数据库密码 | 非默认、非空、最小权限 |
| TLS | 强制，证书校验开启 |
| 安全响应头 | HSTS、CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy |
| 目录列表 | 关闭 |
| 错误页 | 不返回堆栈 |
| 默认账号 | 已删除/改名/强密码 |
| 上传目录 | Web 根目录外，不可执行 |
| 备份 | 加密、访问受控 |

## 二、Django

```python
DEBUG = False
SECRET_KEY = os.environ["SECRET_KEY"]
ALLOWED_HOSTS = ["app.example.com"]
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
```

检查：

- `CORS_ALLOW_ALL_ORIGINS` / `CORS_ALLOW_CREDENTIALS`
- `DATABASES` 账号权限
- `MEDIA_ROOT` / `STATIC_ROOT` 位置
- `TEMPLATES` 的 `autoescape`
- `LOGGING` 是否记录敏感字段
- `ADMINS` / `EMAIL` 配置是否泄露
- `SECURE_PROXY_SSL_HEADER` 是否与可信代理匹配

## 三、Flask

```python
app.config.update(
    DEBUG=False,
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    TRUSTED_HOSTS=["app.example.com"],  # Flask 3.1+；旧版本在反代层校验 Host
)
```

检查：

- `app.run(debug=True)` 是否残留
- `CORS(app, origins="*", supports_credentials=True)`
- `ProxyFix` 的 `x_for` 是否限制
- 静态目录是否包含上传目录
- `Flask-WTF` CSRF 是否全局启用

## 四、FastAPI

```python
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["app.example.com"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

检查：

- 文档端点是否公网可达
- 每个路由是否有认证依赖
- Pydantic 模型是否暴露敏感可写字段
- `allow_origins=["*"]` + `allow_credentials=True` 组合
- 启动事件/后台任务是否执行外部调用

## 五、容器与部署

| 检查项 | 安全值 |
|---|---|
| 基础镜像 | 固定 digest，非 latest |
| 用户 | 非 root |
| 根文件系统 | 只读 |
| 能力 | 最小 `cap_drop: ALL` |
| 网络 | 默认拒绝，按需放行 |
| 密钥 | 挂载/环境注入，非镜像内 |
| 健康检查 | 不泄露内部信息 |
| 日志 | 不含敏感信息 |

```dockerfile
FROM python:3.12-slim
RUN useradd -r -u 10001 app
USER app
```

检查：

- `Dockerfile` 中 `curl | bash`
- 构建参数中是否传入密钥（会留在镜像历史）
- `docker-compose` 是否 `privileged: true`
- K8s `securityContext` 是否 `runAsNonRoot`、`readOnlyRootFilesystem`

## 六、CI/CD

- `pull_request_target` 是否检出并使用 PR 代码
- Action 是否固定版本/digest
- `secrets` 是否在不可信上下文使用
- 发布令牌权限是否最小
- 构建产物是否签名、是否可追溯
- 是否在 CI 中执行不可信脚本

## 七、配置审查命令

```bash
rg -n "DEBUG\s*=\s*True|debug=True|ALLOWED_HOSTS|SECRET_KEY|CORS|csrf_exempt" .
rg -n "verify=False|InsecureRequestWarning|ssl_verify" .
rg -n "privileged|runAsRoot|readOnlyRootFilesystem|cap_add" .
rg -n "pull_request_target|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh" .github
rg -n "password|passwd|secret|token|api_key" .env* config* 2>/dev/null
```
