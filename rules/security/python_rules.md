# Python 漏洞规则（PY-01～PY-16）

每条规则固定结构：触发点 / 可控源 / 判定条件 / 误报排除 / 修复 / CWE。
审计时必须给出 source → propagator → sink → sanitizer 的完整链路。

## OWASP Top 10 (2021) 映射

| OWASP 类别 | 对应规则 |
|---|---|
| A01 Broken Access Control | PY-09、PY-10、PY-16 |
| A02 Cryptographic Failures | PY-11、PY-12 |
| A03 Injection | PY-01、PY-02、PY-03、PY-04、PY-08 |
| A04 Insecure Design | `rules/arch/design_review.md` |
| A05 Security Misconfiguration | `rules/arch/config_baseline.md` |
| A06 Vulnerable & Outdated Components | PY-15、`supply_chain.md` |
| A07 Identification & Authentication Failures | PY-09 |
| A08 Software & Data Integrity Failures | PY-05、PY-15 |
| A09 Security Logging & Monitoring Failures | PY-14 |
| A10 Server-Side Request Forgery | PY-07 |

## 通用追踪模型

| 类别 | 常见位置 |
|---|---|
| Source | `request.args/form/json/files/headers/cookies`、路径参数、`sys.argv`、`os.environ`、上传文件、数据库/队列消息、第三方 API 返回 |
| Propagator | 赋值、拼接、`format`、`%`、`join`、`json.loads`、解码/解压、跨函数传参 |
| Sink | 命令、SQL、模板、文件、网络、反序列化、日志、认证判断 |
| Sanitizer | 类型/白名单校验、参数化查询、`shlex.quote`、`secure_filename`、`html.escape`、`defusedxml`、`yaml.safe_load`、`secrets` |

---

## PY-01 命令执行

**触发点**
`os.system`、`os.popen`、`subprocess.run/Popen(..., shell=True)`、`os.exec*`、`commands.getoutput`

**可控源**
`request.*`、`sys.argv`、`os.environ`、上传文件内容、数据库/队列消息

**判定条件**
sink 参数可由外部输入拼接，且无白名单或 `shlex.quote`；`shell=True` 时存在 `; | & $() \`` 等分隔符注入。

**误报排除**

- 命令为常量，参数以列表传入且 `shell=False`
- 输入仅来自可信配置且启动时校验
- 已用严格白名单（固定枚举）校验

**修复**

```python
subprocess.run(["ping", "-c", "1", host], shell=False, check=True, timeout=5)
```

必要时用 `ipaddress` 校验 IP，禁止传入任意主机名。

**CWE-78**

---

## PY-02 代码执行

**触发点**
`eval`、`exec`、`compile`、`__import__`、`getattr(__builtins__, ...)`、`importlib.import_module(user_input)`

**可控源**
请求参数、配置、数据库、文件、反序列化结果

**判定条件**
参数含外部输入，或来自解码/解压/拼接后的字符串；动态导入的模块名可控。

**误报排除**

- `eval` 参数为常量或严格白名单
- `ast.literal_eval` 仅解析字面量
- 插件机制有签名校验与路径限制

**修复**

```python
import ast

value = ast.literal_eval(user_input)  # 只接受字面量
```

需要动态执行时，改用受限 DSL 或独立沙箱进程，不要在主进程 `eval`。

**CWE-95**

---

## PY-03 SQL 注入

**触发点**
`cursor.execute`、`executemany`、Django `raw()` / `extra()`、SQLAlchemy `text()`、`pandas.read_sql`

**可控源**
请求参数、排序/分页字段、表名/列名、`IN` 列表

**判定条件**
SQL 字符串由 f-string、`%`、`format`、`+` 拼接外部输入；表名/列名/排序方向无法参数化且未白名单校验。

**误报排除**

- 使用 `%s` / `?` / `:name` 绑定参数
- ORM 查询条件由表达式构造
- 动态表名来自固定枚举

**修复**

```python
cursor.execute("SELECT * FROM items WHERE name = %s", (q,))
```

```python
# 排序列必须白名单
sort = {"name": "name", "created": "created_at"}.get(raw_sort, "created_at")
cursor.execute(f"SELECT * FROM items ORDER BY {sort} LIMIT %s", (limit,))
```

**CWE-89**

---

## PY-04 模板注入（SSTI）

**触发点**
`render_template_string`、`jinja2.Template(user_input)`、`Environment(autoescape=False)`、Django `Template(user_input)`

**可控源**
请求参数、数据库模板、邮件模板、管理后台配置

**判定条件**
用户输入进入模板源码而非模板变量；或模板引擎沙箱被关闭。

**误报排除**

- 模板名固定，用户输入只作为变量传入
- 使用 `autoescape=True`
- 使用沙箱环境且限制属性访问

**修复**

```python
# 模板固定，输入只做变量
return render_template("search.html", q=q)
```

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment(autoescape=True)
```

**CWE-1336**

---

## PY-05 反序列化

**触发点**
`pickle.load/loads`、`yaml.load`（无 SafeLoader）、`marshal.loads`、`dill`、`joblib.load`、`torch.load`、`jsonpickle`

**可控源**
上传文件、Cookie/Session、缓存、消息队列、第三方接口、数据库字段

**判定条件**
反序列化数据来自不可信来源，且无签名/完整性校验。

注意 PyYAML 变体：

- PyYAML ≥ 6.0：`yaml.load(data)` 不传 `Loader` 会直接抛 `TypeError`，但 `yaml.load(data, Loader=yaml.FullLoader)` 仍**不是**安全选项（FullLoader 不能完全阻止对象构造），必须用 `yaml.safe_load`
- 显式 `Loader=yaml.UnsafeLoader` / `yaml.Loader` 等价于 `pickle.loads`
- `torch.load` 在 PyTorch ≥ 2.6 默认 `weights_only=True`，旧版本需显式传参

**误报排除**

- 数据由本进程生成且不落盘、不出网
- 使用 JSON 等纯数据格式
- `torch.load(..., weights_only=True)` 且来源可信
- 有 HMAC 签名且密钥不泄露

**修复**

```python
import json
data = json.loads(payload)
```

```python
import yaml
data = yaml.safe_load(payload)
```

```python
import torch
state = torch.load(path, map_location="cpu", weights_only=True)
```

必须用 pickle 时，用 HMAC 签名并限制来源：

```python
import hmac, hashlib, pickle

def loads_signed(blob: bytes, key: bytes):
    sig, body = blob[:32], blob[32:]
    if not hmac.compare_digest(sig, hmac.new(key, body, hashlib.sha256).digest()):
        raise ValueError("bad signature")
    return pickle.loads(body)
```

**CWE-502**

---

## PY-06 路径穿越与任意文件

**触发点**
`open`、`Path.read_text/write_text`、`send_file`、`FileResponse`、`shutil.copy`、`zipfile.extractall`、`tarfile.extractall`、`shutil.unpack_archive`、`tempfile.mktemp`

**可控源**
文件名/路径参数、上传文件名、压缩包条目、配置中的路径

**判定条件**
路径由外部输入拼接，未做规范化 + 根目录限制；压缩包未校验 `..`、绝对路径、符号链接。

**误报排除**

- 路径来自固定枚举
- 已用 `resolve()` + `is_relative_to(base)` 校验
- 使用随机生成的文件名，不保留用户路径

**修复**

```python
from pathlib import Path

base = Path("/srv/files").resolve()
target = (base / user_path).resolve()
if not target.is_relative_to(base):
    raise ValueError("invalid path")
```

```python
import tarfile

# filter 参数自 3.12 引入；3.14 起默认即 'data'（≤3.13 默认 fully_trusted）
with tarfile.open(path) as tar:
    tar.extractall(dest, filter="data")
```

旧版本（< 3.12）需逐条校验成员路径，禁止绝对路径、`..`、符号链接；zipfile 用 `extractall` 前同样逐条校验。

**CWE-22 / CWE-73**

---

## PY-07 SSRF

**触发点**
`requests.get/post`、`httpx`、`urllib.request`、`aiohttp`、`redirect()`、Webhook 回调

**可控源**
URL 参数、回调地址、图片/文件 URL、第三方配置

**判定条件**
目标 URL 完全或部分可控，且无协议/域名/IP 白名单；未限制重定向和内网地址。

**误报排除**

- URL 来自固定配置
- 已做域名白名单 + DNS 解析后校验 IP
- 禁止重定向或每跳重新校验

**修复**

```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_HOSTS = {"api.example.com"}

def safe_get(url: str):
    p = urlparse(url)
    if p.scheme not in {"https"} or p.hostname not in ALLOWED_HOSTS:
        raise ValueError("blocked")
    infos = socket.getaddrinfo(p.hostname, 443)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("blocked ip")
    return requests.get(url, timeout=5, allow_redirects=False)
```

注意：先解析后连接存在 TOCTOU/DNS rebinding 窗口；高保证场景应在连接层固定解析出的 IP，或走出网代理统一校验。

**CWE-918**

---

## PY-08 XXE

**触发点**
`lxml.etree.parse/fromstring`（`resolve_entities=True`）、`xml.sax`、`xml.dom.minidom`、`xml.etree.ElementTree`

**可控源**
上传的 XML、SOAP 请求、配置文件、第三方接口

**判定条件**
解析不可信 XML 且允许实体/外部 DTD；未使用 `defusedxml`。

**误报排除**

- 使用 `defusedxml`
- `lxml` 显式关闭实体与网络
- 输入为固定内部文件

**修复**

```python
from defusedxml import ElementTree as ET
root = ET.fromstring(payload)
```

```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
root = etree.fromstring(payload, parser=parser)
```

**CWE-611**

---

## PY-09 认证与会话

**触发点**
`jwt.decode`、`jwt.encode`、`itsdangerous`、`session`、`login_user`、密码校验、权限装饰器

**可控源**
Token、Cookie、Header、登录表单、OAuth 回调

**判定条件**

- PyJWT 2.x：`jwt.decode(..., options={"verify_signature": False})` 跳过签名校验
- PyJWT 2.x：`algorithms=["none"]` 或未指定 `algorithms`（接受任意算法，含 `none`）
- PyJWT 1.x（已过时）：`jwt.decode(token, verify=False)`
- 关闭已注册声明校验：`options={"verify_exp": False, "verify_aud": False}`
- JWT 密钥弱或硬编码
- Session 密钥硬编码、Cookie 缺 `Secure/HttpOnly/SameSite`
- 密码使用 MD5/SHA1 或明文比较
- 鉴权异常时 `except` 后继续放行（失败开放）
- 只校验登录，不校验角色/对象归属

**误报排除**

- 固定算法、强密钥、校验 `exp/aud/iss`
- 使用 `bcrypt` / `argon2`
- 异常路径显式拒绝

**修复**

```python
payload = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    options={"require": ["exp", "iss", "aud"], "verify_aud": True},
)
```

```python
from argon2 import PasswordHasher

ph = PasswordHasher()
ph.verify(password_hash, password)
```

**CWE-287 / CWE-384 / CWE-798**

---

## PY-10 越权 / IDOR

**触发点**
`get_object_or_404`、`Model.objects.get(pk=...)`、`filter(id=...)`、批量接口、导出接口、管理接口

**可控源**
路径/查询参数中的对象 ID、租户 ID、用户 ID、批量 ID 列表

**判定条件**
只校验“已登录”，未校验对象归属或角色；租户 ID 来自请求而非会话；批量接口逐条缺少权限判断。

**误报排除**

- 查询条件强制包含 `owner=request.user` 或 `tenant=request.tenant`
- 统一权限层（DRF permission / 中间件）覆盖
- 对象本身为公开资源

**修复**

```python
obj = get_object_or_404(Order, pk=order_id, owner=request.user)
```

```python
# DRF 对象级权限
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id
```

**CWE-639 / CWE-862**

---

## PY-11 加密与随机数

**触发点**
`hashlib.md5/sha1`、`random`、`Crypto.Cipher`、`cryptography`、`os.urandom`、`secrets`

**可控源**
密码、Token、验证码、密钥、盐

**判定条件**

- 密码/令牌用 MD5/SHA1 或 `random`
- AES 使用 ECB、固定 IV、复用 nonce
- 密钥硬编码或从不可信来源加载
- `requests(..., verify=False)`

**误报排除**

- 仅用于非安全场景的校验和
- 使用 `secrets` / `os.urandom`
- AES-GCM 且 nonce 唯一

**修复**

```python
import secrets

token = secrets.token_urlsafe(32)
```

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
```

**CWE-327 / CWE-330 / CWE-338**

---

## PY-12 密钥硬编码

**触发点**
源码、配置文件、测试、文档、Notebook、CI 配置中的 `SECRET_KEY`、`API_KEY`、`TOKEN`、数据库密码、私钥

**可控源**
仓库内容与 Git 历史

**判定条件**
出现真实格式的密钥，或高熵字符串赋值给敏感变量名；`.env` 被提交。

**误报排除**

- 明确的占位符（`changeme`、`xxx`、`<REDACTED>`）
- 测试用假值且无权限
- 公钥、证书（非私钥）

**修复**

- 改从环境变量/密钥管理服务读取
- 轮换已泄露密钥
- 清理 Git 历史并加 pre-commit 扫描

```python
import os
SECRET_KEY = os.environ["SECRET_KEY"]
```

**CWE-798**

---

## PY-13 文件上传

**触发点**
`request.files`、`UploadFile`、`FileField`、`save()`、`shutil.copyfileobj`

**可控源**
文件名、扩展名、Content-Type、文件内容

**判定条件**

- 只校验扩展名或 Content-Type
- 保留原始文件名并落在 Web 可访问目录
- 允许 `..`、绝对路径、双扩展名
- 未限制大小与类型

**误报排除**

- 白名单扩展名 + 内容魔数校验
- 随机文件名，存储在 Web 根目录之外
- 上传后重命名并做病毒扫描

**修复**

```python
from pathlib import Path
from werkzeug.utils import secure_filename
import uuid

ALLOWED = {".png", ".jpg", ".pdf"}
name = secure_filename(file.filename)
suffix = Path(name).suffix.lower()
if suffix not in ALLOWED:
    raise ValueError("bad type")

dest = Path("/srv/uploads") / f"{uuid.uuid4().hex}{suffix}"
file.save(dest)
```

**CWE-434**

---

## PY-14 日志与错误信息泄露

**触发点**
`logging`、`print`、异常处理、`DEBUG=True`、错误页、调试接口

**可控源**
请求参数、异常对象、上下文变量

**判定条件**

- 日志记录密码、Token、身份证、银行卡、完整请求体
- 用户输入直接拼进日志（日志注入）
- 生产开启 `DEBUG`，堆栈/配置外泄
- `except Exception: pass` 吞掉安全异常

**误报排除**

- 已脱敏
- 仅记录 ID 与结果码
- 调试配置仅在本地

**修复**

```python
logger.info("login failed user_id=%s ip=%s", user_id, ip)
```

不要记录密码、Token、完整 Cookie。生产关闭 `DEBUG`，统一错误页。

**CWE-532 / CWE-209 / CWE-390**

---

## PY-15 依赖与供应链

详见 `supply_chain.md`。要点：

- 用 `pip-audit` / OSV 按 CVE 查，不硬编码库名
- 检查锁文件、安装钩子、`.pth`、私有源、依赖混淆
- vendored 代码与 wheel 内二进制纳入后门排查
- 只报告，不自动升级、不改锁文件

**CWE-1104 / CWE-1395**

---

## PY-16 业务逻辑与并发

详见 `../logic/`。安全侧重点关注：

- 金额/数量/折扣由前端传入
- 重复提交、支付回调无幂等
- 状态机可非法跳转
- 验证码可复用
- 并发导致超卖/重复领取
- 事务缺失导致部分成功

**CWE-840 / CWE-362**

---

## 快速 grep 清单

```bash
rg -n "eval\(|exec\(|compile\(|__import__|pickle\.|yaml\.load|marshal\.|dill\.|joblib\.|torch\.load" .
rg -n "os\.system|os\.popen|subprocess\.|shell=True|os\.exec" .
rg -n "execute\(|executemany\(|\.raw\(|\.extra\(|text\(" .
rg -n "render_template_string|Template\(|autoescape" .
rg -n "open\(|send_file|FileResponse|extractall|unpack_archive|mktemp" .
rg -n "requests\.|httpx\.|urllib|aiohttp|redirect\(" .
rg -n "md5|sha1|random\.|ECB|verify=False|jwt\.decode" .
rg -n "SECRET_KEY|API_KEY|TOKEN|PASSWORD|PRIVATE KEY" .
rg -n "DEBUG\s*=\s*True|ALLOWED_HOSTS|CORS|csrf_exempt|mark_safe" .
```
