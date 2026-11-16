# 审计范围矩阵

本文件定义审计维度、优先级、模式映射与范围声明，用于阶段 0 和报告阶段。

## 优先级

| 级别 | 含义 | 默认模式 |
|---|---|---|
| P0 | 直接导致严重安全后果，必须覆盖 | security |
| P1 | 需结合业务判断，安全增量最大 | logic / arch |
| P2 | 质量、性能、可维护性 | quality / perf |

## 维度 1：安全漏洞（security）

| 子项 | Python 具体表现 | 优先级 | 检测手段 |
|---|---|---|---|
| 注入 | SQL 拼接、`os.system`、`subprocess(shell=True)`、`render_template_string`、LDAP/NoSQL 拼接 | P0 | SAST + 人工 |
| XSS / CSRF | `autoescape=False`、`mark_safe`、`|safe`、`@csrf_exempt`、CORS 通配 | P0 | SAST + 配置检查 |
| 认证与会话 | `jwt.decode(verify=False)`、`alg=none`、弱密钥、Cookie 缺 `Secure/HttpOnly/SameSite` | P0 | SAST + 配置检查 |
| 水平/垂直越权 | 只校验登录、不校验对象归属；管理接口缺角色校验 | P0 | 人工 |
| 反序列化 | `pickle`、`yaml.load`、`marshal`、`dill`、`joblib`、`torch.load` | P0 | SAST |
| 敏感信息泄露 | 硬编码密钥、日志打印 PII/Token、`DEBUG=True` 堆栈外泄 | P0 | 规则 + 熵检测 |
| 加密缺陷 | MD5/SHA1、`random` 生成令牌、AES-ECB、固定 IV、`verify=False` | P0 | SAST |
| 文件与路径 | `open`/`send_file` 路径穿越、`extractall`、上传校验缺失 | P0 | SAST + 人工 |
| SSRF / XXE / 开放重定向 | `requests.get(user_url)`、`lxml` 实体解析、`redirect(user)` | P0 | SAST |
| 错误处理失败开放 | `except: pass` 后继续放行、鉴权异常默认通过 | P1 | 人工 |
| 审计日志与可追溯 | 关键操作无日志、日志可删改、日志注入 | P1 | 人工 |
| 多租户隔离 | 租户 ID 未强制过滤、缓存/队列串租户 | P1 | 人工 |
| API 安全 | Mass Assignment、无限流、GraphQL 深度、Swagger 未授权 | P1 | SAST + 配置 |

## 维度 2：业务逻辑缺陷（logic）

| 子项 | Python 具体表现 | 优先级 | 检测手段 |
|---|---|---|---|
| 权限校验缺失 | 只 `@login_required`，未校验 `obj.owner == user` | P1 | 人工 |
| 流程绕过 | 金额/数量由前端传入、重复提交、验证码复用、跳过支付步骤 | P1 | 人工 |
| 状态机漏洞 | 订单/支付状态可非法跳转或回滚 | P1 | 人工 + 状态图 |
| 幂等与重放 | 支付回调无幂等键、并发重复执行 | P1 | 人工 + 并发测试 |
| 边界与空值 | `None` 解引用、空列表、负数、超长输入 | P1 | 人工 + 属性测试 |
| 事务一致性 | 部分成功、缺事务、跨库不一致 | P1 | 人工 |
| 时间与时区 | UTC/本地混用、过期判断错误 | P1 | 人工 |
| 资源生命周期 | 连接/文件/锁未释放、长生命周期缓存 | P2 | 人工 + 静态 |

## 维度 3：代码规范与质量（quality / perf）

| 子项 | 工具 | 优先级 |
|---|---|---|
| 命名/注释/冗余 | `ruff` | P2 |
| 异常处理 | `ruff` + 人工 | P1 |
| 类型注解 | `mypy` / `pyright` | P2 |
| 复杂度/重复 | `radon`、`ruff C901` | P2 |
| 死代码/未使用 | `vulture`、`ruff F401` | P2 |
| 测试覆盖 | `pytest-cov` | P2 |
| 性能瓶颈 | `cProfile`、`py-spy`、`scalene`、`nplusone`、`EXPLAIN` | P2 |

## 维度 4：第三方组件风险（security）

| 子项 | Python 具体表现 | 优先级 | 检测手段 |
|---|---|---|---|
| 已知漏洞依赖 | Django、requests、urllib3、cryptography、PyYAML、Jinja2、Pillow、torch | P0 | pip-audit / OSV |
| 供应链投毒 | 包名拼写近似、维护者变更、`setup.py` 安装钩子、`.pth` 文件 | P0 | 人工 + 来源检查 |
| 组件内恶意代码 | vendored 代码、wheel 内二进制 | P0 | 后门排查 |
| SBOM / 清单 | 依赖树、版本锁定 | P1 | `syft` / `cyclonedx` |
| 许可证 | GPL/AGPL 传染性 | P2 | `pip-licenses`（法律意见除外） |

## 维度 5：设计与架构安全（arch）

| 子项 | Python 具体表现 | 优先级 | 检测手段 |
|---|---|---|---|
| 信任边界 | 内外网接口混用、反代头盲信 `X-Forwarded-For` | P1 | 人工 + 架构图 |
| 最小权限 | 数据库账号过高、容器 root、云 AK 过大 | P1 | 配置审查 |
| 暴露面 | 调试端点、Actuator、`/docs`、管理后台 | P0 | 配置审查 |
| 配置错误 | `DEBUG=True`、`ALLOWED_HOSTS=*`、CORS `*`、目录列表 | P0 | 配置审查 |
| 加密与密钥架构 | 密钥硬编码、无轮换、KMS 缺失 | P0/P1 | 人工 |
| 不安全设计 | 无威胁建模、单点信任、越权设计 | P1 | 架构评审 |
| 死依赖/未使用引用 | 遗留依赖、动态 `importlib` | P2 | `vulture` + 人工 |

## 横向关注点

| 关注点 | 说明 | 优先级 |
|---|---|---|
| 合规映射 | 等保 2.0 / PCI DSS / HIPAA / GDPR / 个保法，只映射控制项，不出认证结论 | P1 |
| 隐私与 PII | 收集最小化、脱敏、留存、跨境 | P1 |
| CI/CD 与 IaC | GitHub Actions 注入、`pull_request_target`、Dockerfile、K8s | P1 |
| 后门与恶意代码 | 编码载荷、异常外联、持久化、安装钩子、Git 历史 | P0/P1 |

## Python 化修正

通用安全表格直接套 Python 容易误判，注意：

1. **Log4j 类事件** → Python 侧对应 PyYAML、urllib3、cryptography、Jinja2、Pillow、torch 等，统一用 `pip-audit` 按 CVE 查，不要硬编码库名。
2. **缓冲区溢出** → 纯 Python 基本没有；重点看 `ctypes`、`struct`、`mmap`、C 扩展、解压炸弹（zip bomb）。
3. **类修饰符/域/方法** → Python 没有真正私有，`_`/`__` 只是约定，**不能当访问控制**；安全上看公开 API、`__all__`、暴露的调试方法。
4. **空指针** → 对应 `None` 解引用、`Optional` 未校验、`dict.get()` 返回值未判空。
5. **内存泄漏** → 长生命周期全局缓存、未关闭连接/文件、C 扩展引用计数；纯 Python 循环引用有 GC 兜底。

## 范围声明模板

```markdown
## 审计范围

| 项 | 内容 |
|---|---|
| 代码 | `src/`、`config/`、`.github/`；`tests/` 仅做密钥与投毒扫描 |
| 版本 | commit `a1b2c3d`，分支 `main` |
| 维度 | ☑ 安全漏洞 ☑ 第三方组件 ☑ 配置/架构 ☑ 后门排查<br>☐ 业务逻辑 ☐ 性能 ☐ 编码规范 |
| 方法 | SAST、依赖扫描、人工 source→sink、定向 PoC |
| 动态验证 | 未执行（未授权） |
| 未覆盖 | DAST、IAST、黑盒渗透、合规认证结论、许可证法律意见 |

**结论边界**：本报告仅代表上述范围与方法下的结果，“未发现”不代表“不存在”。
```

## 模式与维度映射

| mode | 覆盖维度 | 默认 |
|---|---|---|
| `security` | 1 + 4 + 5（配置/加密/暴露面）+ 后门 | ✅ |
| `logic` | 2 + 1 的错误处理/审计日志/多租户/API | |
| `arch` | 5 全量 + 威胁建模 | |
| `quality` | 3 的规范/类型/复杂度/覆盖 | |
| `perf` | 3 的性能部分 | |
| `full` | 全部，建议分模块 | |

## 对齐的行业标准

| 标准 | 用途 |
|---|---|
| OWASP Top 10 (2021)、OWASP ASVS 4.0、OWASP SCVS | 漏洞分类与验证深度基线 |
| CWE / CAPEC | 发现归类与攻击模式 |
| CVSS 3.1（FIRST） | 严重级别量化 |
| NIST SSDF（SP 800-218）、SLSA v1 | 安全开发与供应链溯源 |
| 等保 2.0（GB/T 22239-2019）、PCI DSS v4、HIPAA、GDPR | 合规控制项映射（只映射，不出认证结论） |
| 《网络安全法》《数据安全法》《个人信息保护法》 | 数据与行为边界 |

合规映射示例：

| 发现 | 等保 2.0 | PCI DSS v4 | ASVS 4.0 |
|---|---|---|---|
| SQL 注入 | 安全计算环境-输入校验 | 6.2.4、6.5.1 | V5.3 |
| 硬编码密钥 | 身份鉴别/数据保密性 | 6.3.2、8.6 | V6.2 |
| 无审计日志 | 安全审计 | 10.2 | V7 |
| 传输未加密 | 通信传输 | 4.2.1 | V9.1 |
| 越权访问 | 访问控制 | 7.2 | V4.1 |
