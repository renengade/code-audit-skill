# 供应链安全

## 一、依赖清单来源

| 文件 | 解析方式 |
|---|---|
| `requirements*.txt` | 逐行解析，忽略注释、`-r`、`-e`、URL |
| `pyproject.toml` | `project.dependencies`、`dependency-groups`、`poetry.dependencies`、`optional-dependencies` |
| `poetry.lock` | TOML `package[]` 的 `name` / `version` |
| `uv.lock` | TOML `package[]` 的 `name` / `version` |
| `Pipfile.lock` | JSON `default` / `develop` |
| `setup.py` / `setup.cfg` | `install_requires`、`extras_require` |
| vendored 目录 | `vendor/`、`third_party/`、`_vendor/` 下的源码 |

## 二、已知漏洞

优先用工具，不要硬编码库名：

```bash
pip-audit -r requirements.txt
pip-audit --desc
uvx pip-audit -r requirements.txt
```

离线或工具不可用时，用 OSV 查询：

```bash
curl -s https://api.osv.dev/v1/query \
  -d '{"package":{"name":"django","ecosystem":"PyPI"},"version":"3.2.0"}'
```

记录：包名、当前版本、修复版本、CVE/OSV ID、CVSS、是否直接依赖。

注意：

- 只报告，不自动升级，不改锁文件。
- 区分直接依赖与传递依赖，优先修直接依赖。
- pip-audit 的 JSON 输出不带严重级别，需按 CVE/别名到 OSV/NVD 查询或在报告中标注 `unknown`。
- 无修复版本的，给出缓解建议（禁用功能、WAF、隔离）。

## 三、供应链投毒

### 包名与来源

- 拼写近似：`reqeusts`、`urlib3`、`cryptograpy`
- 维护者近期变更、单维护者、下载量异常
- 包名与知名包相似但发布者不同
- 版本号突然跳变、发布时间异常

### 依赖混淆

```text
--extra-index-url https://pypi.org/simple   # 私有包名可能被公共源抢注
--index-url http://internal/simple
git+https://...                             # 不可审计的直装
```

检查：

- 私有包名是否在公共 PyPI 存在同名包
- 是否固定版本/哈希（`--require-hashes`）
- 是否使用不可信源或 HTTP 源

### 安装期执行

```bash
rg -n "cmdclass|install_requires|setup_requires|dependency_links" setup.py setup.cfg pyproject.toml
find . -name "*.pth"
```

- `setup.py` 自定义 `cmdclass`：安装时执行任意代码
- `.pth` 文件：Python 启动时自动执行其中的 `import`
- wheel 内 `.so` / `.pyd` / 二进制：需 `strings` 检查
- `postinstall` / `preinstall` 脚本（npm 风格，Python 少见但需确认）

### vendored 代码

- `vendor/`、`_vendor/`、`third_party/` 是否与上游一致
- 是否被手工修改
- 是否包含额外网络调用或后门

## 四、SBOM 与溯源

syft 是 Go 二进制，不能用 `uvx` 运行：

```bash
# 方式一：官方安装脚本
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 方式二：Docker
docker run --rm -v "$PWD:/src" anchore/syft:latest dir:/src -o cyclonedx-json=sbom.json
```

纯 Python 工具可用 `uvx`：

```bash
uvx cyclonedx-py environment -o sbom.json
uvx pip-licenses --format=json
```

记录：

- 组件清单与版本
- 许可证（GPL/AGPL 传染性，仅提示，不出法律结论）
- 是否可追溯到官方发布
- 哈希/签名校验（`--require-hashes`、sigstore）
- 构建/发布溯源：SLSA 等级、`--provenance`、制品签名（cosign）

参考框架：NIST SSDF（SP 800-218）PS.1/PS.2/PS.3、SLSA v1、OWASP SCVS。

## 五、CI/CD 与发布链路

```bash
rg -n "pull_request_target|workflow_run|secrets\.|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh" .github
rg -n "FROM |RUN |ADD |COPY " Dockerfile*
```

关注：

- `pull_request_target` + 检出 PR 代码 + 使用 secrets
- 未固定版本的 Action（`@main`、`@v1`）
- `curl | bash`、不可信下载源
- 构建产物未签名、发布权限过大
- 令牌权限过宽（`contents: write`、`id-token: write`）

## 六、响应建议

1. 立即隔离受影响版本。
2. 升级到修复版本，或临时禁用相关功能。
3. 轮换可能泄露的凭据。
4. 加锁文件、哈希校验、依赖审计 CI。
5. 建立 SBOM 与依赖变更评审。

## 七、报告字段

| 字段 | 示例 |
|---|---|
| 包名 | `django` |
| 当前版本 | `3.2.0` |
| 修复版本 | `3.2.25` |
| 漏洞 ID | `CVE-2024-xxxxx` / `GHSA-...` |
| 级别 | High |
| 依赖类型 | 直接 / 传递 |
| 影响 | 反序列化 RCE / DoS |
| 建议 | 升级 / 缓解 / 隔离 |
