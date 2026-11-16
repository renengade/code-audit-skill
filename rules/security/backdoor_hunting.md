# 后门与恶意代码排查

目标：发现**故意隐藏**的访问通道、数据外传、持久化与逻辑炸弹。
注意：静态排查只能提高发现概率，不能证明后门不存在。

## 可信度分级

| 级别 | 判定 |
|---|---|
| 确认后门 | 触发条件 + 载荷 + 外联/持久化证据 |
| 高度可疑 | 混淆执行、无业务理由的外联、安装钩子 |
| 待动态验证 | 静态只能看到壳，需要沙箱运行 |
| 未发现 | 仅代表本次范围内没看到 |

## A. 执行链异常

```bash
rg -n "exec\(|eval\(|compile\(|__import__|getattr\(|globals\(\)|locals\(\)" --type py
rg -n "base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|rot13" --type py
rg -n "\\\\x[0-9a-fA-F]{2}" --type py
```

关注：

- 解码/解压后直接 `exec`/`eval`
- 超长单行、字符码拼接、`chr()` 链
- 动态取函数名、动态导入
- 正常业务不需要的 `subprocess` / `os.system`

## B. 网络外联

```bash
rg -n "socket\.|connect\(|pty\.spawn|dup2|/dev/tcp|nc -e|bash -i" --type py
rg -n "requests\.(get|post)|httpx\.|urllib|aiohttp|webhook|telegram|discord|pastebin" --type py
rg -n "stratum\+tcp|xmrig|miner" .
rg -n "\b(?:\d{1,3}\.){3}\d{1,3}\b" --type py
```

关注：

- 硬编码 IP/域名、短链接、动态域名
- 反弹 shell：`socket` + `pty.spawn` / `bash -i >& /dev/tcp/...`
- 把环境变量、文件内容 POST 到外部
- DNS 外传、Telegram Bot、Discord Webhook、GitHub Gist
- 挖矿：`stratum+tcp`、`xmrig`

## C. 凭据与数据收集

```bash
rg -n "\.ssh|id_rsa|\.aws/credentials|\.env|keyring|cookies|Login Data|clipboard" --type py
rg -n "os\.environ|environ\.copy|dict\(os\.environ\)" --type py
```

关注：

- 读取 SSH 私钥、云凭证、浏览器 Cookie、剪贴板
- 遍历环境变量并外发
- 读取数据库配置后打包上传

## D. 持久化

```bash
rg -n "atexit|signal\.|threading\.Timer|crontab|systemd|autostart|\.bashrc|\.profile|sitecustomize|usercustomize|\.pth" .
```

关注：

- `atexit` 注册恶意清理/回连
- 写 crontab、systemd、`~/.config/autostart`
- 修改 `site-packages`、放置 `.pth`（导入即执行）
- 修改 `PYTHONSTARTUP`、`conftest.py`、`__init__.py`

## E. 隐藏与反分析

```bash
rg -n "gettrace|settrace|setprofile|ptrace|SANDBOX|CI|DEBUG|VM|virtualbox|qemu" --type py
rg -n "datetime\.now|time\.time|date\.today" --type py
```

关注：

- 检测调试器/沙箱/虚拟机后改变行为
- 特定日期/时间才执行
- 正常路径不可达的死代码
- 依赖特定 UA/IP/用户名/魔法参数触发

## F. 混淆与编码

```bash
rg -n "[A-Za-z0-9+/]{80,}={0,2}" --type py
rg -n "b['\"][A-Za-z0-9+/=]{40,}" --type py
```

关注：

- 高熵字符串、超长 base64、嵌套压缩
- `pickle` 载荷、`marshal` 字节码
- 与业务无关的加密常量

## G. 供应链与安装钩子

```bash
rg -n "cmdclass|install_requires|dependency_links|postinstall|preinstall" setup.py setup.cfg pyproject.toml 2>/dev/null
rg -n "extra-index-url|index-url|git\+https|--trusted-host" requirements*.txt pyproject.toml 2>/dev/null
find . -name "*.pth" -o -name "*.so" -o -name "*.pyd" -o -name "*.pyc" -o -name "*.whl"
```

关注：

- `setup.py` 自定义 `cmdclass` 在安装期执行
- `.pth` 文件（Python 启动自动执行）
- wheel 内二进制、异常大的包
- 包名拼写近似、维护者近期变更
- 依赖混淆：私有包名 + 公共源

## H. 仓库与历史异常

```bash
git log --all --oneline --decorate
git log --all -p -- "*.py" | rg -n "exec\(|eval\(|base64|socket|/dev/tcp"
git log --all --diff-filter=D --name-only
git grep -n "eval(" $(git rev-list --all) -- "*.py" 2>/dev/null | head
ls -la .git/hooks
rg -n "curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|pull_request_target" .github Dockerfile* 2>/dev/null
```

关注：

- 先提交后门再删除
- 异常作者/时间/提交信息
- Git hooks 被替换
- CI 配置里的命令注入与密钥外传
- 文档、示例、Notebook 隐藏 cell

## I. 编译产物

```bash
find . -name "*.pyc" -o -name "*.so" -o -name "*.pyd" -o -name "*.whl" -o -name "*.zip"
strings suspicious.so | rg -n "http|socket|exec|/bin/sh"
```

关注：

- 源码与 `.pyc` 时间戳/哈希不一致
- 未在源码中出现的字符串
- 可疑二进制依赖

## Semgrep 规则

后门线索规则已抽成独立文件，离线可用：

```bash
semgrep --config rules/security/semgrep_rules.yaml <目标目录>
```

文件位于 `rules/security/semgrep_rules.yaml`，包含全部 PY-01～PY-16 规则与后门线索规则（`category: backdoor-lead`）：

- `pysec-bd-decode-exec`：解码/解压后动态执行
- `pysec-bd-reverse-shell`：`pty.spawn` / `dup2` 反弹 shell 原语
- `pysec-bd-dynamic-import`：动态导入
- `pysec-bd-ci-curl-sh` / `pysec-bd-ci-pr-target`：CI 注入与 `pull_request_target`
- `pysec-bd-private-key` / `pysec-bd-aws-key`：私钥与云 AK 泄露

修改规则后自检：

```bash
uvx --python 3.12 semgrep --config rules/security/semgrep_rules.yaml <样例目录>
python3 scripts/selftest.py
```

## 排查流程

1. 先跑 `scripts/hunt_anomalies.py` 得到候选点。
2. 按 A–I 分组人工复核，记录业务理由。
3. 无法解释的混淆/外联/安装钩子标「高度可疑」。
4. 需要确认时，按 `references/dynamic-verification.md` 在隔离环境验证。
5. 报告中单独出「后门排查结论」，不混入普通漏洞统计。

## 禁止事项

- 不在宿主机直接运行可疑代码
- 不把样本带出隔离环境
- 不对外发起真实连接
- 不以“未发现”推断“不存在”
