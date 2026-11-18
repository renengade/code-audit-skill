# code-audit-skill

一个 [OpenCode](https://opencode.ai) Skill：对 Python 项目做**白盒安全代码审计**。
SAST 自动化 + 人工 source→sink 数据流追踪 + 依赖/配置/后门排查，输出可复现、可修复、可归档的结构化报告。

## 特性

- **6 个审计模式**：`security`（默认）/ `logic` / `arch` / `quality` / `perf` / `full`，按需加载规则，不撑爆上下文
- **38 条内置 Semgrep 规则**：`rules/security/semgrep_rules.yaml`，纯本地配置，离线可用
- **16 类 Python 漏洞规则（PY-01～PY-16）**：命令执行、SQL 注入、SSTI、反序列化、路径穿越、SSRF、XXE、认证授权、加密、密钥、越权、IDOR……每条含触发点 / 可控源 / 判定条件 / 误报排除 / 修复 / CWE
- **后门与恶意代码排查**：混淆载荷、反弹 shell、异常外联、持久化、安装钩子、CI 注入、Git 历史、编译产物
- **框架专项**：Django / Flask / FastAPI 配置基线与代码审计点
- **业务逻辑**：越权、流程绕过、状态机、幂等、并发竞态、数据一致性
- **3 个零依赖扫描脚本**（仅标准库，工具缺失自动跳过）：
  - `scan.py` — Bandit / Semgrep / ruff 归一化输出
  - `check_deps.py` — 锁文件解析 + pip-audit / OSV CVE 查询
  - `hunt_anomalies.py` — 后门/混淆/外联/凭据启发式
  - `selftest.py` — 离线验收测试
- **证据链强制**：每条发现必须给出 `文件:行号` + source→sink 数据流 + 修复代码
- **覆盖强制 + 定位自检**：每个待审文件必须 `reviewed` 或 `skipped(原因)`，报告带 coverage_rate；发现写入前重读代码核对行号与数据流
- **被审代码视为不可信输入**：防 prompt injection，指令性注释不得改变审计行为
- **明确能力边界**：「未发现」≠「不存在」；DAST/IAST/合规认证只写交接方法

## 安装

```bash
git clone https://github.com/renengade/code-audit-skill.git
mkdir -p ~/.config/opencode/skills
ln -s "$(pwd)/code-audit-skill" ~/.config/opencode/skills/code-audit-skill
```

或在 `opencode.jsonc` 中添加 skill 目录：

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "skills": ["/path/to/code-audit-skill"]
}
```

> 目录名决定 skill ID：本仓库根目录即 skill 目录，ID 为 `code-audit-skill`（见 SKILL.md）。若改用其他目录名，ID 亦随之变化。

## 使用

对 OpenCode 说：

```text
审计 src/                          # 默认 security 模式
用 logic 模式审计 src/payment/     # 业务逻辑/越权/并发
对 . 做后门排查
```

脚本也可单独运行：

```bash
python3 scripts/scan.py --path /path/to/project --json scan.json
python3 scripts/check_deps.py --path /path/to/project --online --json deps.json
python3 scripts/hunt_anomalies.py --path /path/to/project --json anomalies.json
python3 scripts/selftest.py       # 离线自检
```

- `scan.py` 默认使用内置 Semgrep 规则（离线）；`--use-uvx` 可自动拉取 semgrep/bandit（需联网，semgrep 固定 Python 3.12）
- `check_deps.py --online` 查询 OSV；`--offline` 完全离线

## 审计范围

| 维度 | 内容 |
|---|---|
| 安全漏洞 | 注入、认证授权、越权、反序列化、SSRF/XXE、加密、文件、配置、泄露 |
| 业务逻辑 | 权限校验、流程绕过、状态机、幂等、并发、事务 |
| 第三方组件 | 已知 CVE、供应链投毒、安装钩子、SBOM |
| 设计与架构 | 信任边界、最小权限、暴露面、威胁建模 |
| 规范与质量 | 异常处理、资源管理、类型、复杂度、性能（独立分级，不套 CVSS） |

详见 [`references/scope-matrix.md`](references/scope-matrix.md)。

## 合规与法律边界

1. 仅在**书面授权**范围内审计，授权须明确目标、范围、方法与时间窗口
2. 不使用审计中发现的凭据访问范围外系统；不绕过访问控制获取数据
3. 不复制、不外传项目中的密钥与个人数据；证据打码 `<REDACTED>`
4. 遵守《网络安全法》《数据安全法》《个人信息保护法》及所在地法律
5. 可映射 OWASP/等保/PCI 控制项，但**不出具合规认证结论**
6. 后门排查仅用于防御目的

## 对齐标准

OWASP Top 10 (2021) · OWASP ASVS 4.0 · CWE/CAPEC · CVSS 3.1 · NIST SSDF (SP 800-218) · SLSA v1 · 等保 2.0 · PCI DSS v4

## 限制

- 静态审计无法排除运行时解密、条件触发、编译产物内的恶意逻辑
- 不替代 DAST/IAST/渗透测试
- 工具告警只是线索，必须人工复核

## License

[MIT](LICENSE)
