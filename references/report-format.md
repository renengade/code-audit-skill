# 报告格式

## 一、报告骨架

```markdown
# Python 安全审计报告

## 1. 摘要

- 项目 / 模块：
- 版本 / commit：
- 审计模式：
- 审计时间：
- 总体风险：Critical / High / Medium / Low
- 发现统计：严重 a / 高危 b / 中危 c / 低危 d / 信息 e；待验证 f；误报 g

## 2. 审计范围

| 项 | 内容 |
|---|---|
| 代码 | |
| 版本 | |
| 授权 | 授权编号/日期、确认人 |
| 维度 | |
| 方法 | |
| 动态验证 | |
| 未覆盖 | |

**结论边界**：本报告仅代表上述范围与方法下的结果，“未发现”不代表“不存在”。

## 3. 方法论

- 侦察：框架、入口、依赖、配置
- 自动化：Bandit / Semgrep / ruff / pip-audit / hunt_anomalies
- 人工：source→sink、鉴权、业务逻辑、配置
- 验证：最小 PoC / 单测 / 请求响应

## 4. 风险分布

| 级别 | 数量 | 主要类型 |
|---|---|---|
| Critical | | |
| High | | |
| Medium | | |
| Low | | |
| Info | | |

## 5. 审计覆盖

| 项 | 数值 |
|---|---|
| total_files | 待审文件总数 |
| reviewed_files | 已审文件数 |
| skipped_files | 跳过数 |
| coverage_rate | reviewed / total |

skipped 明细（每条必须有具体原因，禁止静默遗漏）：

| 文件 | 原因 |
|---|---|

## 6. 发现详情

（按严重级别排序，每条使用下方模板）

## 7. 系统性建议

- 编码规范 / 安全库 / 框架配置 / CI 门禁 / 依赖治理

## 8. 误报与线索

| 告警 | 位置 | 排除理由 |
|---|---|---|

## 9. 附录

- 工具版本与输出、扫描范围、证据目录
```

## 二、单条发现模板

````markdown
### VULN-001 用户搜索接口存在 SQL 注入

| 项 | 内容 |
|---|---|
| 级别 | 高危（CVSS 3.1: 8.3） |
| category | security |
| CWE | CWE-89 |
| 位置 | `app/views/search.py:42-45` @ `a1b2c3d`（start_line=42, end_line=45） |
| 状态 | 已确认 |
| 影响 | 可读取任意表数据，含用户凭证 |

**数据流**

`request.args["q"]` → `build_query()` → `cursor.execute(f"SELECT ... '{q}'")`

**证据**

```http
GET /search?q=' OR 1=1-- HTTP/1.1
Host: example.local
```

返回 200 且结果条数异常。

**修复建议**

```python
cursor.execute("SELECT * FROM items WHERE name = %s", (q,))
```

补充参数化查询编码规范与回归测试。

**参考**

- OWASP SQL Injection
- CWE-89
````

## 三、后门排查结论模板

```markdown
### 后门与恶意代码排查

| 检查项 | 结果 |
|---|---|
| 编码/混淆载荷 | 未发现 / 发现 N 处 |
| 异常外联 | 未发现 / 发现 N 处 |
| 安装钩子 | 未发现 / 发现 N 处 |
| 持久化 | 未发现 / 发现 N 处 |
| Git 历史 | 未发现 / 发现 N 处 |
| 二进制/编译产物 | 未发现 / 发现 N 处 |

结论：在本次静态审计范围内未发现确认后门；M 处标记为高度可疑/待动态验证。
静态审计无法排除运行时解密、条件触发、编译产物内的恶意逻辑，也不能证明后门不存在。
```

## 四、findings.json 结构

```json
{
  "meta": {
    "project": "example",
    "root": "/path/to/project",
    "commit": "a1b2c3d",
    "mode": "security",
    "generated_at": "2026-11-09T12:00:00Z",
    "scope": ["src/", "config/"],
    "excluded": ["venv", ".git", "__pycache__"],
    "dynamic_verification": false
  },
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1,
    "info": 0,
    "pending": 1,
    "false_positive": 0
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "用户搜索接口存在 SQL 注入",
      "category": "security",
      "severity": "high",
      "cvss": 8.3,
      "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
      "cwe": "CWE-89",
      "status": "confirmed",
      "file": "app/views/search.py",
      "start_line": 42,
      "end_line": 45,
      "commit": "a1b2c3d",
      "source": "request.args['q']",
      "sink": "cursor.execute(f\"SELECT ... '{q}'\")",
      "dataflow": [
        "request.args['q']",
        "build_query(q)",
        "cursor.execute(f\"...\")"
      ],
      "evidence": "GET /search?q=' OR 1=1-- 返回异常条数",
      "impact": "可读取任意表数据",
      "fix": "cursor.execute(\"SELECT ... WHERE name = %s\", (q,))",
      "refs": ["OWASP SQL Injection", "CWE-89"]
    }
  ],
  "false_positives": [
    {
      "tool": "bandit",
      "rule": "B404",
      "file": "scripts/backup.py",
      "line": 12,
      "reason": "仅导入 subprocess，未使用，且脚本不对外暴露"
    }
  ]
}
```

字段约定：

- `category` 枚举：`bug` / `security` / `performance` / `maintainability` / `test` / `style` / `documentation` / `other`；质量项用 `maintainability`，性能项用 `performance`，不再用标题前缀。
- `severity` 取值：`critical` / `high` / `medium` / `low` / `info`。
- `status` 取值：`confirmed` / `pending` / `false_positive`。
- `start_line` / `end_line` 为整数；**两者均为 0 表示定位失败**（语义与 OCR 对齐），并在 `evidence` 说明原因。单行问题 `start_line == end_line`。
- 工具原始输出（scan/hunt 脚本）用单字段 `line`，写入 findings.json 时换算为 `start_line = end_line = line`。

## 五、写作要求

1. 先结论后细节，摘要能让非技术负责人读懂。
2. 每条发现都能回溯到 `file:line` 和 commit。
3. **定位自检**：写入前重读该发现的 `file:line` 附近代码，确认行号、内容、数据流三者一致；不一致则修正或降级为线索。
4. **覆盖率四件套必填**：total_files / reviewed_files / skipped_files / coverage_rate；每个 skipped 都有具体原因。
5. 修复建议给代码，不写“加强校验”。
6. 同一根因合并，避免重复计数。
7. 敏感值统一 `<REDACTED>`。
8. 不把工具原始输出直接贴进正文，放附录。
