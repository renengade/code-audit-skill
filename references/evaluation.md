# 评估方法（AACR-Bench）

## 一、AACR-Bench 是什么

阿里 Open Code Review 团队开源的**代码审查质量基准**：

- 50 个真实开源仓库、200 个真实 Pull Request、10 种编程语言
- 由 80+ 高级工程师交叉标注出 **1505 条 ground truth 缺陷**
- 地址：`https://huggingface.co/datasets/Alibaba-Aone/aacr-bench`

## 二、主要作用

1. **客观度量**：把“这个审计工具好不好”从主观感觉变成可测指标（Precision / Recall / F1 / 耗时 / token 成本）。
2. **横向对比**：同一模型底座下，比较不同工具/agent 的差距（OCR 用它证明了自己比通用 agent 精度更高、token 更省）。
3. **对本 skill**：用 Python 子集实测误报率与检出率，验证「覆盖强制」「精度优先」等改动是否真的提升 precision 而不明显牺牲 recall。

## 三、指标定义

| 指标 | 公式 | 说明 |
|---|---|---|
| Precision | 正确发现 / 全部报告发现 | 越高 = 误报越少 |
| Recall | 正确发现 / ground truth 总数 | 越高 = 漏报越少 |
| F1 | 2·P·R / (P + R) | 综合分 |

**命中判定口径**：报告的发现与 ground truth 满足“同一文件 + 行号偏差 ≤3 行 + 根因同类”视为命中。三条件必须同时满足，防止“蹭中”。

## 四、对本 skill 的实测流程（近似校准）

1. 从数据集中筛选 **Python 语言**的仓库与 PR。
2. 检出对应 commit，运行本 skill（security 或 logic 模式），限定审到该 PR 涉及文件。
3. 汇总 findings.json，与 ground truth 对齐，计算 P / R / F1。
4. 把结果写入评估记录（建议放 `evaluation-log.md` 或仓库 issue），作为规则增删的依据：
   - Precision 偏低 → 收紧规则判定条件、提高误报排除要求
   - Recall 偏低 → 补充规则触发点、放宽命中的文件分发

## 五、局限（必须写进结论）

- AACR-Bench 是 **PR / diff 视角**，本 skill 是整库白盒审计，只能近似校准，不能直接等同。
- 数据集多语言混合，仅取 Python 子集，样本量有限。
- ground truth 的标注口径（bug/安全/可维护性混合）与本 skill 的 CWE/CVSS 口径不完全一致，统计时需按类别拆分。

## 六、与自检的关系

- `scripts/selftest.py`：离线冒烟测试，保证**规则与脚本不回归**（每次改动必跑）。
- AACR-Bench：**质量校准**，衡量“找得准不准、全不全”（阶段性跑，非每次）。

两者互补，不可互相替代。
