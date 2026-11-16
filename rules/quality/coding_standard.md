# 编码规范与质量

## 原则

1. **格式与风格交给工具**，不要用 LLM 逐行判 PEP 8。
2. 只对工具无法判断的部分做人工评审：异常语义、资源生命周期、可维护性风险。
3. 质量问题不套 CVSS，单独列「质量改进项」。

## 一、工具与命令

```bash
ruff check .
ruff format --check .
mypy .
pyright
radon cc -s -a .
radon mi -s .
vulture .
pytest --cov=src --cov-report=term-missing
```

| 工具 | 关注 |
|---|---|
| `ruff` | 未使用导入、未定义名、复杂度、常见缺陷 |
| `mypy` / `pyright` | 类型不一致、`Optional` 未处理 |
| `radon` | 圈复杂度、可维护性指数 |
| `vulture` | 死代码、未使用函数/变量 |
| `pytest-cov` | 覆盖率、未覆盖分支 |

## 二、异常处理

### 危险写法

```python
try:
    do_something()
except Exception:
    pass
```

```python
except Exception:
    return True  # 失败开放
```

### 建议

```python
try:
    do_something()
except SpecificError as exc:
    logger.warning("do_something failed: %s", exc)
    raise
```

检查：

- 是否吞掉异常后继续放行
- 是否捕获过宽（`Exception` / `BaseException`）
- 是否泄露堆栈给用户
- 是否在 `finally` 中释放资源

## 三、资源管理

### 危险写法

```python
f = open(path)
data = f.read()  # 异常时未关闭
```

```python
conn = db.connect()
cursor = conn.cursor()
```

### 建议

```python
with open(path) as f:
    data = f.read()
```

```python
with db.connect() as conn, conn.cursor() as cur:
    ...
```

检查：

- 文件/连接/锁是否用 `with` 或 `finally`
- 线程池/进程池是否关闭
- 长生命周期缓存是否设上限
- 大文件是否流式处理

## 四、类型与空值

```python
def get_user(user_id: int | None) -> User | None:
    if user_id is None:
        return None
    ...
```

检查：

- `Optional` 是否在使用前判空
- `dict.get()` 返回值是否判空
- `Any` 是否滥用
- 返回值类型是否与声明一致

## 五、复杂度与重复

- 单个函数圈复杂度 > 10 需拆分
- 嵌套超过 4 层需重构
- 重复代码块 > 20 行考虑抽取
- 超长函数/文件需说明

## 六、命名与注释

- 变量/函数名表达意图
- 公共 API 有 docstring
- 复杂逻辑解释“为什么”，不是“做什么”
- 注释与代码同步，避免误导

## 七、测试

- 核心路径有单测
- 安全相关有回归测试（鉴权、参数化查询、路径校验）
- 测试中不放真实密钥
- 测试数据脱敏

## 八、报告方式

| 级别 | 示例 |
|---|---|
| 高 | 异常吞掉导致鉴权失败开放、资源泄漏影响可用性 |
| 中 | 复杂度超标、关键路径无测试、类型缺失导致运行错误 |
| 低 | 命名、注释、格式 |
| 建议 | 引入 pre-commit、统一规范 |

报告建议：

```markdown
### [质量] app/services/order.py 圈复杂度 28

- 位置：`app/services/order.py:120`
- 工具：`radon cc -s`
- 影响：分支过多，易漏测试，修改风险高
- 建议：拆分为 `validate_order` / `calculate_amount` / `persist_order`
```
