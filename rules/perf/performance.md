# 性能审计

静态分析只给线索，性能结论必须靠 profiling 或 EXPLAIN 验证。

## 一、常见问题

| 类型 | 表现 |
|---|---|
| N+1 查询 | 循环内查库/查缓存 |
| 无界查询 | 全表加载、无分页、无 LIMIT |
| 阻塞 I/O | async 路由里 `requests` / `time.sleep` / 同步文件 |
| 算法复杂度 | 嵌套循环、列表 `in`、重复排序 |
| 内存膨胀 | 一次性读大文件、全量加载、缓存无上限 |
| 连接/线程池 | 池过小、未复用、泄漏 |
| 正则回溯 | 灾难性回溯 ReDoS |
| 序列化 | 大对象反复 JSON 编解码 |
| 锁竞争 | 粗粒度锁、持锁 IO |

## 二、N+1

### 危险写法

```python
orders = Order.objects.all()
for order in orders:
    print(order.user.name)  # 每次触发查询
```

### 安全写法

```python
orders = Order.objects.select_related("user").all()
```

```python
orders = Order.objects.prefetch_related("items").all()
```

工具：`nplusone`、Django Debug Toolbar、SQL 日志。

## 三、无界查询

```python
# 危险
items = session.query(Item).all()
data = open("huge.csv").read()

# 安全
items = session.query(Item).limit(100).all()
for chunk in pd.read_csv("huge.csv", chunksize=10000):
    process(chunk)
```

检查：

- 列表接口是否强制分页
- 导出是否流式
- 是否有最大条数限制
- `count()` 是否在大表上频繁调用

## 四、async 阻塞

```python
# 危险
@app.get("/x")
async def x():
    time.sleep(1)
    requests.get(url)

# 安全
@app.get("/x")
async def x():
    await asyncio.sleep(1)
    async with httpx.AsyncClient() as client:
        await client.get(url)
```

CPU 密集：

```python
loop = asyncio.get_running_loop()
result = await loop.run_in_executor(None, cpu_task, data)
```

## 五、算法与数据结构

- 列表成员判断 → `set` / `dict`
- 嵌套循环 → 哈希表、排序后双指针
- 重复排序 → 一次排序复用
- 字符串反复拼接 → `"".join()`
- 大对象深拷贝 → 共享/不可变

## 六、ReDoS

```python
# 危险：嵌套量词
re.match(r"(a+)+$", user_input)

# 安全：限制长度与超时
if len(user_input) > 100:
    raise ValueError
re.match(r"a+$", user_input)
```

检查用户可控输入进入复杂正则的位置；Python `re` 无超时，必要时用 `regex` 库的 timeout 或独立进程。

## 七、内存

- 大文件流式处理
- 生成器替代列表
- 缓存设 TTL 与最大容量（`functools.lru_cache(maxsize=...)`）
- 避免全局累积
- 图片/视频处理限制尺寸

## 八、数据库

```sql
EXPLAIN ANALYZE SELECT ...;
```

检查：

- 高频查询是否有索引
- 是否 `SELECT *`
- 是否有隐式类型转换导致索引失效
- 大表是否分区
- 事务是否过长

## 九、profiling

```bash
python -m cProfile -o prof.out app.py
python -m pstats prof.out
py-spy top --pid <pid>
scalene app.py
pytest --benchmark-only
```

## 十、报告方式

| 级别 | 判定 |
|---|---|
| 高 | 可被外部触发的资源耗尽、O(n²) 以上热点 |
| 中 | 高频路径 N+1、无界查询 |
| 低 | 局部低效、可优化项 |
| 建议 | 压测、监控、索引建议 |

性能项不套 CVSS，报告标题加 `[性能]`，并附测量数据（耗时、查询次数、内存）。
