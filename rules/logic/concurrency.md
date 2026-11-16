# 并发与竞态

## 一、常见竞态

| 场景 | 后果 |
|---|---|
| 检查后使用（TOCTOU） | 越权、重复领取 |
| 读-改-写无锁 | 超卖、余额错乱 |
| 幂等键非原子 | 重复支付 |
| 缓存击穿/雪崩 | 数据库被打穿 |
| 异步任务重复消费 | 重复发货 |
| 全局可变状态 | 请求间数据串扰 |

## 二、TOCTOU

### 危险写法

```python
if not exists(order_id):
    create_order(order_id)  # 并发下会创建多次
```

### 安全写法

```python
try:
    create_order(order_id)
except IntegrityError:
    pass  # 依赖唯一约束
```

```sql
CREATE UNIQUE INDEX uq_order ON orders(order_id);
```

## 三、读-改-写

### 危险写法

```python
stock = db.get(Stock, item_id).quantity
if stock > 0:
    db.update(Stock, item_id, quantity=stock - 1)
```

### 安全写法（原子更新）

```python
updated = db.execute(
    "UPDATE stock SET quantity = quantity - 1 WHERE item_id = %s AND quantity > 0",
    (item_id,),
)
if updated.rowcount == 0:
    raise OutOfStock
```

或使用行锁：

```python
row = db.query(Stock).filter_by(item_id=item_id).with_for_update().one()
```

## 四、幂等键

### 危险写法

```python
if not cache.get(key):
    process()
    cache.set(key, 1)
```

`get` 与 `set` 之间不是原子操作。

### 安全写法

```python
if not cache.add(key, 1, timeout=86400):  # SETNX 原子
    return
process()
```

数据库唯一约束兜底：

```python
try:
    db.add(ProcessedEvent(event_id=event_id))
    db.commit()
except IntegrityError:
    db.rollback()
    return
```

## 五、异步与阻塞

### 危险写法

```python
@app.get("/data")
async def data():
    time.sleep(1)              # 阻塞事件循环
    requests.get(url)          # 同步 HTTP
    open("big.csv").read()     # 同步 IO
```

### 安全写法

```python
import asyncio, httpx, aiofiles

@app.get("/data")
async def data():
    await asyncio.sleep(1)
    async with httpx.AsyncClient() as client:
        await client.get(url)
    async with aiofiles.open("big.csv") as f:
        await f.read()
```

CPU 密集任务用 `run_in_executor` 或独立进程，不要卡住事件循环。

## 六、线程与全局状态

### 检查点

- 模块级可变字典/列表被多请求修改
- `threading.local()` 是否真的隔离
- 单例对象持有请求上下文（用户、租户）
- 连接池/会话是否跨线程共享
- `asyncio` 任务是否持有请求对象

### 危险写法

```python
CURRENT_USER = None  # 全局变量

def set_user(u):
    global CURRENT_USER
    CURRENT_USER = u
```

### 安全写法

使用上下文变量：

```python
from contextvars import ContextVar

current_user = ContextVar("current_user")
current_user.set(user)
```

## 七、锁与死锁

- 锁顺序是否一致
- 是否在持锁时做网络/磁盘 IO
- 是否用超时锁
- 分布式锁是否有续期与唯一 owner
- 数据库事务中是否调用了外部服务

```python
with lock.acquire(timeout=5):
    ...
```

## 八、限流与资源

- 登录、验证码、搜索、导出是否限流
- 线程池/连接池是否有上限
- 队列是否有积压保护
- 大文件是否流式处理

## 九、审计清单

- [ ] 关键写操作有唯一约束或原子更新
- [ ] 幂等键使用原子操作
- [ ] 支付/退款回调可重复执行而不产生副作用
- [ ] async 路由无阻塞调用
- [ ] 无跨请求全局可变状态
- [ ] 锁有顺序与超时
- [ ] 事务内不调用外部服务
- [ ] 关键接口有限流
- [ ] 队列消费有幂等与重试上限
