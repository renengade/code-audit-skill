# 数据一致性

## 一、事务边界

### 检查点

- 多表写入是否在同一事务
- 事务是否覆盖全部副作用
- 是否在事务中调用外部服务/发消息
- 异常是否触发回滚
- 嵌套事务/savepoint 是否正确

### 危险写法

```python
def transfer(from_id, to_id, amount):
    db.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s", (amount, from_id))
    db.commit()
    call_remote_api()  # 失败后无法回滚
    db.execute("UPDATE accounts SET balance = balance + %s WHERE id = %s", (amount, to_id))
    db.commit()
```

### 安全写法

```python
def transfer(from_id, to_id, amount):
    with db.begin():
        db.execute(
            "UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s",
            (amount, from_id, amount),
        )
        db.execute(
            "UPDATE accounts SET balance = balance + %s WHERE id = %s",
            (amount, to_id),
        )
    # 事务提交后再发消息，使用 outbox
    outbox.publish("transfer.completed", {...})
```

## 二、部分失败

### 检查点

- 批量操作是否“部分成功”且无补偿
- 文件写入 + 数据库记录是否一致
- 对象存储上传成功、数据库失败是否留孤儿文件
- 消息发送成功、数据库回滚是否导致脏消息

### 建议

- 使用 outbox 表 + 定时投递
- 使用补偿任务（saga）
- 文件先写临时位置，事务成功后再移动

## 三、隔离级别

| 级别 | 风险 |
|---|---|
| Read Uncommitted | 脏读 |
| Read Committed | 不可重复读 |
| Repeatable Read | 幻读（取决于实现） |
| Serializable | 性能下降 |

检查：

- 余额、库存、配额是否在低隔离级别下读-改-写
- 是否用 `SELECT ... FOR UPDATE`
- 长事务是否持有锁过久

## 四、缓存一致性

### 检查点

- 更新数据库后是否删除/更新缓存
- 缓存 Key 是否含租户/用户
- 是否存在缓存穿透、击穿、雪崩
- 缓存是否存储敏感数据
- 缓存过期策略是否合理

### 常见错误

```python
user = cache.get(f"user:{user_id}")
if not user:
    user = db.get(User, user_id)
    cache.set(f"user:{user_id}", user)  # 更新资料后未失效
```

### 建议

- 写后删除缓存（Cache Aside）
- 关键数据以数据库为准
- 热点 Key 加互斥锁或逻辑过期
- 多租户 Key 前缀隔离

## 五、消息与事件

### 检查点

- 生产与消费是否至少一次/恰好一次
- 重复消费是否幂等
- 消息顺序是否影响状态
- 死信队列与重试上限
- 消息体是否含敏感信息

### 建议

```python
def consume(msg):
    key = f"msg:{msg.id}"
    if not cache.add(key, 1, timeout=86400):
        return
    handle(msg)
```

顺序敏感的场景用分区键，保证同一实体进入同一分区。

## 六、时间与时区

### 检查点

- 数据库存 UTC，展示转本地
- 过期判断是否混用 `datetime.now()` 与 `utcnow()`
- 是否使用 naive datetime
- 跨时区业务日期边界

### 建议

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)
```

## 七、数据迁移

### 检查点

- 迁移是否可回滚
- 是否有大表锁
- 是否删除/重命名列导致旧代码失败
- 是否在迁移中执行危险 SQL
- 是否有数据回填与校验

### 建议

- 先加列、双写、回填、再切读、最后删列
- 大表分批处理
- 迁移脚本纳入审计

## 八、审计清单

- [ ] 多表写入有事务
- [ ] 事务内无外部调用
- [ ] 批量操作有补偿或全成功/全失败
- [ ] 余额/库存使用原子更新或行锁
- [ ] 缓存更新与失效策略明确
- [ ] 消息消费幂等
- [ ] 时间统一 UTC
- [ ] 迁移可回滚、可在低峰执行
- [ ] 关键数据有对账任务
