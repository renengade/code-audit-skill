# 业务逻辑审计

业务逻辑漏洞是黑盒与 SAST 的盲区。审计前先画出「入口 → 权限 → 状态 → 数据」四要素。

## 一、权限与对象归属（IDOR）

### 检查点

- 每个接收对象 ID 的接口，是否校验 `owner` / `tenant` / `org`
- 列表/导出/批量接口是否逐条校验
- 管理接口是否校验角色，而非仅登录
- 前端隐藏按钮不等于后端鉴权

### 危险写法

```python
@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(current_user)):
    return db.get(Order, order_id)  # 未校验归属
```

### 安全写法

```python
@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(current_user)):
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.owner_id == user.id,
    ).first()
    if not order:
        raise HTTPException(404)
    return order
```

### 审计问题

1. 对象 ID 是否可枚举？
2. 租户 ID 来自请求还是会话？
3. 批量接口是否用 `in` 查询后跳过权限？
4. 导出接口是否绕过列表权限？

## 二、流程绕过

### 检查点

- 金额、数量、折扣、运费是否由前端传入
- 支付回调是否校验签名、金额、订单状态
- 验证码是否一次性、有有效期、绑定场景
- 优惠券/积分是否可重复使用
- 审批流是否可跳过节点
- 试用/会员是否可反复领取

### 危险写法

```python
@app.post("/pay")
def pay(order_id: int, amount: Decimal):
    order = db.get(Order, order_id)
    order.paid_amount = amount  # 金额由客户端决定
    order.status = "paid"
```

### 安全写法

```python
@app.post("/pay")
def pay(order_id: int, user=Depends(current_user)):
    order = get_owned_order(order_id, user)
    amount = order.total_amount  # 服务端计算
    verify_payment_signature(order, amount)
    if order.status != "pending":
        raise HTTPException(409)
    order.status = "paid"
```

### 审计问题

1. 关键金额/状态是否服务端计算？
2. 回调是否验签、验金额、验状态？
3. 是否有重复提交防护？
4. 验证码是否可无限复用？

## 三、状态机

### 检查点

- 订单/支付/退款/审批状态是否只能按合法边跳转
- 是否允许回滚到已支付/已完成
- 取消后是否还能发货
- 退款后是否还能再次退款

### 建议做法

```python
ALLOWED = {
    "created": {"paid", "cancelled"},
    "paid": {"shipped", "refunded"},
    "shipped": {"completed", "refunded"},
    "completed": {"refunded"},
}

def transition(order, target: str):
    if target not in ALLOWED.get(order.status, set()):
        raise ValueError(f"illegal transition {order.status} -> {target}")
    order.status = target
```

### 审计问题

1. 状态字段是否可被客户端直接赋值？
2. 是否存在“万能更新”接口？
3. 并发下状态是否会被覆盖？

## 四、幂等与重放

### 检查点

- 支付回调、退款、下单、领券是否幂等
- 是否有幂等键（订单号 + 事件 ID）
- 重试是否会产生副作用
- 请求是否可重放（无 nonce/时间戳）

### 建议做法

```python
def handle_callback(event_id: str, payload: dict):
    if not cache.add(f"cb:{event_id}", 1, timeout=86400):
        return {"ok": True}  # 已处理
    process(payload)
    return {"ok": True}
```

数据库唯一约束是最后一道防线：

```sql
ALTER TABLE payments ADD CONSTRAINT uq_event UNIQUE (event_id);
```

## 五、边界与类型

### 检查点

- `None` / 空列表 / 空字符串
- 负数、0、超大数、浮点精度
- 超长字符串、超长数组
- 时区、日期边界、闰年
- 分页参数为负或超大

### 危险写法

```python
page = int(request.args.get("page"))
limit = int(request.args.get("limit"))
items = query.offset(page * limit).limit(limit)  # 无上限
```

### 安全写法

```python
page = max(1, int(request.args.get("page", 1)))
limit = min(100, max(1, int(request.args.get("limit", 20))))
```

## 六、Mass Assignment

### 检查点

- 序列化器/模型是否允许写 `is_admin`、`role`、`balance`、`owner_id`
- 是否用 `**request.json` 直接构造对象
- 是否用 `setattr` 批量赋值

### 危险写法

```python
User(**request.json).save()
```

### 安全写法

```python
class UserCreate(BaseModel):
    username: str
    password: str

data = UserCreate(**request.json)
```

## 七、审计清单

- [ ] 所有对象 ID 接口都校验归属
- [ ] 租户条件来自会话，不来自请求
- [ ] 金额/数量/折扣服务端计算
- [ ] 支付回调验签、验金额、验状态
- [ ] 验证码一次性、有有效期
- [ ] 状态机只允许合法边
- [ ] 关键操作幂等
- [ ] 分页/批量有上限
- [ ] 序列化器无敏感可写字段
- [ ] 导出/搜索/统计接口不放宽权限
