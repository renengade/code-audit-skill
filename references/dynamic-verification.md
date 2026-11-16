# 动态验证

静态审计只能证明“代码看起来危险”，不能证明“可利用”。本文件定义在获得授权后，如何安全地验证漏洞与后门。

## 一、前置条件

必须同时满足：

1. 用户明确授权动态测试。
2. 目标为测试环境或本地副本，**绝不针对生产**。
3. 在隔离容器/虚拟机中执行，可随时销毁。
4. 不接入真实数据，使用假数据与 canary。
5. 明确测试窗口与回滚方案。

默认策略：**只写方法，不执行**。

## 二、隔离环境

```bash
# 示例：无网络、只读根文件系统、临时目录可写
docker run --rm -it \
  --network none \
  --read-only \
  --tmpfs /tmp \
  -v "$PWD/target:/app:ro" \
  -w /app \
  python:3.12-slim bash
```

需要观察外联时，改为受控网络并抓包：

```bash
docker network create --internal audit-net
# 容器接入 audit-net，另起抓包容器
tcpdump -i any -nn -w /tmp/audit.pcap
```

## 三、行为观察

```bash
# 进程与网络
strace -f -e trace=execve,network,openat -o /tmp/trace.log python app.py

# 文件系统变化
find / -xdev -newer /tmp/start -type f 2>/dev/null

# DNS 与外联
tcpdump -i any -nn 'port 53 or port 80 or port 443'
```

重点看：

- `execve`：是否拉起 shell、`curl`、`wget`、`nc`
- `connect`：是否连硬编码 IP/域名
- `openat`：是否读 `~/.ssh`、`.aws/credentials`、`.env`
- 新增文件：crontab、`.bashrc`、systemd、`.pth`

## 四、后门触发

| 手法 | 做法 |
|---|---|
| 时间炸弹 | 修改容器时间到未来日期，或 `libfaketime` |
| 条件触发 | 尝试特殊 Header、UA、IP、用户名、魔法参数 |
| 环境判断 | 伪造/去除 `SANDBOX`、`CI`、`DEBUG` 等变量 |
| 延迟执行 | 观察 `atexit`、后台线程、定时器 |
| 编码载荷 | 在隔离环境 hook `exec`/`eval`，打印解密后的代码 |
| 反序列化 | 用无害 payload 触发，观察是否执行 |

Hook 示例（仅隔离环境）：

```python
import builtins

_orig_exec = builtins.exec

def traced_exec(source, *args, **kwargs):
    print("=== EXEC ===")
    print(source)
    return _orig_exec(source, *args, **kwargs)

builtins.exec = traced_exec
```

## 五、canary 与假凭据

- 放假 AWS key、假 Token、假数据库密码，观察是否被外传。
- 在 `~/.ssh`、`~/.aws` 放置 canary 文件，监控读取。
- 用 DNS canary 域名（如 `*.canary.example`）检测解析。
- 绝不使用真实凭据。

## 六、覆盖率辅助

```bash
coverage run -m pytest
coverage report -m
```

关注“正常路径从不执行”的死代码，可能是隐藏触发分支。

## 七、验证记录

每条验证记录：

- 时间、环境、commit
- 输入/请求
- 观察到的行为
- 是否可利用、影响范围
- 清理与回滚结果

## 八、禁止事项

1. 不在生产环境执行。
2. 不使用真实用户数据。
3. 不进行破坏性操作（删库、写系统目录、持久化）。
4. 不对外发起真实攻击或扫描第三方。
5. 不把恶意样本带出隔离环境。

## 九、无法动态验证时

在报告中写：

> 该发现基于静态数据流分析，因缺少可运行环境/授权，未执行动态验证。建议在测试环境按 `dynamic-verification.md` 复现后再定级。
