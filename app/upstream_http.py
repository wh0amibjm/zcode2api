"""上游 HTTP 的公共构件：进程级共享 TLS 上下文。

为什么共享：httpx.AsyncClient 每次构造都 `create_ssl_context()` → Windows 上
枚举系统证书库（实测 0.17-1.5s/次）。billing 刷新、claim、兑换链、安装序、
telemetry 这些短连接调用点每请求/每任务新建 client，构造税在测试套件（354 次
构造累计 ~64s）和生产（每次 billing 刷新白付一笔）都是真实延迟。

`ssl.Context` 跨线程共享是安全的（CPython/OpenSSL 线上锁语义），httpx 的
`verify=` 直接收 Context。证书校验语义与默认构造完全一致。
"""

from __future__ import annotations

import ssl

SSL_CTX = ssl.create_default_context()
