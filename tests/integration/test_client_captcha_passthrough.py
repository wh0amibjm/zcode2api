"""客户端自带 verify_param（官方客户端形态）的透传行为。

官方 ZCode 客户端对 zcode.z.ai origin 会自行求解并随请求带上
X-Aliyun-Captcha-Verify-Param；网关应透传而不取预解池（不占名额、不覆盖），
被 3007 后降级取池重试（verifyParam 一次性，同枚重发必然再拒）。
"""

from __future__ import annotations

from tests.conftest import seed_account

_MSG_BODY = {"model": "GLM-5.3-Flash", "max_tokens": 16,
             "messages": [{"role": "user", "content": "hi"}]}
_CLIENT_PARAM = "client-solved-token"


def _jwt(tag: str) -> str:
    """每个用例独立 JWT。

    mock 是 session 级的，bind key = 凭据前 16 字符：payload 值必须在**第一个
    字符**就分化（a1/b2/c3），tag 放尾部时三个用例会共享同一个 bind 计数器。
    """
    import base64
    payload = base64.urlsafe_b64encode(f'{{"sub":"{tag}"}}'.encode()).decode().rstrip("=")
    return "h4." + payload + ".sig"


async def test_client_param_passthrough_skips_pool(gateway_client, fresh_app, stub_captcha):
    client, _mock = gateway_client
    jwt = _jwt("a1")
    seed_account(fresh_app, jwt, name="passthru")

    res = await client.post("/v1/messages", json=_MSG_BODY,
                            headers={"X-Aliyun-Captcha-Verify-Param": _CLIENT_PARAM})

    assert res.status_code == 200
    assert stub_captcha.acquires == 0      # 没占预解池名额
    assert stub_captcha.accepts == 1       # 成功路径照常记接受


async def test_no_client_param_still_uses_pool(gateway_client, fresh_app, stub_captcha):
    client, _mock = gateway_client
    seed_account(fresh_app, _jwt("b2"), name="pooluse")

    res = await client.post("/v1/messages", json=_MSG_BODY)

    assert res.status_code == 200
    assert stub_captcha.acquires == 1


async def test_rejected_client_param_falls_back_to_pool(gateway_client, fresh_app,
                                                        stub_captcha, mock_server):
    client, mock = gateway_client
    jwt = _jwt("c3")
    seed_account(fresh_app, jwt, name="fallback")
    # 序列末位是粘滞的（idx = min(n, len-1)），最后一位必须是 "ok"
    mock.state.sequences[jwt[:16]] = ["captcha_3007", "ok"]

    res = await client.post("/v1/messages", json=_MSG_BODY,
                            headers={"X-Aliyun-Captcha-Verify-Param": _CLIENT_PARAM})

    assert res.status_code == 200
    assert stub_captcha.acquires == 1       # 第 2 轮降级取池
    assert stub_captcha.accepts == 1
