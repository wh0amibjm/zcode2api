"""模型级熔断状态机（3012 判级的产物）单元测试。

只测三件纯逻辑：归一化键、剩余秒数、过期自清。判级与调度在
tests/integration/test_gateway_model_block.py。
"""

from __future__ import annotations

import time

import pytest

from app import settings
from app.routes import gateway as gw


@pytest.fixture(autouse=True)
def _clean():
    gw.reset_model_blocks()
    yield
    gw.reset_model_blocks()


def test_model_key_normalizes_case_and_space():
    assert gw._model_key("GLM-5.3") == "glm-5.3"
    assert gw._model_key("  glm-5.3 ") == "glm-5.3"
    assert gw._model_key(None) == ""
    assert gw._model_key(123) == "123"


def test_block_then_remaining_counts_down_and_expires(monkeypatch):
    gw._block_model("GLM-5.3", "test")
    assert gw.model_block_remaining("GLM-5.3") > 0
    # 大小写不敏感：换个写法照样命中
    assert gw.model_block_remaining("glm-5.3") > 0
    assert gw.model_blocks() == [{"model": "glm-5.3",
                                  "remaining": gw.model_block_remaining("glm-5.3")}]

    # 手动把到期时间拨到过去 → 判定为未熔断，且条目被清掉（不涨内存）
    gw._model_block_until["glm-5.3"] = time.time() - 1
    assert gw.model_block_remaining("GLM-5.3") == 0
    assert gw.model_blocks() == []
    assert "glm-5.3" not in gw._model_block_until


def test_block_length_follows_settings(monkeypatch):
    monkeypatch.setattr(settings, "MODEL_BLOCK_SECONDS", 60)
    gw._block_model("GLM-5.3", "test")
    remain = gw.model_block_remaining("GLM-5.3")
    assert 55 <= remain <= 60


def test_unrelated_models_unaffected():
    gw._block_model("GLM-5.3", "test")
    assert gw.model_block_remaining("GLM-5.3-Flash") == 0


def test_empty_model_is_never_blocked():
    gw._block_model("", "test")
    assert gw.model_block_remaining("") == 0
    assert gw.model_blocks() == []
