"""账号热同步：外部进程写库后，网关不必重启就能看见。

这条是被真实故障逼出来的：`cli.py login` 把账号**直接写进库**，而 store 是内存缓存、原先只在
进程启动时 `_load()` 一次 —— 于是 CLI 打印"已保存账号"、管理接口却仍只列旧账号，必须重启网关
才可见（`docs/OAUTH-PATH.md` §8 记了这个坑）。

修法是读入口惰性检查库文件 mtime：外部改过就重载。这里用**第二个 Store 实例**模拟另一个进程，
不需要起真进程。
"""

from __future__ import annotations

from app import settings
from app.store import Store


def _fresh_store(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "accounts.db"))
    monkeypatch.setattr(settings, "DATA_DIR", tmp_path)
    return Store()


class TestHotSync:
    def test_external_write_is_visible_without_restart(self, tmp_path, monkeypatch):
        """核心用例：另一个"进程"写的账号，本实例下一次读就能看到。"""
        s1 = _fresh_store(tmp_path, monkeypatch)
        s2 = Store()                       # 第二个实例 = 另一个写库的进程
        assert s1.list_accounts("zai") == []

        s2.add_account("zai", "ext-account", "h.eyJzdWIiOiJlIn0.sig")

        assert [a.name for a in s1.list_accounts("zai")] == ["ext-account"]
        # find 走的是另一条读路径，也要能看到
        assert s1.find("zai", "ext-account") is not None

    def test_external_delete_is_visible(self, tmp_path, monkeypatch):
        """外部删号同样要立刻反映，否则会拿一个已经不存在的账号去轮询。"""
        s1 = _fresh_store(tmp_path, monkeypatch)
        s2 = Store()
        acc = s2.add_account("zai", "gone-soon", "h.eyJzdWIiOiJnIn0.sig")
        assert len(s1.list_accounts("zai")) == 1

        s2.remove_account("zai", acc.id)
        assert s1.list_accounts("zai") == []

    def test_no_external_change_does_not_reload(self, tmp_path, monkeypatch):
        """没有外部改动时不重载 —— 否则每次读都全量读库，热路径代价太大。"""
        s = _fresh_store(tmp_path, monkeypatch)
        s.add_account("zai", "steady", "h.eyJzdWIiOiJzIn0.sig")

        calls = {"n": 0}
        real_load = Store._load
        def counting_load(self):
            calls["n"] += 1
            return real_load(self)
        monkeypatch.setattr(Store, "_load", counting_load)

        for _ in range(5):
            s.list_accounts("zai")
        assert calls["n"] == 0, f"无外部改动却重载了 {calls['n']} 次"

    def test_own_write_does_not_trigger_reload(self, tmp_path, monkeypatch):
        """自己写的改动要盖戳，否则写后紧接的读会白重载一次（等于每请求多读一遍库）。"""
        s = _fresh_store(tmp_path, monkeypatch)

        calls = {"n": 0}
        real_load = Store._load
        def counting_load(self):
            calls["n"] += 1
            return real_load(self)
        monkeypatch.setattr(Store, "_load", counting_load)

        s.add_account("zai", "mine", "h.eyJzdWIiOiJtIn0.sig")
        s.list_accounts("zai")
        s.update_account(s.list_accounts("zai")[0])
        s.list_accounts("zai")
        assert calls["n"] == 0, f"自己写的改动触发了 {calls['n']} 次重载"
