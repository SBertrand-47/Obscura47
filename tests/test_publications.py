"""Tests for src.utils.publications - the agent's publication ledger."""

from __future__ import annotations

import json

import pytest

from src.utils import publications
from src.utils.publications import Publication


@pytest.fixture
def ledger(tmp_path):
    return str(tmp_path / "publications.json")


ADDR = "abc123def456.obscura"
ADDR2 = "ffff0000ffff.obscura"


class TestRecordPublish:
    def test_creates_entry_with_timestamps(self, ledger):
        pub = publications.record_publish(
            ADDR, name="blog", target="./site", now=100.0, path=ledger
        )
        assert pub.address == ADDR
        assert pub.name == "blog"
        assert pub.target == "./site"
        assert pub.first_published_at == 100.0
        assert pub.last_published_at == 100.0
        assert pub.reachable is None

    def test_persists_to_disk(self, ledger):
        publications.record_publish(ADDR, name="blog", path=ledger)
        with open(ledger, encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == publications.PUBLICATIONS_VERSION
        assert data["publications"][0]["address"] == ADDR

    def test_republish_preserves_first_bumps_last(self, ledger):
        publications.record_publish(ADDR, name="blog", now=100.0, path=ledger)
        pub = publications.record_publish(ADDR, name="blog", now=250.0, path=ledger)
        assert pub.first_published_at == 100.0
        assert pub.last_published_at == 250.0

    def test_manifest_not_wiped_when_omitted(self, ledger):
        publications.record_publish(
            ADDR, title="My Blog", description="hi", tags=["a"], path=ledger
        )
        # Re-host without manifest fields should keep them.
        pub = publications.record_publish(ADDR, target="127.0.0.1:8000", path=ledger)
        assert pub.title == "My Blog"
        assert pub.description == "hi"
        assert pub.tags == ["a"]
        assert pub.target == "127.0.0.1:8000"

    def test_empty_address_rejected(self, ledger):
        with pytest.raises(ValueError):
            publications.record_publish("", path=ledger)


class TestDirectories:
    def test_record_and_dedupe(self, ledger):
        publications.record_publish(ADDR, path=ledger)
        publications.record_directory(ADDR, "dir.obscura", now=1.0, path=ledger)
        pub = publications.record_directory(ADDR, "dir.obscura", now=2.0, path=ledger)
        assert len(pub.directories) == 1
        assert pub.directories[0].registered_at == 2.0

    def test_unregister(self, ledger):
        publications.record_publish(ADDR, path=ledger)
        publications.record_directory(ADDR, "dir.obscura", path=ledger)
        pub = publications.record_unregister(ADDR, "dir.obscura", path=ledger)
        assert pub.directories == []

    def test_directory_without_publish_is_noop(self, ledger):
        assert publications.record_directory(ADDR, "dir.obscura", path=ledger) is None


class TestReachability:
    def test_record_reachable(self, ledger):
        publications.record_publish(ADDR, path=ledger)
        pub = publications.record_reachability(ADDR, True, now=500.0, path=ledger)
        assert pub.reachable is True
        assert pub.last_checked_at == 500.0
        assert pub.last_reachable_at == 500.0

    def test_unreachable_keeps_last_reachable_at(self, ledger):
        publications.record_publish(ADDR, path=ledger)
        publications.record_reachability(ADDR, True, now=500.0, path=ledger)
        pub = publications.record_reachability(ADDR, False, now=900.0, path=ledger)
        assert pub.reachable is False
        assert pub.last_checked_at == 900.0
        # The earlier success is preserved.
        assert pub.last_reachable_at == 500.0

    def test_check_reachability_records_verdict(self, ledger, monkeypatch):
        publications.record_publish(ADDR, path=ledger)

        class _FakeReport:
            ok = True

        monkeypatch.setattr(
            "src.utils.diagnose.run_diagnostics", lambda a: _FakeReport()
        )
        reachable, report = publications.check_reachability(ADDR, path=ledger)
        assert reachable is True
        assert publications.get(ADDR, path=ledger).reachable is True


class TestQueryAndRemove:
    def test_all_publications_sorted_by_last_published(self, ledger):
        publications.record_publish(ADDR, now=100.0, path=ledger)
        publications.record_publish(ADDR2, now=50.0, path=ledger)
        addrs = [p.address for p in publications.all_publications(path=ledger)]
        assert addrs == [ADDR2, ADDR]

    def test_remove(self, ledger):
        publications.record_publish(ADDR, path=ledger)
        assert publications.remove(ADDR, path=ledger) is True
        assert publications.get(ADDR, path=ledger) is None
        assert publications.remove(ADDR, path=ledger) is False


class TestSerialization:
    def test_round_trip_through_disk(self, ledger):
        publications.record_publish(
            ADDR, name="blog", target="./s", title="T",
            description="D", tags=["x", "y"], now=1.0, path=ledger,
        )
        publications.record_directory(ADDR, "dir.obscura", now=2.0, path=ledger)
        publications.record_reachability(ADDR, True, now=3.0, path=ledger)

        pub = publications.get(ADDR, path=ledger)
        assert pub.name == "blog"
        assert pub.tags == ["x", "y"]
        assert pub.directories[0].address == "dir.obscura"
        assert pub.reachable is True

    def test_corrupt_file_is_ignored(self, ledger):
        with open(ledger, "w", encoding="utf-8") as f:
            f.write("not json{{{")
        assert publications.all_publications(path=ledger) == []
        # And a fresh write still works.
        publications.record_publish(ADDR, path=ledger)
        assert len(publications.all_publications(path=ledger)) == 1

    def test_publication_from_dict_tolerates_missing_optionals(self):
        pub = Publication.from_dict({"address": ADDR})
        assert pub.address == ADDR
        assert pub.reachable is None
        assert pub.directories == []
