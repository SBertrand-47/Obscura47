"""Tests for src.utils.sites — multi-site key management."""

from __future__ import annotations

import os
import stat
import tempfile
import json

import pytest

from src.utils.sites import (
    SITES_DIR,
    SITE_MANIFEST_PROTOCOL_VERSION,
    SiteConfig,
    SiteInfo,
    build_site_manifest,
    config_path_for_name,
    delete_site_config,
    ensure_sites_dir,
    export_key,
    import_key,
    key_path_for_name,
    list_sites,
    load_site_config,
    load_or_create_site_key,
    resolve_key_path,
    rotate_key,
    save_site_config,
    set_key_permissions,
    write_site_manifest,
)


@pytest.fixture
def tmp_sites(tmp_path):
    return str(tmp_path / "sites")


class TestKeyPathForName:
    def test_simple(self):
        path = key_path_for_name("myblog", "/fake/sites")
        assert path == "/fake/sites/myblog.pem"

    def test_rejects_path_separator(self):
        with pytest.raises(ValueError, match="path separator"):
            key_path_for_name("../evil", "/fake/sites")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="invalid site name"):
            key_path_for_name("", "/fake/sites")

    def test_rejects_dotfile(self):
        with pytest.raises(ValueError, match="invalid site name"):
            key_path_for_name(".hidden", "/fake/sites")


class TestConfigPathForName:
    def test_simple(self):
        path = config_path_for_name("myblog", "/fake/sites")
        assert path == "/fake/sites/myblog.site.json"


class TestResolveKeyPath:
    def test_explicit_key_wins(self, tmp_sites):
        result = resolve_key_path(name="ignored", key="/explicit.pem", sites_dir=tmp_sites)
        assert result == "/explicit.pem"

    def test_name_defaults_to_sites_dir(self, tmp_sites):
        result = resolve_key_path(name="myblog", sites_dir=tmp_sites)
        assert result == os.path.join(tmp_sites, "myblog.pem")
        assert os.path.isdir(tmp_sites)

    def test_no_name_defaults_to_default(self, tmp_sites):
        result = resolve_key_path(sites_dir=tmp_sites)
        assert result.endswith("default.pem")

    def test_tilde_expansion(self, tmp_sites):
        result = resolve_key_path(key="~/my.pem", sites_dir=tmp_sites)
        assert not result.startswith("~")


class TestEnsureSitesDir:
    def test_creates_directory(self, tmp_sites):
        assert not os.path.isdir(tmp_sites)
        ensure_sites_dir(tmp_sites)
        assert os.path.isdir(tmp_sites)
        mode = os.stat(tmp_sites).st_mode
        assert mode & 0o777 == 0o700

    def test_idempotent(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        ensure_sites_dir(tmp_sites)
        assert os.path.isdir(tmp_sites)


class TestListSites:
    def test_empty_dir(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        assert list(list_sites(tmp_sites)) == []

    def test_nonexistent_dir(self):
        assert list(list_sites("/nonexistent/path")) == []

    def test_lists_created_keys(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        from src.core.encryptions import ecc_load_or_create_keypair
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "alpha.pem"))
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "beta.pem"))

        sites = list(list_sites(tmp_sites))
        assert len(sites) == 2
        names = [s.name for s in sites]
        assert "alpha" in names
        assert "beta" in names
        for s in sites:
            assert s.address.endswith(".obscura")
            assert os.path.isfile(s.key_path)

    def test_ignores_non_pem(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        with open(os.path.join(tmp_sites, "notes.txt"), "w") as f:
            f.write("not a key")
        from src.core.encryptions import ecc_load_or_create_keypair
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "real.pem"))
        sites = list(list_sites(tmp_sites))
        assert len(sites) == 1
        assert sites[0].name == "real"

    def test_stable_addresses(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        from src.core.encryptions import ecc_load_or_create_keypair
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "stable.pem"))
        addr1 = list(list_sites(tmp_sites))[0].address
        addr2 = list(list_sites(tmp_sites))[0].address
        assert addr1 == addr2

    def test_includes_saved_target(self, tmp_sites):
        load_or_create_site_key(name="alpha", sites_dir=tmp_sites, quiet=True)
        save_site_config("alpha", target="./public", sites_dir=tmp_sites)
        site = list(list_sites(tmp_sites))[0]
        assert site.target == "./public"
        assert site.config_path.endswith("alpha.site.json")

    def test_lists_named_site_with_external_key(self, tmp_sites, tmp_path):
        from src.core.encryptions import ecc_load_or_create_keypair

        external_key = str(tmp_path / "outside.pem")
        ecc_load_or_create_keypair(external_key)
        save_site_config(
            "external",
            key_path=external_key,
            target="127.0.0.1:8000",
            sites_dir=tmp_sites,
        )

        sites = list(list_sites(tmp_sites))
        assert len(sites) == 1
        assert sites[0].name == "external"
        assert sites[0].key_path == external_key
        assert sites[0].target == "127.0.0.1:8000"


class TestSetKeyPermissions:
    def test_sets_0600(self, tmp_path):
        p = tmp_path / "test.pem"
        p.write_text("key")
        os.chmod(str(p), 0o644)
        set_key_permissions(str(p))
        mode = os.stat(str(p)).st_mode & 0o777
        assert mode == 0o600

    def test_nonexistent_no_error(self):
        set_key_permissions("/nonexistent/file.pem")


class TestLoadOrCreateSiteKey:
    def test_creates_new_key_with_banner(self, tmp_sites, capsys):
        priv, pub, path, created = load_or_create_site_key(
            name="fresh", sites_dir=tmp_sites,
        )
        assert created is True
        assert os.path.isfile(path)
        assert pub.startswith("-----BEGIN PUBLIC KEY-----")
        captured = capsys.readouterr()
        assert "NEW SITE KEY CREATED" in captured.err

    def test_existing_key_no_banner(self, tmp_sites, capsys):
        load_or_create_site_key(name="existing", sites_dir=tmp_sites)
        capsys.readouterr()  # clear
        _, _, _, created = load_or_create_site_key(
            name="existing", sites_dir=tmp_sites,
        )
        assert created is False
        captured = capsys.readouterr()
        assert "NEW SITE KEY CREATED" not in captured.err

    def test_quiet_suppresses_banner(self, tmp_sites, capsys):
        load_or_create_site_key(
            name="quiet", sites_dir=tmp_sites, quiet=True,
        )
        captured = capsys.readouterr()
        assert "NEW SITE KEY CREATED" not in captured.err

    def test_sets_permissions(self, tmp_sites):
        _, _, path, _ = load_or_create_site_key(name="perms", sites_dir=tmp_sites)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600

    def test_saves_named_site_config(self, tmp_sites):
        _, _, path, _ = load_or_create_site_key(name="named", sites_dir=tmp_sites, quiet=True)
        config = load_site_config("named", sites_dir=tmp_sites)
        assert config is not None
        assert config.key_path == path

    def test_preserves_saved_target(self, tmp_sites):
        save_site_config("named", target="./public", sites_dir=tmp_sites)
        load_or_create_site_key(name="named", sites_dir=tmp_sites, quiet=True)
        config = load_site_config("named", sites_dir=tmp_sites)
        assert config is not None
        assert config.target == "./public"


class TestExportKey:
    def test_export_to_directory(self, tmp_sites, tmp_path):
        from src.core.encryptions import ecc_load_or_create_keypair
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "exportme.pem"))
        ensure_sites_dir(tmp_sites)
        dest_dir = str(tmp_path / "backup")
        os.makedirs(dest_dir)
        out = export_key("exportme", dest_dir, sites_dir=tmp_sites)
        assert os.path.isfile(out)
        assert out.endswith("exportme.pem")
        mode = os.stat(out).st_mode & 0o777
        assert mode == 0o600

    def test_export_to_file(self, tmp_sites, tmp_path):
        from src.core.encryptions import ecc_load_or_create_keypair
        ecc_load_or_create_keypair(os.path.join(tmp_sites, "site2.pem"))
        ensure_sites_dir(tmp_sites)
        out = export_key("site2", str(tmp_path / "copy.pem"), sites_dir=tmp_sites)
        assert out.endswith("copy.pem")

    def test_export_missing_raises(self, tmp_sites):
        ensure_sites_dir(tmp_sites)
        with pytest.raises(FileNotFoundError):
            export_key("nonexistent", ".", sites_dir=tmp_sites)


class TestImportKey:
    def test_import_new_site(self, tmp_sites, tmp_path):
        from src.core.encryptions import ecc_load_or_create_keypair
        src = str(tmp_path / "external.pem")
        ecc_load_or_create_keypair(src)
        dest = import_key("imported", src, sites_dir=tmp_sites)
        assert os.path.isfile(dest)
        assert dest.endswith("imported.pem")

    def test_import_duplicate_raises(self, tmp_sites, tmp_path):
        from src.core.encryptions import ecc_load_or_create_keypair
        src = str(tmp_path / "dup.pem")
        ecc_load_or_create_keypair(src)
        import_key("dup", src, sites_dir=tmp_sites)
        with pytest.raises(FileExistsError):
            import_key("dup", src, sites_dir=tmp_sites)

    def test_import_missing_file_raises(self, tmp_sites):
        with pytest.raises(FileNotFoundError):
            import_key("ghost", "/no/such/file.pem", sites_dir=tmp_sites)


class TestSiteConfig:
    def test_save_and_load(self, tmp_sites):
        path = save_site_config(
            "alpha",
            key_path="~/keys/alpha.pem",
            target="./site",
            sites_dir=tmp_sites,
        )
        config = load_site_config("alpha", sites_dir=tmp_sites)
        assert path.endswith("alpha.site.json")
        assert config == SiteConfig(
            name="alpha",
            key_path=os.path.expanduser("~/keys/alpha.pem"),
            target="./site",
            config_path=path,
        )

    def test_delete(self, tmp_sites):
        save_site_config("alpha", sites_dir=tmp_sites)
        assert delete_site_config("alpha", sites_dir=tmp_sites) is True
        assert delete_site_config("alpha", sites_dir=tmp_sites) is False

    def test_merge_preserves_existing_fields(self, tmp_sites):
        save_site_config("alpha", key_path="/tmp/a.pem", target="./site", sites_dir=tmp_sites)
        save_site_config("alpha", key_path="/tmp/b.pem", sites_dir=tmp_sites)
        config = load_site_config("alpha", sites_dir=tmp_sites)
        assert config == SiteConfig(
            name="alpha",
            key_path="/tmp/b.pem",
            target="./site",
            config_path=config_path_for_name("alpha", tmp_sites),
        )


class TestSiteManifest:
    def test_build_manifest(self):
        manifest = build_site_manifest(
            "abcdefghijklmnop.obscura",
            title="Alpha",
            description="Test site",
            tags=["blog", "blog", " tech "],
        )
        assert manifest == {
            "protocol": SITE_MANIFEST_PROTOCOL_VERSION,
            "address": "abcdefghijklmnop.obscura",
            "title": "Alpha",
            "description": "Test site",
            "tags": ["blog", "tech"],
        }

    def test_write_manifest(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        out = write_site_manifest(
            str(site_dir),
            "abcdefghijklmnop.obscura",
            title="Alpha",
            tags=["blog"],
        )
        assert out.endswith(".well-known/obscura.json")
        with open(out, encoding="utf-8") as f:
            payload = json.load(f)
        assert payload["protocol"] == SITE_MANIFEST_PROTOCOL_VERSION
        assert payload["address"] == "abcdefghijklmnop.obscura"
        assert payload["tags"] == ["blog"]


class TestRotateKey:
    def test_rotate_creates_new_address(self, tmp_sites):
        from src.utils.onion_addr import address_from_pubkey
        load_or_create_site_key(name="rot", sites_dir=tmp_sites, quiet=True)
        old_addr = list(list_sites(tmp_sites))[0].address
        _, pub, path, backup = rotate_key("rot", sites_dir=tmp_sites)
        new_addr = address_from_pubkey(pub)
        assert new_addr != old_addr
        assert backup is not None
        assert backup.endswith(".old.pem")
        assert os.path.isfile(backup)

    def test_rotate_fresh_site(self, tmp_sites):
        _, pub, path, backup = rotate_key("brand_new", sites_dir=tmp_sites)
        assert backup is None
        assert os.path.isfile(path)
