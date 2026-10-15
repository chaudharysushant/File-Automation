import importlib
import os
import tarfile
import tempfile
import time
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch


class RouteFolderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DASHBOARD_SECRET_KEY", "test-secret-key")
        import app as application
        cls.app = importlib.reload(application)
        cls.main = cls.app.main

    def _touch_old(self, path):
        old = time.time() - 120
        os.utime(path, (old, old))

    def _write_file(self, source, name, content=b"data"):
        path = source / name
        path.write_bytes(content)
        self._touch_old(path)
        return path

    def _write_aged_file(self, source, name, days, content=b"data"):
        path = source / name
        path.write_bytes(content)
        old = time.time() - days * 86400
        os.utime(path, (old, old))
        return path

    def _write_zip(self, source, name, members):
        path = source / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, content in members.items():
                archive.writestr(member, content)
        self._touch_old(path)
        return path

    def _write_tar(self, source, name, members):
        path = source / name
        with tarfile.open(path, "w:gz") as archive:
            for member, content in members.items():
                data = content.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, BytesIO(data))
        self._touch_old(path)
        return path

    def _run(self, root, routes, regex=r".*"):
        with patch.object(self.main, "get_route", return_value=routes), \
             patch.object(self.main, "resolve_route_path", side_effect=lambda value: Path(root) / value), \
             patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "30"}):
            self.main.copy_files("CLIENT")

    def test_is_zip_file_matches_extension_case_insensitively(self):
        self.assertTrue(self.main.is_zip_file("Report.ZIP"))
        self.assertTrue(self.main.is_zip_file("Report.zip"))
        self.assertFalse(self.main.is_zip_file("Report.csv"))

    def test_is_archive_file_matches_zip_and_tar_variants(self):
        for name in ("Report.zip", "Report.tgz", "Report.tar.gz", "Report.TAR.BZ2", "Report.tar"):
            self.assertTrue(self.main.is_archive_file(name), name)
        self.assertFalse(self.main.is_archive_file("Report.csv"))

    def test_folder_name_from_filename_normalises_known_formats(self):
        cases = {
            "Report_20240115.zip": "2024-01-15",
            "Report-2024-01-15.zip": "2024-01-15",
            "Report_2024_01_15.zip": "2024-01-15",
            "Export_20240115123000.zip": "2024-01-15",
            "zph_ida_update.10142026.tgz": "2026-10-14",
            "zph_ida_update.20261014.tgz": "2026-10-14",
        }
        for filename, expected in cases.items():
            self.assertEqual(self.main.folder_name_from_filename(filename), expected, filename)

    def test_folder_name_from_filename_falls_back_on_missing_or_invalid_date(self):
        fallback = self.main.current_date_folder()
        self.assertEqual(self.main.folder_name_from_filename("Archive.zip"), fallback)
        self.assertEqual(self.main.folder_name_from_filename("Report_20241340.zip"), fallback)
        self.assertEqual(self.main.folder_name_from_filename("Report.zip", fallback="1999-12-31"), "1999-12-31")

    def test_tgz_with_yyyymmdd_is_extracted_into_dated_folder(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_tar(source, "zph_ida_update.20261014.tgz", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.tgz$", False, True)])

            folder = destination / "2026-10-14"
            self.assertTrue((folder / "zph_ida_update.20261014.tgz").exists())
            self.assertEqual((folder / "data.txt").read_text(), "hello")

    def test_tgz_is_extracted_into_mmddyyyy_dated_folder(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_tar(source, "zph_ida_update.10142026.tgz", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.tgz$", False, True)])

            folder = destination / "2026-10-14"
            self.assertTrue((folder / "zph_ida_update.10142026.tgz").exists())
            self.assertEqual((folder / "data.txt").read_text(), "hello")

    def test_zip_is_extracted_into_dated_folder_and_kept(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_zip(source, "Report_20240115.zip", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.zip$", False, True)])

            folder = destination / "2024-01-15"
            self.assertTrue((folder / "Report_20240115.zip").exists())
            self.assertEqual((folder / "data.txt").read_text(), "hello")

    def test_zip_is_skipped_when_dated_folder_already_exists(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            (destination / "2024-01-15").mkdir()
            self._write_zip(source, "Report_20240115.zip", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.zip$", False, True)])

            self.assertFalse((destination / "2024-01-15" / "Report_20240115.zip").exists())

    def test_zip_without_date_uses_current_date_folder(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_zip(source, "Archive.zip", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.zip$", False, True)])

            folder = destination / self.main.current_date_folder()
            self.assertEqual((folder / "data.txt").read_text(), "hello")

    def test_zip_with_create_folder_both_enabled_extracts(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_zip(source, "Report_20240115.zip", {"data.txt": "hello"})

            self._run(root, [("src", "dst", r".*\.zip$", True, True)])

            folder = destination / "2024-01-15"
            self.assertEqual((folder / "data.txt").read_text(), "hello")

    def test_create_folder_copies_non_zip_into_current_date_folder(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_file(source, "report.csv", b"complete")

            self._run(root, [("src", "dst", r".*\.csv$", True, False)])

            folder = destination / self.main.current_date_folder()
            self.assertTrue((folder / "report.csv").exists())

    def test_create_folder_skips_when_current_date_folder_already_exists(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            (destination / self.main.current_date_folder()).mkdir()
            self._write_file(source, "report.csv", b"complete")

            self._run(root, [("src", "dst", r".*\.csv$", True, False)])

            folder = destination / self.main.current_date_folder()
            self.assertFalse((folder / "report.csv").exists())

    def test_create_folder_copies_multiple_files_created_in_same_run(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_file(source, "first.csv", b"first")
            self._write_file(source, "second.csv", b"second")

            self._run(root, [("src", "dst", r".*\.csv$", True, False)])

            folder = destination / self.main.current_date_folder()
            self.assertTrue((folder / "first.csv").exists())
            self.assertTrue((folder / "second.csv").exists())

    def test_extract_rejects_members_escaping_destination(self):
        with tempfile.TemporaryDirectory() as root:
            archive_path = Path(root) / "evil.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../evil.txt", "boom")
            target = Path(root) / "target"
            target.mkdir()

            with self.assertRaises(ValueError):
                self.main.extract_zip_archive(archive_path, target)

    def test_matches_filename_regex_handles_empty_and_invalid(self):
        self.assertTrue(self.main.matches_filename_regex("a.txt", ""))
        self.assertTrue(self.main.matches_filename_regex("a.txt", None))
        self.assertTrue(self.main.matches_filename_regex("a.txt", "   "))
        self.assertTrue(self.main.matches_filename_regex("a.txt", r"a\."))
        self.assertFalse(self.main.matches_filename_regex("b.txt", r"a\."))
        self.assertFalse(self.main.matches_filename_regex("a.txt", "("))

    def test_regex_is_empty_detects_blank_values(self):
        self.assertTrue(self.main.regex_is_empty(""))
        self.assertTrue(self.main.regex_is_empty(None))
        self.assertTrue(self.main.regex_is_empty("  "))
        self.assertFalse(self.main.regex_is_empty(r".*\.csv$"))

    def test_empty_regex_copies_all_files_ignoring_cutoff(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_aged_file(source, "old_report.csv", 20, b"old")
            self._write_aged_file(source, "older_report.txt", 40, b"older")

            self._run(root, [("src", "dst", "", False, False)])

            self.assertTrue((destination / "old_report.csv").exists())
            self.assertTrue((destination / "older_report.txt").exists())

    def test_none_regex_copies_all_files(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_aged_file(source, "one.dat", 30, b"one")

            self._run(root, [("src", "dst", None, False, False)])

            self.assertTrue((destination / "one.dat").exists())

    def test_empty_regex_does_not_stop_when_newest_already_present(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_aged_file(source, "new.log", 1, b"new")
            self._write_aged_file(source, "old.log", 2, b"old")
            (destination / "new.log").write_bytes(b"new")

            self._run(root, [("src", "dst", "", False, False)])

            self.assertTrue((destination / "old.log").exists())

    def test_regex_still_applies_cutoff_for_configured_pattern(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            self._write_aged_file(source, "old.csv", 20, b"old")
            self._write_aged_file(source, "recent.csv", 1, b"recent")

            self._run(root, [("src", "dst", r".*\.csv$", False, False)])

            self.assertFalse((destination / "old.csv").exists())
            self.assertTrue((destination / "recent.csv").exists())

    def test_extract_tar_rejects_members_escaping_destination(self):
        with tempfile.TemporaryDirectory() as root:
            archive_path = Path(root) / "evil.tgz"
            with tarfile.open(archive_path, "w:gz") as archive:
                info = tarfile.TarInfo("../evil.txt")
                info.size = 4
                archive.addfile(info, BytesIO(b"boom"))
            target = Path(root) / "target"
            target.mkdir()

            with self.assertRaises(ValueError):
                self.main.extract_tar_archive(archive_path, target)


if __name__ == "__main__":
    unittest.main()
