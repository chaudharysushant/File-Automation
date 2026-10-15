import os
import re
import shutil
import tarfile
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import psycopg2
from dotenv import load_dotenv


load_dotenv()


def get_db_config():
    config = {
        "host": os.getenv("PG_HOST", "localhost"),
        "dbname": os.getenv("PG_NAME"),
        "user": os.getenv("PG_USER"),
        "password": os.getenv("PG_PASSWORD"),
        "port": os.getenv("PG_PORT", "5432"),
        "options": f"-c search_path={os.getenv('PG_SCHEMA', 'public')}",
    }

    missing = [
        name
        for name, value in {
            "PG_HOST": config["host"],
            "PG_NAME": config["dbname"],
            "PG_USER": config["user"],
            "PG_PASSWORD": config["password"],
        }.items()
        if value in (None, "")
    ]

    if missing:
        raise RuntimeError(
            "Missing required PostgreSQL environment variables: " + ", ".join(missing)
        )

    config["port"] = int(config["port"])
    return config


def get_base_path():
    return Path(os.getenv("FILE_ROUTE_BASE_PATH", "/home/ubuntu/file-automation/satish"))


def resolve_route_path(stored_path):
    return get_base_path() / stored_path


def get_client_ids():
    conn = psycopg2.connect(**get_db_config())

    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT client_id
        FROM {schema}.file_route
        WHERE enabled = TRUE
        ORDER BY client_id
    """.format(schema=os.getenv("PG_SCHEMA", "public")))

    client_ids = [row[0] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    return client_ids


def client_is_enabled(client_id):
    conn = psycopg2.connect(**get_db_config())

    cursor = conn.cursor()

    cursor.execute("""
        SELECT 1
        FROM {schema}.file_route
        WHERE client_id = %s
          AND enabled = TRUE
        LIMIT 1
    """.format(schema=os.getenv("PG_SCHEMA", "public")), (client_id,))

    found = cursor.fetchone() is not None

    cursor.close()
    conn.close()

    return found


def get_route(client_id):
    conn = psycopg2.connect(**get_db_config())

    cursor = conn.cursor()

    cursor.execute("""
        SELECT source, destination, filename_regex, create_folder, zip
        FROM {schema}.file_route
        WHERE client_id = %s
          AND enabled = TRUE
    """.format(schema=os.getenv("PG_SCHEMA", "public")), (client_id,))

    routes = cursor.fetchall()

    cursor.close()
    conn.close()

    return routes


def describe_size_change(current_size, previous_size):
    if previous_size == 0:
        if current_size == 0:
            return "0.00% (same size; previous file was empty)"
        return "not comparable (previous file was empty)"

    change_percent = ((current_size - previous_size) / previous_size) * 100
    if change_percent > 0:
        description = "bigger"
    elif change_percent < 0:
        description = "smaller"
    else:
        description = "same size"
    return f"{change_percent:+.2f}% ({description})"


def file_stability_seconds():
    try:
        return max(0, int(os.getenv("FILE_STABILITY_SECONDS", "30")))
    except (TypeError, ValueError):
        return 30


def file_signature(path):
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def wait_for_stable_file(path, required_seconds, poll_interval=2.0, timeout=300.0):
    try:
        if time.time() - path.stat().st_mtime >= required_seconds:
            return True
        previous = file_signature(path)
    except OSError:
        return False

    stable_since = time.monotonic()
    deadline = stable_since + timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        try:
            current = file_signature(path)
        except OSError:
            return False
        if current != previous:
            previous = current
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= required_seconds:
            return True
    return False


ZIP_EXTENSIONS = {".zip"}
TAR_EXTENSIONS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2")
FOLDER_DATE_FORMAT = "%Y-%m-%d"

# Date patterns found in source filenames, tried in order. Each entry extracts a
# year/month/day which is normalised to FOLDER_DATE_FORMAT.
_FILENAME_DATE_PATTERNS = (
    re.compile(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"),
    re.compile(r"(?P<year>\d{4})_(?P<month>\d{2})_(?P<day>\d{2})"),
    re.compile(r"(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})"),
    re.compile(r"(?P<month>\d{2})(?P<day>\d{2})(?P<year>\d{4})"),
)


def is_zip_file(filename):
    return Path(filename).suffix.lower() in ZIP_EXTENSIONS


def is_tar_file(filename):
    return Path(filename).name.lower().endswith(TAR_EXTENSIONS)


def is_archive_file(filename):
    return is_zip_file(filename) or is_tar_file(filename)


def current_date_folder():
    return datetime.now().strftime(FOLDER_DATE_FORMAT)


def folder_name_from_filename(filename, fallback=None):
    """Return a YYYY-MM-DD folder name parsed from filename, else the fallback."""
    for pattern in _FILENAME_DATE_PATTERNS:
        for match in pattern.finditer(filename):
            parts = match.groupdict()
            try:
                stamp = datetime(int(parts["year"]), int(parts["month"]), int(parts["day"]))
            except ValueError:
                continue
            return stamp.strftime(FOLDER_DATE_FORMAT)
    return fallback if fallback is not None else current_date_folder()


def regex_is_empty(filename_regex):
    return filename_regex is None or not str(filename_regex).strip()


def matches_filename_regex(filename, filename_regex):
    """Return True when filename matches the route regex; empty matches all."""
    if regex_is_empty(filename_regex):
        return True
    try:
        return re.match(filename_regex, filename) is not None
    except re.error:
        return False


def extract_zip_archive(archive_path, target_dir):
    """Extract a ZIP into target_dir, rejecting members that escape it."""
    target_root = Path(target_dir).resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            member_path = (target_root / member.filename).resolve()
            if target_root != member_path and target_root not in member_path.parents:
                raise ValueError(f"Archive member escapes destination: {member.filename}")
        archive.extractall(target_root)


def extract_tar_archive(archive_path, target_dir):
    """Extract a tar archive into target_dir, rejecting members that escape it."""
    target_root = Path(target_dir).resolve()
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            member_path = (target_root / member.name).resolve()
            if target_root != member_path and target_root not in member_path.parents:
                raise ValueError(f"Archive member escapes destination: {member.name}")
        archive.extractall(target_root)


def extract_archive(archive_path, target_dir):
    if is_tar_file(archive_path):
        extract_tar_archive(archive_path, target_dir)
    else:
        extract_zip_archive(archive_path, target_dir)


def copy_file_into_folder(file, destination, is_archive, folders_created_this_run, stability_seconds):
    """Copy a file into a date-named folder, extracting archives when requested.

    Returns 1 when copied and 0 when skipped or failed. A folder that already
    existed before this run is skipped; folders created earlier in this run
    stay writable so a batch lands together. The source file is never removed.
    """
    folder_name = folder_name_from_filename(file.name) if is_archive else current_date_folder()
    target_folder = destination / folder_name

    if target_folder.exists() and target_folder not in folders_created_this_run:
        print(f"Folder already exists; skipping download: {target_folder}", flush=True)
        return 0

    if not wait_for_stable_file(file, stability_seconds):
        print(f"File still being written; will retry later: {file}", flush=True)
        return 0

    target = target_folder / file.name
    try:
        target_folder.mkdir(parents=True, exist_ok=True)
        folders_created_this_run.add(target_folder)
        shutil.copy2(file, target)
        print(f"COPIED: {file} -> {target}", flush=True)
        if is_archive:
            extract_archive(target, target_folder)
            print(f"EXTRACTED: {target} -> {target_folder}", flush=True)
        return 1
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"ERROR processing {file} -> {target_folder}: {error}", flush=True)
        return 0


def copy_files(client_id=None):
    if client_id is None:
        client_ids = get_client_ids()
    else:
        client_ids = [client_id]

    for current_client_id in client_ids:
        routes = get_route(current_client_id)
        # Folders created in this run stay writable; pre-existing ones are skipped.
        folders_created_this_run = set()

        for source_path, destination_path, filename_regex, create_folder, unzip_files in routes:
            source = resolve_route_path(source_path)
            destination = resolve_route_path(destination_path)

            print(f"Checking source: {source!r}", flush=True)
            print(f"Checking destination: {destination!r}", flush=True)

            try:
                if not source.is_dir():
                    print(
                        f"Source directory unavailable: {source!r}",
                        flush=True,
                    )
                    continue

                if not destination.is_dir():
                    print(
                        f"Destination directory unavailable: {destination!r}",
                        flush=True,
                    )
                    continue

                # Empty regex syncs every file and ignores the recent-files window.
                skip_cutoff = regex_is_empty(filename_regex)
                cutoff = datetime.now().timestamp() - timedelta(days=10).total_seconds()
                recent_files = sorted(
                    (
                        file
                        for file in source.iterdir()
                        if file.is_file()
                        and matches_filename_regex(file.name, filename_regex)
                        and (skip_cutoff or file.stat().st_mtime >= cutoff)
                    ),
                    key=lambda file: file.stat().st_mtime,
                    reverse=True,
                )
                copied_count = 0
                stability_seconds = file_stability_seconds()

                for index, file in enumerate(recent_files):
                    is_archive = bool(unzip_files) and is_archive_file(file.name)

                    if is_archive or bool(create_folder):
                        copied_count += copy_file_into_folder(
                            file,
                            destination,
                            is_archive,
                            folders_created_this_run,
                            stability_seconds,
                        )
                        continue

                    target = destination / file.name

                    if target.exists():
                        if skip_cutoff:
                            print(
                                f"Already in destination; skipping: {target}",
                                flush=True,
                            )
                            continue
                        print(
                            f"Already in destination; stopping before older files: {target}",
                            flush=True,
                        )
                        break

                    if not wait_for_stable_file(file, stability_seconds):
                        print(
                            f"File still being written; will retry later: {file}",
                            flush=True,
                        )
                        continue

                    try:
                        shutil.copy2(file, target)
                        print(f"COPIED: {file} -> {target}", flush=True)
                        if index + 1 < len(recent_files):
                            previous_file = recent_files[index + 1]
                            change = describe_size_change(
                                file.stat().st_size,
                                previous_file.stat().st_size,
                            )
                            print(
                                f"SIZE CHANGE: {file.name} vs previous file "
                                f"{previous_file.name}: {change}",
                                flush=True,
                            )
                        else:
                            print(
                                f"SIZE CHANGE: no older matching file available "
                                f"for {file.name}",
                                flush=True,
                            )
                        copied_count += 1

                    except OSError as e:
                        print(
                            f"ERROR copying {file} -> {target}: {e}",
                            flush=True,
                        )

                if not recent_files:
                    if skip_cutoff:
                        print(
                            f"No files found in {source}",
                            flush=True,
                        )
                    else:
                        print(
                            f"No matching files from the last 10 days in {source}",
                            flush=True,
                        )
                elif copied_count == 0:
                    print(
                        f"No new files to copy from {source}",
                        flush=True,
                    )

            except OSError as e:
                print(
                    f"Filesystem error for client "
                    f"{current_client_id}: {e}",
                    flush=True,
                )
