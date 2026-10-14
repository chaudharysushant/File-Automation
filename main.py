import os
import re
import shutil
import time
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


def get_route(client_id):
    conn = psycopg2.connect(**get_db_config())

    cursor = conn.cursor()

    cursor.execute("""
        SELECT source, destination, filename_regex
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


def copy_files(client_id=None):
    if client_id is None:
        client_ids = get_client_ids()
    else:
        client_ids = [client_id]

    for current_client_id in client_ids:
        routes = get_route(current_client_id)

        for source_path, destination_path, filename_regex in routes:
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

                cutoff = datetime.now().timestamp() - timedelta(days=10).total_seconds()
                recent_files = sorted(
                    (
                        file
                        for file in source.iterdir()
                        if file.is_file()
                        and re.match(filename_regex, file.name)
                        and file.stat().st_mtime >= cutoff
                    ),
                    key=lambda file: file.stat().st_mtime,
                    reverse=True,
                )
                copied_count = 0

                for index, file in enumerate(recent_files):
                    target = destination / file.name

                    if target.exists():
                        print(
                            f"Already in destination; stopping before older files: {target}",
                            flush=True,
                        )
                        break

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


if __name__ == "__main__":
    poll_interval = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
    print(f"Starting file sync poller every {poll_interval} seconds")

    while True:
        print("Checking database for active client_ids...")
        for client_id in get_client_ids():
            print(f"Processing client_id: {client_id}")
            copy_files(client_id)
        time.sleep(poll_interval)
