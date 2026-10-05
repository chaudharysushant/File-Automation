import os
import re
import shutil
import time
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


def copy_files(client_id=None):
    if client_id is None:
        client_ids = get_client_ids()
    else:
        client_ids = [client_id]

    for current_client_id in client_ids:
        routes = get_route(current_client_id)

        for source_path, destination_path, filename_regex in routes:
            source = Path(source_path)
            destination = Path(destination_path)

            print(f"Checking source: {source}")
            print(f"Checking destination: {destination}")

            if not source.exists():
                print(f"Source not found: {source}")
                continue

            if not destination.exists():
                print(f"Destination not found: {destination}")
                continue

            if not destination.is_dir():
                print(f"Destination is not a directory: {destination}")
                continue

            copied_count = 0
            for file in source.iterdir():
                if not file.is_file():
                    continue

                if not re.match(filename_regex, file.name):
                    continue

                target = destination / file.name
                if target.exists():
                    print(f"File already exists: {target}")
                    continue

                try:
                    shutil.copy2(file, target)
                    print(f"COPIED: {file} -> {target}")
                    copied_count += 1

                except Exception as e:
                    print(f"ERROR: {file} - {e}")

            if copied_count == 0:
                print(f"No new file is present to copy from {source}")


if __name__ == "__main__":
    poll_interval = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
    print(f"Starting file sync poller every {poll_interval} seconds")

    while True:
        print("Checking database for active client_ids...")
        for client_id in get_client_ids():
            print(f"Processing client_id: {client_id}")
            copy_files(client_id)
        time.sleep(poll_interval)