import getpass
import json
import os
import tempfile

from src.app import TEACHERS_FILE, hash_password


def main():
    username = input("Teacher username: ").strip()
    if not username:
        raise SystemExit("Username cannot be empty.")

    password = getpass.getpass("Teacher password (at least 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    if TEACHERS_FILE.exists():
        try:
            data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
            teachers = data["teachers"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise SystemExit(f"Cannot read teacher configuration: {error}") from error
        if not isinstance(teachers, list) or not all(
            isinstance(teacher, dict) and isinstance(teacher.get("username"), str)
            for teacher in teachers
        ):
            raise SystemExit("Teacher configuration must contain a teachers list.")
    else:
        teachers = []

    if any(teacher.get("username") == username for teacher in teachers):
        raise SystemExit("That username already exists.")

    teachers.append({"username": username, "password_hash": hash_password(password)})
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=TEACHERS_FILE.parent, delete=False
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump({"teachers": teachers}, temporary_file, indent=2)
            temporary_file.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, TEACHERS_FILE)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
    print(f"Added teacher {username}.")


if __name__ == "__main__":
    main()
