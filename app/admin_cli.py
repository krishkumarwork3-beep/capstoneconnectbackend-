"""Admin accounts from the command line (useful before any admin exists, or if you are locked out).

    uv run python -m app.admin_cli create you@example.com "Your Name"      # asks for a password
    uv run python -m app.admin_cli password you@example.com                # sets a new password
    uv run python -m app.admin_cli list
"""

import argparse
import getpass
import sys

from sqlalchemy import select

from app.db import SessionLocal
from app.models import AdminUser, AuditLog
from app.security import MIN_PASSWORD_LENGTH, hash_password, new_id
from app.services.admin import create_admin


def _password() -> str:
    while True:
        first = getpass.getpass("Password: ")
        if len(first) < MIN_PASSWORD_LENGTH:
            print(f"At least {MIN_PASSWORD_LENGTH} characters.")
            continue
        if getpass.getpass("Again: ") == first:
            return first
        print("They don't match.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.admin_cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("email")
    create.add_argument("name", nargs="?", default="Site admin")
    create.add_argument("--role", choices=["admin", "viewer"], default="admin")
    reset = sub.add_parser("password")
    reset.add_argument("email")
    sub.add_parser("list")
    args = parser.parse_args()

    with SessionLocal() as db:
        if args.command == "list":
            for admin in db.scalars(select(AdminUser).order_by(AdminUser.created_at)):
                print(f"{admin.email:<36} {admin.role:<7} {'active' if admin.active else 'inactive'}  {admin.name}")
            return
        if args.command == "create":
            admin = create_admin(db, args.email, args.name, _password(), args.role)
            summary = f"Created {args.role} {admin.email} from the command line"
        else:
            admin = db.scalar(select(AdminUser).where(AdminUser.email == args.email.strip().lower()))
            if admin is None:
                sys.exit(f"No admin with the email {args.email}")
            admin.password_hash = hash_password(_password())
            admin.active = True
            summary = f"Set a new password for {admin.email} from the command line"
        db.add(AuditLog(id=new_id("aud"), admin_email="command line", action=f"admin.{args.command}", target_type="admin",
                        target_id=admin.id, summary=summary))
        db.commit()
        print(summary)


if __name__ == "__main__":
    main()
