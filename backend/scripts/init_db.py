"""Create all tables (idempotent).   Usage (from backend/):  python -m scripts.init_db"""
from app.db import models  # noqa: F401  (registers tables)
from app.db.models import Base
from app.db.session import get_engine


def main() -> None:
    Base.metadata.create_all(get_engine())
    print("Database tables are ready.")


if __name__ == "__main__":
    main()
