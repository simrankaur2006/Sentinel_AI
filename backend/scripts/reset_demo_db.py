"""DROP and recreate all tables. Refuses non-local databases.   Usage: python -m scripts.reset_demo_db --yes"""
import sys
from urllib.parse import urlparse

from app.core.config import get_settings
from app.db.models import Base
from app.db.session import get_engine


def main() -> None:
    url = get_settings().database_url
    host = (urlparse(url).hostname or "") if not url.startswith("sqlite") else "localhost"
    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit(f"Refusing to reset a non-local database (host={host!r}).")
    if "--yes" not in sys.argv:
        raise SystemExit("This deletes ALL SentinelAI data in the configured local database. Re-run with --yes to confirm.")
    eng = get_engine()
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    print("Demo database reset.")


if __name__ == "__main__":
    main()
