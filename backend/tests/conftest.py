"""API-test fixtures. Tests run on an in-memory SQLite database (documented test-only strategy);
the application itself targets PostgreSQL. Set DATABASE_URL before the app is imported."""
import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AI_PROVIDER"] = "fallback"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import models  # noqa: E402,F401
from app.db.models import Base  # noqa: E402
from app.db.session import dispose_engine, get_engine  # noqa: E402


@pytest.fixture()
def client():
    dispose_engine()
    Base.metadata.create_all(get_engine())
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    Base.metadata.drop_all(get_engine())
    dispose_engine()
