import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from database.db import engine, Base
from models.scan import ScanResult


def init_database():
    db_dir = os.path.join(os.path.dirname(__file__), "..", "..", "database")
    os.makedirs(db_dir, exist_ok=True)

    Base.metadata.create_all(engine)


if __name__ == "__main__":
    init_database()
