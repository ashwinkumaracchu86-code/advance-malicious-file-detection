import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase


class Base(DeclarativeBase):
    pass


DATABASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "malicious_files.db")
DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")


def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


engine = create_engine(
    DATABASE_URI,
    echo=False,
    connect_args={"check_same_thread": False},
)
event.listen(engine, "connect", _set_sqlite_pragma)

SessionFactory = sessionmaker(bind=engine)
Session = scoped_session(SessionFactory)


def get_session():
    return Session()


def close_session(session):
    try:
        session.close()
    except Exception:
        pass
