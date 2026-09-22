import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Index
from database.db import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False, index=True)
    extension = Column(String(32), nullable=False, default="", index=True)
    file_type = Column(String(64), nullable=False, default="unknown")
    mime_type = Column(String(128), nullable=False, default="application/octet-stream")
    file_size = Column(Integer, nullable=False, default=0)
    md5 = Column(String(32), nullable=False, default="")
    sha256 = Column(String(64), nullable=False, default="", index=True)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(20), nullable=False, default="unknown", index=True)
    indicators = Column(Text, nullable=False, default="[]")
    metadata_ = Column("metadata", Text, nullable=False, default="{}")
    scan_timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("idx_risk_level_timestamp", "risk_level", "scan_timestamp"),
    )

    def set_indicators(self, indicators: list):
        self.indicators = json.dumps(indicators)

    def get_indicators(self) -> list:
        try:
            return json.loads(self.indicators)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_metadata(self, data: dict):
        self.metadata_ = json.dumps(data)

    def get_metadata(self) -> dict:
        try:
            return json.loads(self.metadata_)
        except (json.JSONDecodeError, TypeError):
            return {}

    def to_dict(self):
        meta = self.get_metadata()
        return {
            "id": self.id,
            "filename": self.filename,
            "extension": self.extension,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha256": self.sha256,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "indicators": self.get_indicators(),
            "metadata": meta,
            "explanation": meta.get("explanation", ""),
            "scan_timestamp": self.scan_timestamp.isoformat(),
        }

    def __repr__(self):
        return f"<ScanResult id={self.id} filename='{self.filename}' risk_level='{self.risk_level}'>"
