import math
import os
from collections import Counter
from typing import Dict


def calculate_shannon_entropy(file_path: str) -> Dict[str, float]:
    """Calculate Shannon entropy of file content on a 0-8 scale.

    A perfectly uniform distribution yields 8.0 (maximum entropy).
    A file with a single repeated byte yields 0.0 (minimum entropy).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except (OSError, IOError):
        return {"entropy": 0.0, "byte_frequency": {}}

    if not data:
        return {"entropy": 0.0, "byte_frequency": {}}

    file_size = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / file_size
        if probability > 0:
            entropy -= probability * math.log2(probability)

    byte_frequency = {f"0x{k:02x}": v / file_size for k, v in sorted(byte_counts.items())}

    return {
        "entropy": round(entropy, 4),
        "byte_frequency": byte_frequency,
        "file_size": file_size,
    }


def classify_entropy(entropy: float) -> str:
    """Classify entropy value into human-readable category."""
    if entropy < 1.0:
        return "very_low"
    elif entropy < 3.0:
        return "low"
    elif entropy < 5.0:
        return "medium"
    elif entropy < 6.5:
        return "high"
    else:
        return "very_high"


def is_high_entropy(entropy: float, threshold: float = 6.5) -> bool:
    """Check if entropy is above a suspicious threshold."""
    return entropy >= threshold
