import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from analyzers.file_analyzer import analyze_file
from utils.file_security import (
    sanitize_filename,
    validate_filename,
    validate_extension,
    validate_file_size,
    scan_for_dangerous_patterns,
    FileSecurityError,
    PathTraversalError,
    BlockedFileError,
    EmptyFileError,
    FileTooLargeError,
)


class FakeFile:
    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self._data = data

    def read(self):
        return self._data


def test_hash_analyzer():
    print("=== Hash Analyzer ===")
    from analyzers.hash_analyzer import compute_hashes
    result = compute_hashes(b"hello world")
    assert result["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3", f"MD5 mismatch: {result['md5']}"
    assert result["sha256"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", f"SHA256 mismatch: {result['sha256']}"
    print(f"  MD5:    {result['md5']}")
    print(f"  SHA256: {result['sha256']}")
    print("  PASS\n")


def test_type_detector():
    print("=== Type Detector ===")
    from analyzers.type_detector import detect_type_from_bytes

    png_magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    r = detect_type_from_bytes(png_magic)
    assert r["subtype"] == "png", f"Expected png, got {r['subtype']}"
    print(f"  PNG magic: {r['type']}/{r['subtype']} -> {r['mime']}")

    pdf_magic = b"%PDF-1.4" + b"\x00" * 100
    r = detect_type_from_bytes(pdf_magic)
    assert r["subtype"] == "pdf", f"Expected pdf, got {r['subtype']}"
    print(f"  PDF magic: {r['type']}/{r['subtype']} -> {r['mime']}")

    text = b"Hello, this is a plain text file."
    r = detect_type_from_bytes(text)
    assert r["type"] == "text", f"Expected text, got {r['type']}"
    print(f"  Text:      {r['type']}/{r['subtype']} -> {r['mime']}")

    r = detect_type_from_bytes(b"")
    assert r["type"] == "unknown", f"Expected unknown, got {r['type']}"
    print(f"  Empty:     {r['type']}/{r['subtype']}")
    print("  PASS\n")


def test_metadata_analyzer():
    print("=== Metadata Analyzer ===")
    from analyzers.metadata_analyzer import extract_metadata
    tmp = os.path.join(os.path.dirname(__file__), "_test_meta.txt")
    with open(tmp, "wb") as f:
        f.write(b"test content")
    try:
        meta = extract_metadata(tmp, "report.txt")
        assert meta["extension"] == ".txt"
        assert meta["file_size"] == 12
        assert meta["created_at"] is not None
        print(f"  extension:  {meta['extension']}")
        print(f"  file_size:  {meta['file_size']}")
        print(f"  created_at: {meta['created_at']}")
        print(f"  modified_at:{meta['modified_at']}")
    finally:
        os.remove(tmp)
    print("  PASS\n")


def test_file_security():
    print("=== File Security ===")
    assert sanitize_filename("../../../etc/passwd") == "etc_passwd"
    print(f"  sanitize '../..//etc/passwd' -> '{sanitize_filename('../..//etc/passwd')}'")

    try:
        validate_filename("good_file.txt")
        print("  validate_filename('good_file.txt') -> OK")
    except FileSecurityError:
        print("  FAIL: should not reject good filename")

    try:
        validate_filename("../../../etc/passwd")
        print("  FAIL: should have rejected traversal filename")
    except PathTraversalError as e:
        print(f"  validate_filename('../../etc/passwd') -> BLOCKED: {e}")

    try:
        validate_extension("virus.exe")
        print("  FAIL: should have rejected .exe")
    except BlockedFileError as e:
        print(f"  validate_extension('virus.exe') -> BLOCKED: {e}")

    ext = validate_extension("report.pdf")
    print(f"  validate_extension('report.pdf') -> {ext}")

    try:
        validate_file_size(b"", 1024)
        print("  FAIL: should have rejected empty file")
    except EmptyFileError as e:
        print(f"  validate_file_size(empty) -> BLOCKED: {e}")

    try:
        validate_file_size(b"x" * 2048, 1024)
        print("  FAIL: should have rejected oversized file")
    except FileSecurityError as e:
        print(f"  validate_file_size(2048, max=1024) -> BLOCKED: {e}")

    indicators = scan_for_dangerous_patterns(b"eval('dangerous code')")
    print(f"  scan_for_dangerous_patterns(eval) -> {len(indicators)} indicator(s)")
    print("  PASS\n")


def test_full_analysis():
    print("=== Full File Analysis (harmless files) ===")

    test_files = [
        ("test.txt", b"This is a harmless text file used for testing the analysis engine."),
        ("hello.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nThis is a fake PDF for testing."),
        ("photo.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 100),
        ("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 200),
    ]

    for filename, data in test_files:
        fake = FakeFile(filename, data)
        result = analyze_file(fake, max_upload_size=1024 * 1024)
        print(f"\n  [{filename}]")
        print(f"    filename:  {result['filename']}")
        print(f"    extension: {result['extension']}")
        print(f"    file_type: {result['file_type']}")
        print(f"    mime_type: {result['mime_type']}")
        print(f"    file_size: {result['file_size']}")
        print(f"    md5:       {result['md5']}")
        print(f"    sha256:    {result['sha256'][:32]}...")
        print(f"    metadata:  {list(result['metadata'].keys())}")
        print(f"    indicators:{result['indicators']}")

    print("\n  PASS\n")


if __name__ == "__main__":
    test_hash_analyzer()
    test_type_detector()
    test_metadata_analyzer()
    test_file_security()
    test_full_analysis()
    print("ALL TESTS PASSED")
