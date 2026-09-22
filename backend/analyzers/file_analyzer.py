from analyzers.hash_analyzer import compute_hashes
from analyzers.type_detector import detect_type_from_bytes, detect_type_from_extension
from analyzers.metadata_analyzer import extract_metadata
from utils.file_security import (
    validate_filename,
    validate_file_size,
    validate_extension,
    scan_for_dangerous_patterns,
    create_secure_tempfile,
    cleanup_tempfile,
    FileSecurityError,
    EmptyFileError,
    FileTooLargeError,
    BlockedFileError,
)


def analyze_file(file_storage, max_upload_size: int = 0) -> dict:
    tmp_path = None
    try:
        original_filename = getattr(file_storage, "filename", "unknown")
        validate_filename(original_filename)

        data = file_storage.read()
        validate_file_size(data, max_upload_size)

        ext = validate_extension(original_filename)

        hashes = compute_hashes(data)

        detected = detect_type_from_bytes(data)
        ext_mime = detect_type_from_extension(ext)
        if detected["mime"] == "application/octet-stream" and ext_mime != "application/octet-stream":
            detected["mime"] = ext_mime

        tmp_path = create_secure_tempfile(data, suffix=ext or ".tmp")
        file_meta = extract_metadata(tmp_path, original_filename)

        indicators = scan_for_dangerous_patterns(data)

        return {
            "filename": original_filename,
            "extension": ext,
            "file_type": f"{detected['type']}/{detected['subtype']}",
            "mime_type": detected["mime"],
            "file_size": len(data),
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "indicators": indicators,
            "metadata": {
                "original_filename": file_meta["original_filename"],
                "extension": file_meta["extension"],
                "basename": file_meta["basename"],
                "file_size": file_meta["file_size"],
                "created_at": file_meta["created_at"],
                "modified_at": file_meta["modified_at"],
                "accessed_at": file_meta["accessed_at"],
                "detected_type": detected["type"],
                "detected_subtype": detected["subtype"],
            },
        }

    except FileSecurityError:
        raise
    except Exception as e:
        raise FileSecurityError(f"Analysis failed: {e}")
    finally:
        if tmp_path:
            cleanup_tempfile(tmp_path)
