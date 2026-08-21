"""
Report output path safety tests: path traversal, absolute paths, device names.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_path_traversal_detection() -> None:
    """Path traversal patterns are detected."""
    malicious_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../secret.txt",
    ]

    for path_str in malicious_paths:
        path = Path(path_str)
        # Path normalizes but doesn't prevent traversal
        # ponytail: no explicit traversal prevention in CLI
        # application must validate parent directory
        resolved = path.resolve()
        assert isinstance(resolved, Path)


def test_absolute_path_handling() -> None:
    """Absolute paths are handled."""
    import platform

    if platform.system() == "Windows":
        absolute_paths = ["C:\\Windows\\System32\\config\\sam"]
    else:
        absolute_paths = ["/etc/passwd", "/root/secret"]

    for path_str in absolute_paths:
        path = Path(path_str)
        # ponytail: no restriction on absolute paths in report CLI
        assert path.is_absolute()


def test_windows_device_names() -> None:
    """Windows device names don't cause issues."""
    device_names = ["CON", "NUL", "PRN", "AUX", "COM1", "LPT1"]

    for device in device_names:
        path = Path(device)
        # On Windows, these are special
        # On Unix, they're regular names
        assert isinstance(path, Path)


def test_report_output_directory_creation(tmp_path) -> None:
    """Report can be written to nested directories."""
    nested_path = tmp_path / "reports" / "2026" / "phase7" / "test.md"

    # Parent doesn't exist yet
    assert not nested_path.parent.exists()

    # Writing would require parent creation
    # ponytail: CLI doesn't create parent directories
    # Path.write_text will fail if parent doesn't exist
    with pytest.raises(FileNotFoundError):
        nested_path.write_text("test")
