from __future__ import annotations

from dataclasses import dataclass, field
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO

from .utils import file_kind, safe_decode, sha256_bytes, sha256_file


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 150 * 1024 * 1024
MAX_FILES = 2500


@dataclass
class ExtensionFile:
    path: str
    absolute_path: Path
    size: int
    sha256: str
    kind: str


@dataclass
class ExtractedExtension:
    original_name: str
    archive_sha256: str
    archive_size: int
    workdir: Path | None = None
    root_dir: Path | None = None
    manifest: dict = field(default_factory=dict)
    manifest_path: str = ""
    files: list[ExtensionFile] = field(default_factory=list)
    js_files: list[ExtensionFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.root_dir)

    def cleanup(self) -> None:
        if self.workdir and self.workdir.exists():
            shutil.rmtree(self.workdir, ignore_errors=True)


def prepare_upload(uploaded_file: BinaryIO, original_name: str = "extension.zip") -> ExtractedExtension:
    raw = uploaded_file.read()
    result = ExtractedExtension(
        original_name=original_name or "extension.zip",
        archive_sha256=sha256_bytes(raw),
        archive_size=len(raw),
    )

    if not raw:
        result.errors.append("Uploaded archive is empty.")
        return result
    if len(raw) > MAX_ARCHIVE_BYTES:
        result.errors.append("Archive exceeds the 50 MB forensic intake limit.")
        return result

    workdir = Path(tempfile.mkdtemp(prefix="extensionsentry_"))
    archive_path = workdir / "upload.zip"
    extract_dir = workdir / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(raw)
    result.workdir = workdir
    result.root_dir = extract_dir

    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_FILES:
                result.errors.append(f"Archive contains {len(members)} files; limit is {MAX_FILES}.")
                return result
            total_uncompressed = sum(max(member.file_size, 0) for member in members)
            if total_uncompressed > MAX_EXTRACTED_BYTES:
                result.errors.append("Archive expands beyond the 150 MB safety limit.")
                return result

            for member in members:
                if member.is_dir():
                    continue
                target = _safe_member_target(extract_dir, member.filename)
                if target is None:
                    result.warnings.append(f"Skipped unsafe path: {member.filename}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
    except zipfile.BadZipFile:
        result.errors.append("Uploaded file is not a valid ZIP archive.")
        return result
    except OSError as exc:
        result.errors.append(f"Archive could not be extracted: {exc}")
        return result

    _index_files(result)
    _load_manifest(result)
    return result


def _safe_member_target(root: Path, member_name: str) -> Path | None:
    normalized = member_name.replace("\\", "/").lstrip("/")
    if not normalized or normalized.startswith("../") or "/../" in normalized:
        return None
    target = (root / normalized).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def _index_files(result: ExtractedExtension) -> None:
    if not result.root_dir:
        return
    files: list[ExtensionFile] = []
    for path in result.root_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(result.root_dir).as_posix()
        try:
            size = path.stat().st_size
            files.append(
                ExtensionFile(
                    path=relative,
                    absolute_path=path,
                    size=size,
                    sha256=sha256_file(path),
                    kind=file_kind(path),
                )
            )
        except OSError as exc:
            result.warnings.append(f"Could not index {relative}: {exc}")
    result.files = sorted(files, key=lambda item: item.path)
    result.js_files = [item for item in result.files if item.kind == "javascript"]


def _load_manifest(result: ExtractedExtension) -> None:
    manifest_file = next(
        (item for item in result.files if item.path.lower().endswith("manifest.json")),
        None,
    )
    if manifest_file is None:
        result.errors.append("manifest.json was not found in the archive.")
        return
    result.manifest_path = manifest_file.path
    try:
        text = safe_decode(manifest_file.absolute_path.read_bytes(), limit=2 * 1024 * 1024)
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        result.errors.append(f"manifest.json is malformed JSON at line {exc.lineno}.")
        return
    except OSError as exc:
        result.errors.append(f"manifest.json could not be read: {exc}")
        return
    if not isinstance(loaded, dict):
        result.errors.append("manifest.json root must be an object.")
        return
    result.manifest = loaded
