"""InstallShield cabinet files (data1.hdr / data1.cab), extracted with unshield.

Format: as read by unshield (https://github.com/twogood/unshield, MIT): a
common header, a cabinet descriptor with a file table, and file data. The
file handler takes self-contained cabinets of the version 5 layout (header
version 0x01xxxxxx, major 0 or 5). From version 6 on, the file table is in
data1.hdr and the data in data1.cab ... dataN.cab, so a set (data1.hdr and/or
data1.cab ... dataN.cab in one directory) is taken by the directory handler
and given to unshield whole, whatever its version.
"""

import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    DirectoryExtractor,
    DirectoryHandler,
    ExtractError,
    Extractor,
    ExtractResult,
    File,
    Glob,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    MultiFile,
    Reference,
    ValidChunk,
)
from unblob.report import (
    ExtractCommandFailedReport,
    ExtractionProblem,
    ExtractorDependencyNotFoundReport,
)

COMMON = struct.Struct(
    "<4sIIII"
)  # signature, version, volume info, descriptor offset, size
VOLUME_V5 = struct.Struct(
    "<10I"
)  # data offset, unknown, first/last index, first/last file
FILE_INVALID = 0x8
FD_FLAGS, FD_SIZES, FD_DATA_OFFSET = 8, 10, 0x26  # within a v5 file descriptor
# From unshield 1.6.2 (libunshield.c, file.c): descriptor has a 0x3e-byte
# fixed header followed by two arrays of 71 uint32 offsets. V5 file
# descriptors have 0x3a bytes, including their MD5 field.
MIN_DESCRIPTOR_SIZE = 0x3E + 2 * 71 * 4
FILE_DESCRIPTOR_V5_SIZE = 0x3A


def _unpack(fmt: str | struct.Struct, buf, offset: int) -> tuple:
    layout = fmt if isinstance(fmt, struct.Struct) else struct.Struct(fmt)
    if offset < 0 or offset + layout.size > len(buf):
        raise InvalidInputFormat(
            "InstallShield structure runs past the end of the data"
        )
    return layout.unpack_from(buf, offset)


def major_version(version: int) -> int:
    """Major format version, as unshield derives it (minimum 5)."""
    if version >> 24 == 1:
        major = (version >> 12) & 0xF
    elif version >> 24 in (2, 4):
        major = (version & 0xFFFF) // 100
    else:
        raise InvalidInputFormat(
            f"unknown InstallShield header version 0x{version:08x}"
        )
    return max(major, 5)


def _file_table_end(buf, start: int, descriptor: int, descriptor_end: int) -> int:
    """Furthest V5 file end; table and descriptors must fit their declared region."""
    (table_offset,) = _unpack("<I", buf, descriptor + 0x0C)
    (directories,) = _unpack("<I", buf, descriptor + 0x1C)
    (files,) = _unpack("<I", buf, descriptor + 0x28)
    table = descriptor + table_offset
    # Check before building a Struct: corrupt count fields can be UINT32_MAX.
    if table < descriptor or table > descriptor_end:
        raise InvalidInputFormat("InstallShield file table outside descriptor")
    if directories + files > (descriptor_end - table) // 4:
        raise InvalidInputFormat("InstallShield file table exceeds descriptor")
    offsets = _unpack(f"<{directories + files}I", buf, table)
    end = 0
    for entry in offsets[directories:]:
        fd = table + entry
        if fd < descriptor or fd + FILE_DESCRIPTOR_V5_SIZE > descriptor_end:
            raise InvalidInputFormat("InstallShield file descriptor exceeds descriptor")
        (flags,) = _unpack("<H", buf, fd + FD_FLAGS)
        _expanded, compressed = _unpack("<II", buf, fd + FD_SIZES)
        (data_offset,) = _unpack("<I", buf, fd + FD_DATA_OFFSET)
        if flags & FILE_INVALID or not data_offset:
            continue
        end = max(end, start + data_offset + compressed)
    return end


def cabinet_end(buf, start: int) -> int:
    """End offset of the self-contained cabinet at start."""
    signature, version, _info, desc_offset, desc_size = _unpack(COMMON, buf, start)
    if signature != b"ISc(":
        raise InvalidInputFormat("no ISc( signature")
    if major_version(version) != 5:
        raise InvalidInputFormat("only the version 5 cabinet layout is handled")
    # A valid V5 descriptor must begin after the volume header and contain
    # its fixed field tables; just checking for nonzero size accepts a
    # fabricated 101-byte ISc( blob as a complete cabinet.
    if desc_offset < COMMON.size + VOLUME_V5.size:
        raise InvalidInputFormat("InstallShield descriptor overlaps volume header")
    if desc_size < MIN_DESCRIPTOR_SIZE:
        raise InvalidInputFormat("InstallShield descriptor too short")
    descriptor = start + desc_offset
    descriptor_end = descriptor + desc_size
    if descriptor_end > len(buf):
        raise InvalidInputFormat("InstallShield descriptor exceeds input")
    end = max(
        descriptor_end,
        _file_table_end(buf, start, descriptor, descriptor_end),
    )
    volume = _unpack(VOLUME_V5, buf, start + COMMON.size)
    last_offset, last_compressed = volume[7], volume[9]
    if last_offset:  # a spanned volume records where its data ends
        end = max(end, start + last_offset + last_compressed)
    if end > len(buf):
        raise InvalidInputFormat("file data lies beyond the data (a multi-volume set)")
    return end


def run_tool(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run unshield; a missing command is a dependency report."""
    try:
        return subprocess.run(command, capture_output=True, check=False)
    except FileNotFoundError:
        raise ExtractError(
            ExtractorDependencyNotFoundReport(dependencies=[command[0]])
        ) from None


def run_unshield(target: Path, outdir: Path) -> None:
    """Extract with unshield into outdir, only if it succeeds.

    Some cabinets need unshield's old-compression mode (-O); unshield's own
    tests mark the Avigo Manager set so. A failed run (a missing volume,
    say) leaves nothing in outdir.
    """
    result = None
    for options in ([], ["-O"]):
        with tempfile.TemporaryDirectory() as tmp:
            command = ["unshield", *options, "-d", tmp, "x", str(target)]
            result = run_tool(command)
            if result.returncode == 0:
                for item in Path(tmp).iterdir():
                    shutil.move(item, outdir / item.name)
                return
    assert result is not None
    raise ExtractError(
        ExtractCommandFailedReport(
            command=" ".join(result.args),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
        )
    )


class UnshieldExtractor(Extractor):
    def get_dependencies(self) -> list[str]:
        return ["unshield"]

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        # unshield derives sibling volume names from "data1.cab".
        with tempfile.TemporaryDirectory() as tmp:
            cab = Path(tmp) / "data1.cab"
            shutil.copyfile(inpath, cab)
            run_unshield(cab, outdir)
        return ExtractResult(reports=[])


class InstallShieldHandler(Handler):
    NAME = "installshield"
    PATTERNS = [HexString("49 53 63 28")]  # "ISc("
    EXTRACTOR = UnshieldExtractor()
    DOC = HandlerDoc(
        name="InstallShield cabinet",
        description="InstallShield cabinet (data1.cab) holding an installer's files, extracted with unshield.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Flexera (InstallShield)",
        references=[
            Reference(title="unshield", url="https://github.com/twogood/unshield"),
            Reference(
                title="InstallScript .cab and .hdr files",
                url="https://docs.revenera.com/installshield/helplibrary/IsCabViewOverview.htm",
            ),
        ],
        limitations=[
            "Only the version 5 cabinet layout as a single file",
            "Multi-volume sets are taken by installshield_set",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        return ValidChunk(
            start_offset=start_offset, end_offset=cabinet_end(file, start_offset)
        )


def _volume_number(path: Path) -> int | None:
    """N for dataN.cab (any case), else None."""
    name = path.name.lower()
    if name.startswith("data") and name.endswith(".cab") and name[4:-4].isdigit():
        return int(name[4:-4])
    return None


def _is_cabinet(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"ISc("


class UnshieldSetExtractor(DirectoryExtractor):
    def get_dependencies(self) -> list[str]:
        return ["unshield"]

    def extract(self, paths: list[Path], outdir: Path) -> ExtractResult | None:
        # A gap can otherwise cause the directory handler to silently omit
        # later cabinets while unshield succeeds on the earlier ones.
        numbers = {_volume_number(path) for path in paths}
        numbers.discard(None)
        if not numbers or numbers != set(range(1, max(numbers) + 1)):
            missing = sorted(set(range(1, max(numbers, default=1) + 1)) - numbers)
            return ExtractResult(
                reports=[
                    ExtractionProblem(
                        problem=(
                            "Incomplete InstallShield cabinet set: missing "
                            + ", ".join(f"data{n}.cab" for n in missing)
                        ),
                        resolution="Skipped extraction to avoid silently missing files.",
                    )
                ]
            )
        invalid = [
            path.name
            for path in paths
            if _volume_number(path) is not None and not _is_cabinet(path)
        ]
        if invalid:
            return ExtractResult(
                reports=[
                    ExtractionProblem(
                        problem="Invalid InstallShield volume: " + ", ".join(invalid),
                        resolution="Skipped extraction to avoid silently missing files.",
                    )
                ]
            )
        # unshield finds the volumes by their lower-case names beside data1.
        with tempfile.TemporaryDirectory() as tmp:
            for path in paths:
                shutil.copyfile(path, Path(tmp) / path.name.lower())
            header = Path(tmp) / "data1.hdr"
            run_unshield(header if header.exists() else Path(tmp) / "data1.cab", outdir)
        return ExtractResult(reports=[])


class InstallShieldSetHandler(DirectoryHandler):
    NAME = "installshield_set"
    PATTERN = Glob("[dD][aA][tT][aA]1.[hH][dD][rR]", "[dD][aA][tT][aA]1.[cC][aA][bB]")
    EXTRACTOR = UnshieldSetExtractor()
    DOC = HandlerDoc(
        name="InstallShield multi-volume set",
        description="InstallShield cabinet set: data1.hdr and/or data1.cab ... dataN.cab in one directory, extracted as one set with unshield.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Flexera (InstallShield)",
        references=[
            Reference(title="unshield", url="https://github.com/twogood/unshield"),
        ],
        limitations=["Volumes must be named dataN.cab and numbered without gaps"],
    )

    def calculate_multifile(self, file: Path) -> MultiFile | None:
        siblings = {p.name.lower(): p for p in file.parent.iterdir() if p.is_file()}
        header = siblings.get("data1.hdr")
        if file.name.lower() == "data1.cab" and header is not None:
            return None  # the set starts at data1.hdr
        if not _is_cabinet(file):
            return None
        # Collect *all* numbered volumes, including those after a numbering
        # gap, so the extractor can report incomplete sets instead of
        # silently claiming a successful partial extraction.
        volumes = [
            (number, path)
            for path in siblings.values()
            if (number := _volume_number(path)) is not None and number >= 1
        ]
        volumes.sort()
        if header is None and len(volumes) < 2:
            return None
        volumes = [path for _, path in volumes]
        paths = ([header] if header is not None else []) + volumes
        return MultiFile(name=file.stem, paths=paths)
