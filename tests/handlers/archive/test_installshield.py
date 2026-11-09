"""Regression tests for InstallShield cabinet validation and multi-volume sets.

The sample cabinets are the original fixtures from Ext745's PR #1689.
"""

import shutil
import struct
import tarfile
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.installshield import (
    InstallShieldSetHandler,
    UnshieldSetExtractor,
    cabinet_end,
)
from unblob.report import ExtractionProblem

INPUTS = (
    Path(__file__).parents[2]
    / "integration"
    / "archive"
    / "installshield"
    / "__input__"
)


def test_real_v5_cabinet_bounds():
    contents = (INPUTS / "standard.cab").read_bytes()
    with File.from_bytes(contents) as f:
        assert cabinet_end(f, 0) == len(contents)


def test_real_v5_cabinet_embedded_bounds():
    contents = b"prefix" + (INPUTS / "standard.cab").read_bytes() + b"suffix"
    with File.from_bytes(contents) as f:
        assert cabinet_end(f, 6) == len(contents) - 6


def test_tiny_forged_descriptor_is_not_a_cabinet():
    # Before the fix, this 101-byte magic match passed as a complete chunk,
    # despite having no real descriptor or file table.
    contents = bytearray(101)
    struct.pack_into("<4sIIII", contents, 0, b"ISc(", 0x01000004, 0, 20, 1)
    struct.pack_into("<I", contents, 20 + 7 * 4, 100)
    struct.pack_into("<I", contents, 20 + 9 * 4, 1)
    with File.from_bytes(contents) as f, pytest.raises(InvalidInputFormat):
        cabinet_end(f, 0)


@pytest.mark.parametrize(
    "offset,value",
    [
        (12, 20),  # descriptor overlaps the 40-byte V5 volume header
        (16, 1),  # impossibly short V5 descriptor
        (0x200 + 0x0C, 0x400),  # table outside declared descriptor
        (0x200 + 0x280 + 4, 0x500),  # file descriptor outside descriptor
    ],
)
def test_invalid_descriptor_bounds(offset: int, value: int):
    contents = bytearray((INPUTS / "standard.cab").read_bytes())
    struct.pack_into("<I", contents, offset, value)
    with File.from_bytes(contents) as f, pytest.raises(InvalidInputFormat):
        cabinet_end(f, 0)


def _cabinet_set(root: Path):
    with tarfile.open(INPUTS / "set.tar") as archive:
        for name in ("data1.hdr", "data1.cab"):
            with archive.extractfile(f"set/{name}") as src:
                (root / name).write_bytes(src.read())


def test_complete_set_preserves_original_behavior(tmp_path: Path):
    _cabinet_set(tmp_path)
    paths = InstallShieldSetHandler().calculate_multifile(tmp_path / "data1.hdr")
    assert paths is not None
    assert [p.name for p in paths.paths] == ["data1.hdr", "data1.cab"]


def test_gap_is_reported_instead_of_silently_extracted(tmp_path: Path):
    _cabinet_set(tmp_path)
    shutil.copyfile(tmp_path / "data1.cab", tmp_path / "data3.cab")
    paths = InstallShieldSetHandler().calculate_multifile(tmp_path / "data1.hdr")
    assert paths is not None
    assert [p.name for p in paths.paths] == ["data1.hdr", "data1.cab", "data3.cab"]

    output = tmp_path / "extracted"
    output.mkdir()
    result = UnshieldSetExtractor().extract(paths.paths, output)
    assert result is not None
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "data2.cab" in result.reports[0].problem
    assert not list(output.iterdir())


def test_corrupted_volume_is_reported(tmp_path: Path):
    _cabinet_set(tmp_path)
    (tmp_path / "data2.cab").write_bytes(b"not an InstallShield cabinet")
    paths = InstallShieldSetHandler().calculate_multifile(tmp_path / "data1.hdr")
    assert paths is not None
    assert [p.name for p in paths.paths] == ["data1.hdr", "data1.cab", "data2.cab"]

    output = tmp_path / "extracted"
    output.mkdir()
    result = UnshieldSetExtractor().extract(paths.paths, output)
    assert result is not None
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "data2.cab" in result.reports[0].problem
    assert not list(output.iterdir())
