#!/usr/bin/env python3

# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TextIO

import click

from trezorlib._internal.slip26 import (
    STR_TO_PURPOSE,
    VENDOR_TEXT_TO_PURPOSE,
    Purpose,
    make_label,
    parse_label,
)

# Artefact info and fingerprint: (model integer, purpose, 32-byte fingerprint).
ArtefactFingerprint = tuple[int, int, bytes]


def model_to_int(name: str) -> int:
    return int.from_bytes(name.encode(), "little")


def ensure32(value: bytes, where: object) -> None:
    if len(value) != 32:
        raise ValueError(f"{where}: fingerprint must be 32 bytes, got {len(value)}")


def fingerprint_from_bin(path: Path) -> ArtefactFingerprint:
    """Parse a Trezor firmware binary into (model integer, purpose, fingerprint).
    Raises if the image isn't a recognized target.
    """
    from trezorlib._internal import firmware_headers as fwh
    from trezorlib.firmware import models as fw_models

    try:
        fw = fwh.parse_image(path.read_bytes())
    except Exception as e:
        raise ValueError(f"{path}: not a recognized Trezor firmware image ({e})") from e

    def model_str(img: fwh.CosiSignedMixin) -> str:
        hw = img.get_header().hw_model
        if isinstance(hw, fw_models.Model):
            hw = hw.value
        return "T2T1" if hw == b"\x00\x00\x00\x00" else hw.decode()

    if isinstance(fw, fwh.SecmonImage):
        model, purpose, digest = model_str(fw), Purpose.SECURE_MONITOR, fw.digest()
    elif isinstance(fw, fwh.BootloaderImage):
        model, purpose, digest = model_str(fw), Purpose.BOOTLOADER, fw.digest()
    elif isinstance(fw, fwh.LegacyV2Firmware):
        # Legacy T1B1 has no hw_model in its header. Universal and bitcoin-only
        # variants are not distinguished.
        model, purpose, digest = "T1B1", Purpose.FIRMWARE, fw.digest()
    elif isinstance(fw, fwh.VendorFirmware):
        model = model_str(fw)
        try:
            # A vendor image may wrap a secmon-only build. If so, the relevant
            # fingerprint and purpose are the secmon's (matches firmware-fingerprint.py).
            digest = fwh.SecmonImage.parse(fw.firmware.code).digest()
            purpose = Purpose.SECURE_MONITOR
        except Exception:
            purpose = VENDOR_TEXT_TO_PURPOSE.get(fw.vendor_header.text)
            if purpose is None:
                raise ValueError(
                    f"{path}: unsupported vendor header {fw.vendor_header.text!r}"
                ) from None
            digest = fw.digest()
    else:
        raise ValueError(f"{path}: unsupported image type {type(fw).__name__}")

    ensure32(digest, path)
    return model_to_int(model), purpose, digest


def parse_fingerprints_file(f: TextIO) -> set[ArtefactFingerprint]:
    """Parse ``<model>_<type>: HEX`` lines (this tool's own output) into targets."""

    result: set[ArtefactFingerprint] = set()
    for lineno, raw in enumerate(f.read().splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        label, sep, hexval = line.partition(":")
        if not sep:
            raise ValueError(f"{f.name}:{lineno}: expected 'label: HEX', got {raw!r}")
        try:
            model, purpose = parse_label(label.strip())
        except ValueError as e:
            raise ValueError(f"{f.name}:{lineno}: {e}") from e
        value = bytes.fromhex(hexval.strip())
        ensure32(value, f"{f.name}:{lineno}")
        result.add((model, purpose, value))
    return result


def master_fingerprint(fingerprints: set[ArtefactFingerprint]) -> bytes:
    """Hash the targets into the master fingerprint, in canonical order."""

    if not fingerprints:
        raise ValueError("no fingerprints found")

    ctx = hashlib.sha256()
    for model, purpose, value in sorted(fingerprints):
        ctx.update(model.to_bytes(4, "little"))
        ctx.update(bytes([purpose]))
        ctx.update(value)
    return ctx.digest()


@click.command()
@click.argument(
    "paths",
    nargs=-1,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "-f",
    "--fingerprints",
    "fingerprints_files",
    multiple=True,
    type=click.File("r"),
    help="a fingerprints file in this tool's own '<model>_<type>: HEX' output "
    "format (may be given multiple times; merged with PATHS)",
)
@click.option(
    "--definitions", metavar="HEX", help="model-agnostic definitions fingerprint (hex)"
)
@click.option(
    "--translations",
    metavar="HEX",
    help="model-agnostic translations fingerprint (hex)",
)
def firmware_master_fingerprint(
    paths: tuple[Path, ...],
    fingerprints_files: tuple[TextIO, ...],
    definitions: str | None,
    translations: str | None,
) -> None:
    """Compute master fingerprint for a collection of fingerprints.

    PATHS are Trezor firmware binaries (.bin).

    Output is a `<model>_<type>: HEX` line per fingerprint plus the master
    fingerprint. The output round-trips via -f, so a fingerprints file can be
    assembled progressively -- dump the firmware lines from the binaries, append
    model-agnostic objects as `definitions:` / `translations:` lines, then feed
    the whole file back to compute the master.
    """
    try:
        fingerprints = {fingerprint_from_bin(path) for path in paths}
        for f in fingerprints_files:
            fingerprints |= parse_fingerprints_file(f)
        for word, hexval in (
            ("definitions", definitions),
            ("translations", translations),
        ):
            if hexval:
                value = bytes.fromhex(hexval)
                ensure32(value, word)
                fingerprints.add((0, STR_TO_PURPOSE[word], value))
        master = master_fingerprint(fingerprints)
    except ValueError as e:
        raise click.ClickException(str(e)) from e

    for model, purpose, value in sorted(fingerprints):
        click.echo(f"{make_label(model, purpose)}: {value.hex()}")

    master_hex = " ".join(
        master.hex()[i : i + 4] for i in range(0, len(master.hex()), 4)
    )
    click.echo(f"\nMaster fingerprint: {master_hex}", err=True)


if __name__ == "__main__":
    firmware_master_fingerprint()
