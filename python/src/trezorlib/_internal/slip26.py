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

from enum import IntEnum

from ..firmware.models import Model


# SLIP-26 purposes.
class Purpose(IntEnum):
    BOOTLOADER = 0
    VENDOR_HEADER = 1
    FIRMWARE = 2
    DEFINITIONS = 3
    PRODTEST = 4
    CA_FIRMWARE = 5
    BITCOIN_ONLY = 8
    TRANSLATIONS = 9
    SECURE_MONITOR = 10
    NRF_FIRMWARE = 11
    FIRMWARE_ROOT_2025 = 12


# Purpose strings used in fingerprints files ("<model>_<purpose>: HEX"). Only the
# purposes that are actually fingerprinted have a string representation.
PURPOSE_TO_STR: dict[Purpose, str] = {
    Purpose.BOOTLOADER: "bootloader",
    Purpose.FIRMWARE: "universal",
    Purpose.DEFINITIONS: "definitions",
    Purpose.PRODTEST: "prodtest",
    Purpose.CA_FIRMWARE: "ca",
    Purpose.BITCOIN_ONLY: "btconly",
    Purpose.TRANSLATIONS: "translations",
    Purpose.SECURE_MONITOR: "secmon",
    Purpose.NRF_FIRMWARE: "nrf",
    Purpose.FIRMWARE_ROOT_2025: "firmware_root_2025",
}
STR_TO_PURPOSE: dict[str, Purpose] = {v: k for k, v in PURPOSE_TO_STR.items()}

# Vendor-header text -> purpose, for classifying a vendor firmware image.
VENDOR_TEXT_TO_PURPOSE: dict[str, Purpose] = {
    "SatoshiLabs": Purpose.FIRMWARE,
    "Trezor": Purpose.FIRMWARE,
    "UNSAFE, FACTORY TEST ONLY": Purpose.PRODTEST,
    "Internal CA": Purpose.CA_FIRMWARE,
    "Trezor Bitcoin-only": Purpose.BITCOIN_ONLY,
}

# Vendor header `fw_type` (vendor_fw_type_t) -> purpose. Note that legacy vendor
# headers predate this field (value 0) and do not distinguish bitcoin-only, so
# classification by vendor text is more reliable for older images.
VENDOR_FW_TYPE_TO_PURPOSE: dict[int, Purpose] = {
    2: Purpose.FIRMWARE,
    4: Purpose.PRODTEST,
    5: Purpose.CA_FIRMWARE,
    3: Purpose.BITCOIN_ONLY,
}

_MODEL_NAMES = {model.value.decode() for model in Model}


def make_label(model_int: int, purpose: Purpose) -> str:
    """Render a fingerprints-file label, e.g. (T3W1, BITCOIN_ONLY) -> "t3w1_btconly".

    ``model_int`` is the little-endian ASCII model integer, or 0 for model-agnostic
    objects (rendered as the bare label).
    """
    purpose_str = PURPOSE_TO_STR.get(purpose)
    if purpose_str is None:
        raise ValueError(f"purpose {purpose} has no label")

    if model_int == 0:
        # model-agnostic label, e.g. "translations"
        return purpose_str

    return f"{model_int.to_bytes(4, 'little').decode().lower()}_{purpose_str}"


def parse_label(label: str) -> tuple[int, Purpose]:
    """Inverse of `make_label`: "model_label" -> (model integer, purpose)."""
    head, sep, tail = label.partition("_")
    if sep and head.upper() in _MODEL_NAMES:
        model_int = int.from_bytes(head.upper().encode(), "little")
        purpose_str = tail
    else:
        # model-agnostic label, e.g. "translations"
        model_int = 0
        purpose_str = label

    if purpose_str not in STR_TO_PURPOSE:
        raise ValueError(f"unknown label {label!r}")

    return model_int, STR_TO_PURPOSE[purpose_str]
