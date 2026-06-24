import ustruct

from storage import cache_common as cc
from storage.cache import get_sessionless_cache
from trezor import app
from trezor.crypto import random
from trezor.messages import (
    TrezorAppDataChunkAck,
    TrezorAppDataChunkRequest,
    TrezorAppHeaderAck,
    TrezorAppHeaderRequest,
    TrezorAppLoad,
    TrezorAppLoaded,
)
from trezor.wire import context
from trezor.wire.errors import DataError


def image_matches(image: app.AppImage, msg: TrezorAppLoad) -> bool:
    if not image.is_ready():
        return False
    if image.get_id() != msg.id:
        return False
    if image.get_version() < tuple(msg.version):
        return False
    if msg.hash != b"" and image.get_header_hash() != msg.hash:
        return False
    return True


async def _load_image(msg: TrezorAppLoad) -> app.AppImage:
    from trezor import app
    from trezor.ui.layouts.progress import progress

    binary = await context.call(
        TrezorAppHeaderRequest(),
        TrezorAppHeaderAck,
    )

    image = app.create_image(binary.header, binary.proof)

    prog = progress("Loading app...")
    chunk_size = image.get_chunk_size()
    chunk_count = (image.get_size() + chunk_size - 1) // chunk_size
    for chunk_index in range(chunk_count):
        prog.report(int(chunk_index / chunk_count * 1000))
        chunk = await context.call(
            TrezorAppDataChunkRequest(
                index=chunk_index,
            ),
            TrezorAppDataChunkAck,
        )
        image.write_chunk(chunk.data, chunk.hash)

    if not image_matches(image, msg):
        image.delete()
        raise DataError("Loaded image does not match the expected app")

    prog.stop()
    return image


async def load(msg: TrezorAppLoad) -> TrezorAppLoaded:
    """Load external application from a host and return its hash."""
    from trezor import app

    image = app.get_image_by_index(0)

    if image is not None:
        if not image_matches(image, msg):
            image.delete()
            image = None
        elif image.is_running():
            image.stop()  # ensure clean state

    if image is None:
        try:
            image = await _load_image(msg)
            assert image is not None
        except Exception as e:
            raise DataError(f"Failed to load app: {e}") from e

    image.run()

    instance_id = random.uniform(2**32 - 1)
    cache_entry = ustruct.pack("<BI", image.get_handle(), instance_id)
    get_sessionless_cache().set(cc.APP_EXTAPP_IDS, cache_entry)
    return TrezorAppLoaded(instance_id=instance_id)
