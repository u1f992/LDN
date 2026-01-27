
from collections.abc import AsyncIterator

import contextlib
import trio


@contextlib.asynccontextmanager
async def background_task(task, *args) -> AsyncIterator[None]:
    """
    Starts a task in the background and cancels it as soon as the context
    manager exits.
    """
    async with trio.open_nursery() as nursery:
        nursery.start_soon(task, *args)
        yield
        nursery.cancel_scope.cancel()
