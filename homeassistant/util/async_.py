"""Asyncio backports for Python 3.6 compatibility."""
import asyncio
from asyncio import coroutines, ensure_future
from asyncio.events import AbstractEventLoop
import concurrent.futures
import logging
import threading
from typing import Any, Awaitable, Callable, Coroutine, List, Optional, TypeVar

_LOGGER = logging.getLogger(__name__)


try:
    # pylint: disable=invalid-name
    asyncio_run = asyncio.run  # type: ignore
except AttributeError:
    _T = TypeVar("_T")

    def asyncio_run(main: Awaitable[_T], *, debug: bool = False) -> _T:
        """Minimal re-implementation of asyncio.run (since 3.7)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_debug(debug)
        try:
            return loop.run_until_complete(main)
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def fire_coroutine_threadsafe(coro: Coroutine, loop: AbstractEventLoop) -> None:
    """Submit a coroutine object to a given event loop.

    This method does not provide a way to retrieve the result and
    is intended for fire-and-forget use. This reduces the
    work involved to fire the function on the loop.
    """
    ident = loop.__dict__.get("_thread_ident")
    if ident is not None and ident == threading.get_ident():
        raise RuntimeError("Cannot be called from within the event loop")

    if not coroutines.iscoroutine(coro):
        raise TypeError("A coroutine object is required: %s" % coro)

    def callback() -> None:
        """Handle the firing of a coroutine."""
        ensure_future(coro, loop=loop)

    loop.call_soon_threadsafe(callback)


def run_callback_threadsafe(
    loop: AbstractEventLoop, callback: Callable, *args: Any
) -> concurrent.futures.Future:
    """Submit a callback object to a given event loop.

    Return a concurrent.futures.Future to access the result.
    """
    ident = loop.__dict__.get("_thread_ident")
    if ident is not None and ident == threading.get_ident():
        raise RuntimeError("Cannot be called from within the event loop")

    future: concurrent.futures.Future = concurrent.futures.Future()

    def run_callback() -> None:
        """Run callback and store result."""
        try:
            future.set_result(callback(*args))
        except Exception as exc:  # pylint: disable=broad-except
            if future.set_running_or_notify_cancel():
                future.set_exception(exc)
            else:
                _LOGGER.warning("Exception on lost future: ", exc_info=True)

    loop.call_soon_threadsafe(run_callback)
    return future


async def safe_wait(
    tasks: List[Awaitable[Any]],
    logger: Optional[logging.Logger] = None,
    return_exceptions=False,
) -> List[Any]:
    """ Safe version of wait and gather.

    It work like gather but wait don't break any workflows.
    It allow also to log exception in correct namespace.
    """
    all_tasks = list(tasks)
    if not all_tasks:
        return []
    finished_tasks, _ = await asyncio.wait(all_tasks)

    results: List[Any] = []
    raise_exception: Optional[Exception] = None
    for task in finished_tasks:
        if not task.done():
            results.append(None)
        elif task.exception():
            if logger:
                logger.exception(task.exception())
            if not raise_exception:
                raise_exception = task.exception()
            results.append(task.exception())
        else:
            results.append(task.result())

    # Raise exception or return results
    if not return_exceptions and raise_exception:
        raise raise_exception
    return results
