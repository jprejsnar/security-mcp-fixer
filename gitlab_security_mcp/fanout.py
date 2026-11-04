"""Run independent I/O together and return results in request order.

A single item stays on the caller thread. The pool exists only for the
call and is shut down before return, so worker threads are not left behind.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

MAX_WORKERS = 8

Item = TypeVar("Item")
Result = TypeVar("Result")


def map_ordered(
    function: Callable[[Item], Result], items: Iterable[Item]
) -> list[Result]:
    """Apply function to each item and keep the input order.

    The caller owns shutdown of any client the function uses. An exception
    from function propagates after the pool finishes work it already started
    and cancels work it has not started.
    """
    sequence = list(items)
    if len(sequence) <= 1:
        return [function(item) for item in sequence]
    workers = min(MAX_WORKERS, len(sequence))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(function, sequence))
