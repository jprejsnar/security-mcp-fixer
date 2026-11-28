"""Run independent I/O together and return results in request order.

A single item stays on the caller thread. The pool exists only for the
call and is shut down before return, so worker threads are not left behind.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextvars import copy_context
from itertools import islice
from time import perf_counter
from typing import TypeVar

from gitlab_security_mcp.util import (
    _resource_counters,
    _resource_interval,
    log_concurrency,
)

MAX_WORKERS = 8

Item = TypeVar("Item")
Result = TypeVar("Result")


def map_ordered(
    function: Callable[[Item], Result],
    items: Iterable[Item],
    *,
    on_result: Callable[[int, Result], None] | None = None,
) -> list[Result]:
    """Apply function to each item and keep the input order.

    The caller owns shutdown of any client the function uses. An exception
    from function propagates after the pool finishes work it already started
    and cancels work it has not started.
    on_result runs on the caller thread as each result arrives, before more
    work is submitted. Its index identifies the original input position.
    """
    remaining = iter(items)
    sequence = list(islice(remaining, MAX_WORKERS))
    if len(sequence) <= 1:
        single_results = []
        for index, item in enumerate(sequence):
            result = function(item)
            if on_result is not None:
                on_result(index, result)
            single_results.append(result)
        return single_results
    workers = min(MAX_WORKERS, len(sequence))
    before = _resource_counters()
    started = perf_counter()
    error = None
    submitted = len(sequence)
    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="security-io"
    ) as pool:
        pending: dict[Future[Result], int] = {}
        results: dict[int, Result] = {}
        try:
            for index, item in enumerate(sequence):
                pending[pool.submit(copy_context().run, function, item)] = index
            while pending:
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    index = pending.pop(future)
                    results[index] = future.result()
                    if on_result is not None:
                        on_result(index, results[index])
                for item in islice(remaining, len(completed)):
                    pending[pool.submit(copy_context().run, function, item)] = submitted
                    submitted += 1
            return [results[index] for index in range(submitted)]
        except BaseException as exc:
            error = type(exc).__name__
            raise
        finally:
            for future in pending:
                future.cancel()
            elapsed = perf_counter() - started
            log_concurrency(
                "fanout",
                "security-io",
                workers=workers,
                items=submitted,
                duration_ms=round(elapsed * 1000, 3),
                error=error,
                **_resource_interval(before, _resource_counters(), elapsed),
            )
