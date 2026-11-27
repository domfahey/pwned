from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import IO

import httpx
from pydantic import Field

from pwned._parsers import _parse_range_response
from pwned.client import MAX_RETRIES, REQUEST_TIMEOUT, HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import NonNegativeInt, _HIBPBase
from pwned.passwords import BASE_URL

MAX_PREFIX_EXCLUSIVE = 0x100000


class DownloadStats(_HIBPBase):
    """Summary statistics returned by :func:`download_offline_db`."""

    prefixes_total: NonNegativeInt
    prefixes_downloaded: NonNegativeInt
    prefixes_cached: NonNegativeInt
    hashes_written: NonNegativeInt
    elapsed_seconds: float = Field(ge=0.0)
    output_path: str
    ntlm: bool = False


def _validate_options(
    *,
    concurrency: int,
    max_retries: int,
    start_prefix: int,
    end_prefix: int,
) -> None:
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if max_retries < 0:
        raise ValueError("max_retries must be non-negative")
    if start_prefix < 0 or end_prefix > MAX_PREFIX_EXCLUSIVE or start_prefix >= end_prefix:
        raise ValueError(
            "start_prefix and end_prefix must satisfy "
            f"0 <= start_prefix < end_prefix <= 0x{MAX_PREFIX_EXCLUSIVE:X}"
        )


def _load_etags(path: Path) -> dict[str, str]:
    """Load a prefix -> ETag mapping from JSON, returning {} if missing or invalid."""
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, str)}


@contextlib.contextmanager
def _atomic_open(target: Path) -> Iterator[IO[str]]:
    """Open a sibling temp file for writing and atomically replace `target` on success."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            yield handle
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _merge_shards(
    output_path: Path,
    work_dir: Path,
    start_prefix: int,
    end_prefix: int,
) -> int:
    """Merge sorted shards into `output_path` atomically and return total hashes written."""
    hashes_written = 0
    with _atomic_open(output_path) as handle:
        for prefix_int in range(start_prefix, end_prefix):
            prefix = f"{prefix_int:05X}"
            shard_path = work_dir / prefix[:2] / f"{prefix}.txt"
            counts = _parse_range_response(shard_path.read_text(encoding="utf-8"))
            for suffix, count in sorted(counts.items()):
                handle.write(f"{prefix}{suffix}:{count}\r\n")
                hashes_written += 1
    return hashes_written


async def download_offline_db(
    output_path: Path,
    *,
    ntlm: bool = False,
    concurrency: int = 32,
    resume: bool = True,
    overwrite: bool = True,
    etag_cache_path: Path | None = None,
    start_prefix: int = 0x00000,
    end_prefix: int = MAX_PREFIX_EXCLUSIVE,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = REQUEST_TIMEOUT,
    max_retries: int = MAX_RETRIES,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_progress: Callable[[int, int], None] | None = None,
) -> DownloadStats:
    """Download an offline HIBP Pwned Passwords dump compatible with ``OfflinePasswordsClient``.

    Downloads 5-character hash range shards into a resumable work directory
    (``.<output_path.name>.part``) and merges them in ascending lexicographical order into
    ``output_path`` using an atomic file replacement.

    When ``overwrite`` is ``False`` and ``output_path`` already exists, raises
    :class:`FileExistsError` before creating any work directory or issuing HTTP requests.

    When ``etag_cache_path`` is provided, the sharded work directory is preserved after completion
    so future runs with ``resume=True`` can send ``If-None-Match`` headers and retain existing
    shards on HTTP 304 responses. When ``etag_cache_path`` is ``None``, the work directory is
    removed after the merged output file is written.
    """
    _validate_options(
        concurrency=concurrency,
        max_retries=max_retries,
        start_prefix=start_prefix,
        end_prefix=end_prefix,
    )
    if not overwrite and output_path.exists():
        raise FileExistsError(
            f"Output file already exists: {output_path} (use --overwrite to replace)"
        )

    started = time.monotonic()
    work_dir = output_path.parent / f".{output_path.name}.part"
    if not resume and work_dir.exists():
        shutil.rmtree(work_dir)

    etags: dict[str, str] = _load_etags(etag_cache_path) if etag_cache_path is not None else {}
    params: dict[str, str] = {"mode": "ntlm"} if ntlm else {}
    total_prefixes = end_prefix - start_prefix

    prefixes_downloaded = 0
    prefixes_cached = 0
    completed = 0

    owns_client = client is None
    active_client = (
        client
        if client is not None
        else httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            proxy=proxy,
        )
    )

    async def _process_prefix(prefix_int: int) -> None:
        nonlocal prefixes_downloaded, prefixes_cached, completed
        prefix = f"{prefix_int:05X}"
        shard_path = work_dir / prefix[:2] / f"{prefix}.txt"

        if resume and shard_path.exists() and etag_cache_path is None:
            prefixes_cached += 1
        else:
            headers: dict[str, str] = {}
            if resume and shard_path.exists():
                cached_etag = etags.get(prefix)
                if cached_etag is not None:
                    headers["If-None-Match"] = cached_etag

            attempt = 0
            while True:
                try:
                    resp = await active_client.get(
                        f"/range/{prefix}",
                        headers=headers,
                        params=params,
                    )
                except httpx.RequestError as exc:
                    if attempt < max_retries:
                        await sleep(min(0.5 * (2**attempt), 10.0))
                        attempt += 1
                        continue
                    raise HIBPError(f"Request failed for prefix {prefix}: {exc}") from exc

                if resp.status_code == 304 and "If-None-Match" in headers:
                    prefixes_cached += 1
                    break
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < max_retries:
                        await sleep(min(0.5 * (2**attempt), 10.0))
                        attempt += 1
                        continue
                    raise HIBPError(f"HTTP {resp.status_code} for prefix {prefix}")
                if resp.status_code != 200:
                    raise HIBPError(f"HTTP {resp.status_code} for prefix {prefix}")

                shard_path.parent.mkdir(parents=True, exist_ok=True)
                shard_path.write_text(resp.text, encoding="utf-8")
                new_etag = resp.headers.get("etag")
                if new_etag:
                    etags[prefix] = new_etag
                prefixes_downloaded += 1
                break

        completed += 1
        if on_progress is not None:
            on_progress(completed, total_prefixes)

    prefix_iter = iter(range(start_prefix, end_prefix))

    async def _worker() -> None:
        for prefix_int in prefix_iter:
            await _process_prefix(prefix_int)

    try:
        worker_count = min(concurrency, total_prefixes)
        workers = [asyncio.create_task(_worker()) for _ in range(worker_count)]
        try:
            await asyncio.gather(*workers)
        except BaseException:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise
    finally:
        if owns_client:
            await active_client.aclose()

    hashes_written = _merge_shards(output_path, work_dir, start_prefix, end_prefix)

    if etag_cache_path is not None:
        with _atomic_open(etag_cache_path) as handle:
            handle.write(json.dumps(etags, sort_keys=True, indent=2))
    else:
        # Without ETag revalidation, shards are no longer needed once merged.
        shutil.rmtree(work_dir)

    return DownloadStats(
        prefixes_total=total_prefixes,
        prefixes_downloaded=prefixes_downloaded,
        prefixes_cached=prefixes_cached,
        hashes_written=hashes_written,
        elapsed_seconds=max(0.0, time.monotonic() - started),
        output_path=str(output_path),
        ntlm=ntlm,
    )
