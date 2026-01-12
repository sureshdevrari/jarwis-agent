import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from .config import DEFAULT_CLOUD_CONFIG
from .schemas import CloudFinding, CloudScanContext, ScannerMetadata


class CloudScanner(ABC):
    metadata: ScannerMetadata

    def __init__(self, config: Dict[str, Any]) -> None:
        merged = {**DEFAULT_CLOUD_CONFIG, **(config or {})}
        self.config = merged
        self.rate_limit = float(merged.get("rate_limit", DEFAULT_CLOUD_CONFIG["rate_limit"]))
        self.max_concurrency = int(merged.get("max_concurrency", DEFAULT_CLOUD_CONFIG["max_concurrency"]))
        self.retries = int(merged.get("retries", DEFAULT_CLOUD_CONFIG["retries"]))
        self.backoff = float(merged.get("backoff", DEFAULT_CLOUD_CONFIG["backoff"]))
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._metrics: List[Dict[str, Any]] = []

    @abstractmethod
    async def scan(self, context: CloudScanContext) -> List[CloudFinding]:
        raise NotImplementedError

    async def _sleep_rate(self) -> None:
        delay = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        if delay > 0:
            await asyncio.sleep(delay)

    async def run_limited(self, coro):
        async with self._sem:
            return await coro

    def validate_config(self) -> None:
        return None

    @property
    def name(self) -> str:
        return getattr(self, "metadata", None).name if getattr(self, "metadata", None) else self.__class__.__name__

    async def with_retry(self, func, *args, retries: int = 3, backoff: float = 0.5, **kwargs):
        attempt = 0
        last_exc = None
        use_retries = retries if retries is not None else self.retries
        use_backoff = backoff if backoff is not None else self.backoff
        while attempt < use_retries:
            try:
                result_coro = func(*args, **kwargs)
                return await result_coro
            except Exception as e:
                last_exc = e
                await asyncio.sleep(use_backoff * (2 ** attempt))
                attempt += 1
        raise last_exc

    def log_event(self, event: str, message: str, **fields: Any) -> None:
        payload = {"event": event, "message": message, **fields}
        self.logger.info(payload)

    def record_metric(self, name: str, value: float, **dimensions: Any) -> None:
        metric = {"name": name, "value": value, **dimensions}
        self._metrics.append(metric)


__all__ = ["CloudScanner"]
