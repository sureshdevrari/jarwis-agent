from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type

from attacks.cloud.base import CloudScanner
from attacks.cloud.schemas import Provider, ScannerMetadata


@dataclass
class CloudScannerEntry:
    cls: Type[CloudScanner]
    meta: ScannerMetadata


class CloudScannerRegistry:
    def __init__(self) -> None:
        self._by_provider: Dict[Provider, List[CloudScannerEntry]] = {}
        self._by_name: Dict[str, CloudScannerEntry] = {}

    def register(self, scanner_cls: Type[CloudScanner], meta: ScannerMetadata) -> None:
        entry = CloudScannerEntry(cls=scanner_cls, meta=meta)
        self._by_name[meta.name] = entry
        self._by_provider.setdefault(meta.provider, []).append(entry)

    def get_scanners(self, provider: Provider) -> List[Type[CloudScanner]]:
        return [e.cls for e in self._by_provider.get(provider, [])]

    def get_metadata(self, name: str) -> Optional[ScannerMetadata]:
        entry = self._by_name.get(name)
        return entry.meta if entry else None

    def list_providers(self) -> List[Provider]:
        return list(self._by_provider.keys())

    def all_entries(self) -> List[CloudScannerEntry]:
        items: List[CloudScannerEntry] = []
        for entries in self._by_provider.values():
            items.extend(entries)
        return items


registry = CloudScannerRegistry()


def load_default_cloud_scanners() -> CloudScannerRegistry:
    """Import and register built-in cloud scanners."""
    from attacks.cloud.aws_scanner import AWSScanner
    from attacks.cloud.azure_scanner import AzureScanner
    from attacks.cloud.gcp_scanner import GCPScanner

    registry.register(AWSScanner, AWSScanner.metadata)
    registry.register(AzureScanner, AzureScanner.metadata)
    registry.register(GCPScanner, GCPScanner.metadata)
    return registry


__all__ = ["CloudScannerRegistry", "CloudScannerEntry", "registry", "load_default_cloud_scanners"]
