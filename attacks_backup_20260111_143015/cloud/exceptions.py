from typing import Optional


class CloudScanError(Exception):
    def __init__(
        self,
        message: str,
        *,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.service = service
        self.retryable = retryable


class ProviderAuthError(CloudScanError):
    pass


class ServicePermissionError(CloudScanError):
    pass


class ResourceDiscoveryError(CloudScanError):
    pass


class InvalidConfigError(CloudScanError):
    pass


class RateLimitError(CloudScanError):
    def __init__(self, message: str, *, provider: Optional[str] = None, service: Optional[str] = None) -> None:
        super().__init__(message, provider=provider, service=service, retryable=True)


class APIThrottlingError(CloudScanError):
    def __init__(self, message: str, *, provider: Optional[str] = None, service: Optional[str] = None) -> None:
        super().__init__(message, provider=provider, service=service, retryable=True)


class CloudTimeoutError(CloudScanError):
    def __init__(self, message: str, *, provider: Optional[str] = None, service: Optional[str] = None) -> None:
        super().__init__(message, provider=provider, service=service, retryable=True)


__all__ = [
    "CloudScanError",
    "ProviderAuthError",
    "ServicePermissionError",
    "ResourceDiscoveryError",
    "InvalidConfigError",
    "RateLimitError",
    "APIThrottlingError",
    "CloudTimeoutError",
]
