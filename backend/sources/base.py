"""Abstract base class for CT log data sources."""

from abc import ABC, abstractmethod


class CTSource(ABC):
    """A single upstream source of certificate-transparency subdomain data."""

    name: str = "base"

    @abstractmethod
    async def query(self, client, apex: str) -> list[str]:
        """Return raw name entries (may include wildcards/duplicates)."""
        raise NotImplementedError
