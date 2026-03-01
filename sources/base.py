"""
Base class for all data sources.
Each source module inherits from this and implements fetch().
"""

import time
import random
from abc import ABC, abstractmethod
from typing import List, Optional
from ..config import SourceConfig
from ..models import Subdomain


class BaseSource(ABC):
    """Abstract base class for subdomain data sources."""

    def __init__(self, config: SourceConfig):
        self.config = config
        self.name = config.name
        self.results: List[str] = []
        self.count: int = 0
        self.elapsed: float = 0.0

    @abstractmethod
    def fetch(self, domain: str) -> List[str]:
        """
        Fetch subdomains from this source for the given domain.
        Returns a list of subdomain hostnames.
        """
        pass

    @abstractmethod
    def fetch_demo(self, domain: str) -> List[str]:
        """
        Generate demo/simulated data for testing output rendering.
        Returns a list of subdomain hostnames.
        """
        pass

    def run(self, domain: str, demo: bool = False) -> List[str]:
        """Execute fetch with timing."""
        start = time.time()
        try:
            if demo:
                self.results = self.fetch_demo(domain)
            else:
                self.results = self.fetch(domain)
        except Exception as e:
            self.results = []
        self.elapsed = time.time() - start
        self.count = len(self.results)
        return self.results

    def _generate_demo_subdomains(self, domain: str, count: int) -> List[str]:
        """Helper to generate realistic-looking demo subdomains."""
        from ..utils import generate_random_subdomain
        subs = set()
        while len(subs) < count:
            subs.add(generate_random_subdomain(domain))
        return list(subs)
