"""Scope guard: only lab targets on the allow-list may ever be touched."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

DEFAULT_ALLOW = ["127.0.0.0/8", "localhost", "::1/128"]


class OutOfScopeError(Exception):
    pass


class ScopeGuard:
    def __init__(self, allow: list[str] | None = None):
        self.hosts: set[str] = set()
        self.nets: list[ipaddress._BaseNetwork] = []
        for item in allow or DEFAULT_ALLOW:
            try:
                self.nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                self.hosts.add(item.lower())

    @staticmethod
    def _host(target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or "").lower()
        host = target.split("/")[0]
        if host.count(":") == 1:  # host:port
            host = host.split(":")[0]
        return host.lower().strip("[]")

    def allowed(self, target: str) -> bool:
        host = self._host(target)
        if host in self.hosts:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self.nets)

    def check(self, target: str) -> None:
        if not self.allowed(target):
            raise OutOfScopeError(f"target {target!r} is outside the lab scope")
