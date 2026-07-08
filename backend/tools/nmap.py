"""Nmap CLI wrapper (stub)."""

from typing import Any

from tools.base import BaseSecurityTool


class NmapTool(BaseSecurityTool):
    name = "nmap"

    async def run(self, target: str, scope: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("Nmap tool integration not yet implemented")
