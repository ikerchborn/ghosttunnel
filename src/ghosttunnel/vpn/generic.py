from __future__ import annotations
from ghosttunnel.core.models import VpnState, NetworkSnapshot

class VpnAdapter:
    """Base class for VPN Adapters."""
    
    def __init__(self, name: str):
        self.name = name

    def get_state(self, snapshot: NetworkSnapshot) -> VpnState:
        """Analyze network snapshot to determine if this VPN is active."""
        raise NotImplementedError

    def reconnect(self) -> bool:
        """Attempt to reconnect/rotate the VPN node. Return True if successful."""
        raise NotImplementedError
