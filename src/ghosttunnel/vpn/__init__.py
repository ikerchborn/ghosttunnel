from .generic import VpnAdapter
from .proton import ProtonVpnAdapter
from .wireguard import WireguardAdapter
from .openvpn import OpenVpnAdapter

def get_adapters() -> list[VpnAdapter]:
    return [
        ProtonVpnAdapter(),
        WireguardAdapter(),
        OpenVpnAdapter()
    ]
