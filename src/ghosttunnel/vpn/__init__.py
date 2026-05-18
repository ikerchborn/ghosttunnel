from .generic import VpnAdapter
from .proton import ProtonVpnAdapter
from .wireguard import WireguardAdapter
from .openvpn import OpenVpnAdapter
from .custom import CustomVpnAdapter
from ghosttunnel.core.config import Settings

def get_adapters(settings: Settings) -> list[VpnAdapter]:
    return [
        ProtonVpnAdapter(),
        WireguardAdapter(),
        OpenVpnAdapter(),
        CustomVpnAdapter(settings)
    ]
