from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Dict, List, Literal, Optional

SUBSCOPE = Literal["DOD", "DODCON"]


@dataclass
class DomainInfo:
    name: str  # Domain name
    dns: bool  # does the DNS record exists?
    mx: bool  # does the MX point to Office 365?
    spf: bool  # does the SPF contain Exchange Online?
    type: Annotated[str, "NameSpaceType"]  # Federated or Managed
    dmarc: bool  # is the DMARC record configured?
    dkim: bool  # is the DKIM record configured?
    mta_sts: Annotated[bool, "MTA-STS"]  # is MTA-STS configured?
    sts: Annotated[str, "AuthURL"]  # The FQDN of the federated IdP's (Identity Provider) STS (Security Token Service) server
    rps: Optional[List[str]] = None  # Relaying parties of STS (AD FS). Requires -GetRelayingParties switch.
    brand: Optional[str] = None
    branding_urls: Optional[List[dict]] = None


@dataclass
class TenantInfo:
    id: Optional[str] = None
    name: Optional[str] = None
    brand: Optional[str] = None
    region: Optional[str] = None
    subscope: Optional[SUBSCOPE] = None
    sso: Optional[bool] = None
    cba: Optional[bool] = None
    mdi: Optional[str] = None
    uses_cloud_sync: bool = False
    domains_info: List[DomainInfo] = field(default_factory=list)

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}
