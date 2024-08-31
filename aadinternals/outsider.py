import logging
import re
import uuid
import xml.etree.ElementTree as ET
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional

import dns.resolver
import requests

from aadinternals.common import SUBSCOPE, DomainInfo, TenantInfo

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

ALLOWED_METHODS = Literal["normal", "login", "autologon", "rst2"]

PAYLOAD = r"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">{uri}</a:To>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Request>
                    <Domain>{domain}</Domain>
                </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>"""


def dns_query(resolver: dns.resolver.Resolver, domain: str, record_type: str, use_tcp: bool = False, ignore_error: bool = True) -> List[str]:
    """Perform a DNS query and return the results."""
    try:
        answers = resolver.resolve(domain, record_type, tcp=use_tcp)
        if record_type == "MX":
            return [re.sub(r"\.*$", "", answer.exchange.to_text()) for answer in answers]
        elif len(answers.response.answer) > 0:
            return [re.sub(r"\.*$", "", str(item)) for resp in answers.response.answer for item in resp]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        if not ignore_error:
            raise e
        return []


def domain_exists(resolver: dns.resolver.Resolver, domain: str, use_tcp: bool = False) -> bool:
    return bool(dns_query(resolver, domain, "A", use_tcp) or dns_query(resolver, domain, "AAAA", use_tcp))


def get_tenant_login_url(subscope: Optional[SUBSCOPE] = None) -> str:
    """Get the tenant login URL based on the subscope."""
    if subscope in ("DOD", "DODCON"):
        return "https://login.microsoftonline.us"
    return "https://login.microsoftonline.com"


def get_tenant_id(domain: str) -> Optional[str]:
    """Get the tenant ID for a domain."""
    try:
        response = requests.get(f"https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={domain}")
        response.raise_for_status()
        return response.json().get("tenantId")
    except requests.RequestException:
        return None


@lru_cache(maxsize=1000)
def get_credential_type(username: str, subscope: Optional[SUBSCOPE] = None, flowtoken: Optional[str] = None, originalrequest: Optional[str] = None) -> Dict[str, Any]:
    """Get credential type for a username."""
    url = f"{get_tenant_login_url(subscope)}/common/GetCredentialType"
    data = {
        "username": username,
        "isOtherIdpSupported": True,
        "checkPhones": True,
        "isRemoteNGCSupported": False,
        "isCookieBannerShown": False,
        "isFidoSupported": False,
        "originalRequest": originalrequest,
        "flowToken": flowtoken,
    }
    if originalrequest is not None:
        data["isAccessPassSupported"] = True
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {}


def has_cba(username: str, subscope: Optional[SUBSCOPE] = None) -> bool:
    """Check if a username has Certificate Based Authentication."""
    credential_type = get_credential_type(username, subscope=subscope)
    return credential_type.get("Credentials", {}).get("HasCertAuth", False)


def has_desktop_sso(domain: str, subscope: Optional[SUBSCOPE] = None) -> bool:
    """Check if a domain has Desktop Single Sign-On enabled."""
    credential_type = get_credential_type(f"nn@{domain}", subscope=subscope)
    return credential_type.get("EstsProperties", {}).get("DesktopSsoEnabled", False)


def has_cloud_mx(resolver: dns.resolver.Resolver, domain: str, subscope: Optional[SUBSCOPE] = None, use_tcp: bool = False) -> bool:
    """Check if a domain has cloud MX records."""
    mx_filter = ".protection.office365.us" if subscope in ("DOD", "DODCON") else ".mail.protection.outlook.com"
    return any(t.endswith(mx_filter) for t in dns_query(resolver, domain, "MX", use_tcp))


def has_cloud_spf(resolver: dns.resolver.Resolver, domain: str, subscope: Optional[SUBSCOPE] = None, use_tcp: bool = False) -> bool:
    """Check if a domain has cloud SPF records."""
    spf_filter = "include:spf.protection.office365.us" if subscope in ("DOD", "DODCON") else "include:spf.protection.outlook.com"
    return any(spf_filter in t for t in dns_query(resolver, domain, "TXT", use_tcp))


def has_cloud_dmarc(resolver: dns.resolver.Resolver, domain: str, use_tcp: bool = False) -> bool:
    """Check if a domain has cloud DMARC records."""
    return any('"v=DMARC1' in t for t in dns_query(resolver, domain, "TXT", use_tcp))


def has_cloud_dkim(resolver: dns.resolver.Resolver, domain: str, subscope: Optional[SUBSCOPE] = None, use_tcp: bool = False) -> bool:
    """Check if a domain has cloud DKIM records."""
    dkim_filter = r".*_domainkey\..*\.onmicrosoft\.us.*" if subscope in ("DOD", "DODCON") else r".*_domainkey\..*\.onmicrosoft\.com.*"
    for selector in ["selector1", "selector2"]:
        check_domain = f"{selector}._domainkey.{domain}"
        if any(re.match(dkim_filter, resp) for resp in dns_query(resolver, check_domain, "CNAME", use_tcp)):
            return True
    return False


def has_cloud_mtasts(domain: str, subscope: Optional[SUBSCOPE] = None) -> bool:
    """Check if a domain has MTA-STS configured."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    mx_filter = r"mx: .*\.mail\.protection\.office365\.us" if subscope == "DODCON" else r"mx: .*\.mail\.protection\.outlook\.com"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        content = response.text
        return "version: STSv1" in content and re.search(mx_filter, content)
    except requests.RequestException:
        return False


def get_branding_logo_url(domain: str, subscope: Optional[SUBSCOPE] = None) -> Optional[str]:
    """Get the branding logo URL for a domain."""
    credential_type = get_credential_type(f"nn@{domain}", subscope=subscope)
    # print(f"{credential_type = }")
    brands = credential_type.get("EstsProperties", {}).get("UserTenantBranding", [])
    if not brands:
        return None

    retvalue = []
    for brand in brands:
        q = {}
        for key in ["BannerLogo", "TileLogo", "TileDarkLogo", "Illustration", "UserIdLabel"]:
            if key in brand and brand[key]:
                q[key] = brand[key]
        if q:
            retvalue.append(q)
    return retvalue


@lru_cache(maxsize=1000)
def get_openid_configuration(domain: Optional[str] = None) -> Dict[str, Any]:
    """Get OpenID configuration for a domain."""
    try:
        response = requests.get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {}


def get_tenant_subscope(domain: Optional[str] = None, openid_config: Optional[Dict[str, Any]] = None) -> Optional[SUBSCOPE]:
    """Get tenant subscope from OpenID configuration."""
    if not openid_config:
        openid_config = get_openid_configuration(domain)
    return openid_config.get("tenant_region_sub_scope")


@lru_cache(maxsize=1000)
def get_user_realm_v2(username: str, subscope: Optional[SUBSCOPE] = None) -> Dict[str, Any]:
    """Get user realm information."""
    url = f"{get_tenant_login_url(subscope)}/GetUserRealm.srf?login={username}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {}


def get_mdi_instance(tenant: str) -> Optional[str]:
    """Get MDI instance for a tenant."""
    tenant = tenant.split(".")[0]
    for domain in [f"{tenant}.atp.azure.com", f"{tenant}-onmicrosoft-com.atp.azure.com"]:
        if domain_exists(dns.resolver.Resolver(), domain):
            return domain
    return None


def get_tenant_domains(domain: str, subscope: Optional[SUBSCOPE] = None) -> List[str]:
    """Get all domains for a tenant."""
    subscope = subscope or get_tenant_subscope(domain)
    uri = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
    if subscope == "DOD":
        uri = "https://autodiscover-s-dod.office365.us/autodiscover/autodiscover.svc"
    elif subscope == "DODCON":
        uri = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"
    body = PAYLOAD.format(uri=uri, domain=domain)
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
        "User-Agent": "AutodiscoverClient",
    }
    namespaces = {"s": "http://schemas.xmlsoap.org/soap/envelope/", "a": "http://www.w3.org/2005/08/addressing"}
    xpath_query = r"./s:Body/{http://schemas.microsoft.com/exchange/2010/Autodiscover}GetFederationInformationResponseMessage/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Response/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domains/{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain"

    try:
        response = requests.post(uri, headers=headers, data=body)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        domains = [domain_elt.text for domain_elt in root.findall(xpath_query, namespaces=namespaces) if domain_elt.text]
        if domain not in domains:
            domains.append(domain)
        return sorted(domains)
    except (requests.RequestException, ET.ParseError):
        return [domain]


def does_user_exist(username: str, method: ALLOWED_METHODS = "normal", subscope: Optional[SUBSCOPE] = None) -> Optional[bool]:
    """Check if a user exists using the specified method."""
    subscope = subscope or get_tenant_subscope(username.split("@")[-1])

    if method == "normal":
        cred_type = get_credential_type(username, subscope=subscope)
        if cred_type.get("ThrottleStatus") == 1:
            return None
        return cred_type.get("IfExistsResult") in [0, 6]

    elif method == "login":
        random_guid = uuid.uuid4()
        body = {
            "resource": str(random_guid),
            "client_id": str(random_guid),
            "grant_type": "password",
            "username": username,
            "password": "none",
            "scope": "openid",
        }
        try:
            response = requests.post(
                f"{get_tenant_login_url(subscope)}/common/oauth2/token",
                headers={"ContentType": "application/x-www-form-urlencoded"},
                data=body,
            )
            parsed_resp = response.json()
            error_description = parsed_resp.get("error_description", "")
            if "The user account {EUII Hidden} does not exist in the" in error_description:
                return False
            elif "Error validating credentials due to invalid username or password." in error_description:
                return True
        except requests.RequestException:
            pass
    elif method in ("autologon", "rst2"):
        raise NotImplementedError("Method Autologon and RST2 are not yet implemented")
    else:
        raise ValueError("What are you doing? %s is not a valid method." % method)
    return None


def get_relaying_parties(auth_url: str) -> List[str]:
    """Get relaying parties from the IDP URL."""
    idp_url = auth_url.rpartition("/")[0] + "/idpinitiatedsignon.aspx"
    try:
        response = requests.get(idp_url)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        options = root.findall(".//select[@id='idp_RelyingPartyDropDownList']/option")
        return [option.text for option in options if option.text]
    except (requests.RequestException, ET.ParseError):
        return []


def recon_as_outsider(
    domain_name: str, username: Optional[str] = None, single: bool = False, get_relaying_parties: bool = False, resolver: dns.resolver.Resolver = dns.resolver.Resolver(), use_tcp: bool = False
) -> TenantInfo:
    """Perform reconnaissance as an outsider."""
    tenant_info = TenantInfo()
    tenant_info.id = get_tenant_id(domain_name)

    if tenant_info.id is None:
        return tenant_info

    logger.info(f"Starting reconnaissance for domain: {domain_name}")

    openid_config = get_openid_configuration(domain_name)
    tenant_info.region = openid_config.get("tenant_region_scope")
    tenant_info.subscope = get_tenant_subscope(openid_config=openid_config)
    domains = get_tenant_domains(domain_name, subscope=tenant_info.subscope)
    logger.debug(f"Discovered domains: {domains}")
    tenant_info.domains_info = []

    for domain in domains:
        if not single or (single and domain.lower() == domain_name.lower()):
            domain_info = get_domain_info(domain, tenant_info.subscope, get_relaying_parties, resolver, use_tcp)
            tenant_info.domains_info.append(domain_info)

    update_tenant_info(tenant_info, username)
    logger.info("Reconnaissance completed")
    return tenant_info


def get_domain_info(domain: str, subscope: Optional[SUBSCOPE], get_relaying_parties: bool, resolver: dns.resolver.Resolver, use_tcp: bool) -> Dict[str, Any]:
    """Get information about a specific domain."""
    logger.debug(f"Getting info for domain: {domain}")
    exists = domain_exists(resolver, domain, use_tcp)
    domain_info = DomainInfo(
        name=domain,
        dns=exists,
        mx=False,
        spf=False,
        dmarc=False,
        dkim=False,
        mta_sts=False,
        type="",
        sts="",
    )
    if exists:
        domain_info.mx = has_cloud_mx(resolver, domain, subscope, use_tcp)
        domain_info.spf = has_cloud_spf(resolver, domain, subscope, use_tcp)
        domain_info.dmarc = has_cloud_dmarc(resolver, domain, use_tcp)
        domain_info.dkim = has_cloud_dkim(resolver, domain, subscope, use_tcp)
        domain_info.mta_sts = has_cloud_mtasts(domain, subscope)

    realm_info = get_user_realm_v2(f"nn@{domain}", subscope=subscope)
    domain_info.type = realm_info.get("NameSpaceType", "")
    auth_url = realm_info.get("AuthURL", "")
    domain_info.sts = auth_url.split("/")[2] if auth_url else ""
    domain_info.brand = realm_info.get("FederationBrandName", "")
    domain_info.branding_urls = get_branding_logo_url(domain, subscope=subscope)

    if get_relaying_parties and auth_url:
        domain_info.rps = get_relaying_parties(auth_url)
    return domain_info


def update_tenant_info(tenant_info: TenantInfo, username: Optional[str]) -> None:
    """Update tenant information with additional details."""
    for domain_info in tenant_info.domains_info:
        if tenant_info.name is None and re.match(r"^[^.]*\.onmicrosoft\.(com|us)$", domain_info.name.lower()):
            tenant_info.name = domain_info.name
        if tenant_info.sso is None:
            tenant_info.sso = has_desktop_sso(domain_info.name, subscope=tenant_info.subscope)
        if tenant_info.brand is None:
            tenant_info.brand = domain_info.brand
    if username:
        tenant_info.cba = has_cba(username, subscope=tenant_info.subscope)
    if tenant_info.name:
        tenant_info.mdi = get_mdi_instance(tenant_info.name)
        tenant_info.uses_cloud_sync = does_user_exist(f"ADToAADSyncServiceAccount@{tenant_info.name}")


def user_enumeration_as_outsider(username: str, method: ALLOWED_METHODS = "normal", external: bool = False, domain: Optional[str] = None) -> Dict[str, Any]:
    """Enumerate user existence as an outsider."""
    raise NotImplementedError("User enumeration as an outsider is not yet implemented")
    domain = domain or username.split("@")[-1]
    tenant_subscope = get_tenant_subscope(domain)
    if method == "normal" and external:
        if not domain:
            raise ValueError("Domain is required for external method")
        username = f'{username.replace("@", "_")}#EXT#@{domain}'
    exists = does_user_exist(username, method=method, subscope=tenant_subscope)
    return {"username": username, "exists": exists, "method": method, "external": external}
