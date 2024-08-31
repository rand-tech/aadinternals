"""Pythonic AAADInternals recon"""

import argparse
import json
import logging
import os

import dns.resolver
import requests

from aadinternals.common import TenantInfo
from aadinternals.outsider import recon_as_outsider, user_enumeration_as_outsider

logger = logging.getLogger(__name__)


def save_brand_image(data: TenantInfo, output_dir: str) -> None:
    """Save the branding image to a file."""

    def dl(branding_url: str) -> bytes:
        response = requests.get(branding_url, timeout=5, headers={"User-Agent": "AutodiscoverClient"})
        response.raise_for_status()
        return response.content

    os.makedirs(output_dir, exist_ok=True)
    for domain_info in data.domains_info:
        if not domain_info.branding_urls:
            continue
        # branding urls is a list of dictionaries with keys: BannerLogo, TileLogo, TileDarkLogo, Illustration, UserIdLabel
        for idx, branding in enumerate(domain_info.branding_urls):
            for key, url in branding.items():
                if url and "http" in url:
                    with open(os.path.join(output_dir, f"{domain_info.name}_{idx}_{key}.png"), "wb") as f:
                        f.write(dl(url))


def pretty_print_table(data: TenantInfo) -> str:
    """Generate a pretty-printed table of tenant information."""
    tenant_info = data.to_dict()
    body = f"""
Tenant brand:                             {data.brand}
Tenant name:                              {data.name}
Tenant region:                            {data.region}
Tenant id:                                {data.id}
DesktopSSO enabled:                       {data.sso}
Uses Azure AD Connect cloud sync:         {data.uses_cloud_sync}
Certificate-based authentication (CBA):   {data.cba}
MDI instance:                             {data.mdi}
Verified domains:                         {len(data.domains_info)}

"""
    domains_info = tenant_info.get("domains_info", [])
    if not domains_info:
        return body
    headers = list(domains_info[0].keys())
    headers.remove("branding_urls")
    column_widths = {h: max(len(h), max(len(str(row[h])) for row in domains_info)) for h in headers}
    row_format = "\t".join(f"{{:<{w}}}" for w in column_widths.values())
    tsv = row_format.format(*headers) + "\n"
    tsv += row_format.format(*["-" * w for w in column_widths.values()]) + "\n"
    for row in sorted(domains_info, key=lambda x: x.get("name", "").lower()):
        tsv += row_format.format(*(str(row[h]) for h in headers)) + "\n"
    output_str = body + tsv
    return output_str


def pretty_print(data: TenantInfo, mode: str) -> str:
    """Pretty print tenant information in the specified format."""
    if mode == "json":
        return json.dumps(data.to_dict(), indent=2, ensure_ascii=False)
    elif mode == "pretty":
        return pretty_print_table(data)
    else:
        raise ValueError("Invalid output format. Please use 'json' or 'pretty'.")


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__, prog="aadinternals")
    parser.add_argument("--dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS requests", default=False)
    parser.add_argument("--dns", action="append", help="Use this specific DNS (can be used multiple times)", default=[])
    parser.add_argument("-v", "--verbose", action="store_true", default=False)

    subparsers = parser.add_subparsers(help="sub-commands", dest="subcmd")
    parser_recon = subparsers.add_parser("recon", help="ReconAsOutsider")
    parser_recon.add_argument("target", type=str, help="targeted domain or username")
    parser_recon.add_argument("-s", "--single", action="store_true", help="only perform advanced checks for the targeted domain", default=False)
    parser_recon.add_argument("-r", "--relayingparties", action="store_true", help="retrieve relaying parties of STSs", default=False)
    parser_recon.add_argument("-t", "--type", choices=["json", "pretty"], default="pretty", help="output format")
    parser_recon.add_argument("-i", "--save-images", type=str, help="Save branding images to a directory")

    parser_enum = subparsers.add_parser("user_enum", help="UserEnumerationAsOutsider")
    parser_enum.add_argument("username", help="user to test")
    parser_enum.add_argument("-m", "--method", choices=["normal", "login", "autologon", "rst2"], help="enumeration method", default="normal")
    parser_enum.add_argument("-e", "--external", action="store_true")
    parser_enum.add_argument("-d", "--domain", type=str, default=None)
    return parser


def main():
    """Main function to run the script."""
    parser = parse_arguments()
    args = parser.parse_args()

    resolver = dns.resolver.Resolver()
    if args.dns:
        resolver.nameservers = args.dns
    if args.dns_tcp:
        resolver.use_tcp = True

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.subcmd == "recon":
        domain, username = (args.target, None)
        if args.target.count("@") == 1:
            username, domain = args.target.split("@")
        if args.target.count("@") > 1:
            raise ValueError("Invalid target. Please provide a single domain (e.g. 'example.com') or username (e.g. 'admin@example.com')")
        result = recon_as_outsider(domain_name=domain, username=username, single=args.single, get_relaying_parties=args.relayingparties, resolver=resolver, use_tcp=args.dns_tcp)
        print(pretty_print(result, args.type))
        if args.save_images:
            save_brand_image(result, args.save_images)
    elif args.subcmd == "user_enum":
        result = user_enumeration_as_outsider(username=args.username, method=args.method, external=args.external, domain=args.domain)
        print(json.dumps(result, indent=2))
    else:
        print(parser.format_usage())


if __name__ == "__main__":
    main()
