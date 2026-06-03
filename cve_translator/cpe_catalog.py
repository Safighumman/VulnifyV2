"""The normalisation catalogue: informal product names to canonical CPEs.

This is the single most important piece of the whole tool. CVE matching fails
silently when a product name does not line up with the CPE identifiers used in
the NVD data: a vulnerability that genuinely affects your software simply will
not appear in the results, with no error message. So every CPE target below
was verified against the real 2024 and 2025 NVD feeds rather than guessed.

Each catalogue entry has:

    name     a clean canonical label shown in the output
    aliases  the informal spellings a user might actually type
    cpe      one or more "vendor:product" targets from the real CPE data
    category a rough grouping used only for the summary brief

A CPE target ending in "*" is a prefix match. This elegantly absorbs the
Windows release sprawl: Microsoft no longer ships a bare "windows_10" CPE, only
release-tagged products such as "windows_10_22h2", "windows_10_21h2" and so on.
A single "microsoft:windows_10*" target matches every release.

Several entries deliberately list more than one CPE because the real world is
messier than one product name to one identifier:

  * "VMware vSphere" is a product suite with no "vmware:vsphere" CPE. Its
    components live under "vmware:vcenter_server" and "vmware:esxi".
  * "Zoom" the classic client is now published as "zoom:workplace".
  * "nginx" moved under the "f5" vendor namespace after the F5 acquisition.
  * "MySQL" appears as both "oracle:mysql" and "oracle:mysql_server".

These cases are exactly why a hand-curated, verified catalogue beats naive
string matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Product:
    name: str
    aliases: List[str]
    cpe: List[str]
    category: str = "Software"

    def cpe_label(self) -> str:
        return ", ".join(self.cpe)


# The catalogue: 49 widely used software titles, each CPE target verified
# against the real NVD feed. Covers all 12 entries in the project sample asset
# list plus common SMB software and frequently exploited enterprise products.
CATALOG: List[Product] = [
    # Sample asset list (Section 10 of the brief)
    Product(
        "Microsoft 365 Apps",
        ["microsoft 365 apps for business", "microsoft 365 apps", "office 365",
         "microsoft 365", "m365 apps", "office365", "o365"],
        ["microsoft:365_apps"],
        "Productivity",
    ),
    Product(
        "Windows Server 2022",
        ["windows server 2022", "win server 2022", "windows server 2022 21h2",
         "windows srv 2022"],
        ["microsoft:windows_server_2022*"],
        "Operating system",
    ),
    Product(
        "Windows 10",
        ["windows 10 pro", "windows 10", "win10", "windows10",
         "windows 10 enterprise", "windows 10 home"],
        ["microsoft:windows_10*"],
        "Operating system",
    ),
    Product(
        "Adobe Acrobat Reader DC",
        ["adobe acrobat reader dc", "adobe acrobat reader", "adobe reader",
         "acrobat reader", "acrobat reader dc", "adobe acrobat"],
        ["adobe:acrobat_reader_dc", "adobe:acrobat_reader",
         "adobe:acrobat_dc", "adobe:acrobat"],
        "Document reader",
    ),
    Product(
        "Cisco IOS XE",
        ["cisco ios xe", "ios xe", "cisco ios-xe", "ios-xe"],
        ["cisco:ios_xe"],
        "Network firmware",
    ),
    Product(
        "VMware vSphere",
        ["vmware vsphere", "vsphere", "vcenter", "vcenter server", "esxi",
         "vmware esxi"],
        ["vmware:vcenter_server", "vmware:esxi", "vmware:cloud_foundation"],
        "Virtualisation",
    ),
    Product(
        "Google Chrome",
        ["google chrome", "chrome", "chrome browser"],
        ["google:chrome"],
        "Web browser",
    ),
    Product(
        "OpenSSL",
        ["openssl", "open ssl"],
        ["openssl:openssl"],
        "Cryptography library",
    ),
    Product(
        "Apache HTTP Server",
        ["apache http server", "apache httpd", "apache web server", "httpd",
         "apache2"],
        ["apache:http_server"],
        "Web server",
    ),
    Product(
        "Zoom",
        ["zoom", "zoom client", "zoom workplace", "zoom meetings",
         "zoom desktop"],
        ["zoom:workplace", "zoom:workplace_desktop", "zoom:rooms",
         "zoom:meetings"],
        "Video conferencing",
    ),
    Product(
        "WordPress",
        ["wordpress", "word press", "wordpress core"],
        ["wordpress:wordpress"],
        "Content management",
    ),
    Product(
        "Moodle",
        ["moodle", "moodle lms"],
        ["moodle:moodle"],
        "Learning management",
    ),
    # Common extras (broaden the SMB coverage)
    Product(
        "Windows 11",
        ["windows 11 pro", "windows 11", "win11", "windows11",
         "windows 11 enterprise"],
        ["microsoft:windows_11*"],
        "Operating system",
    ),
    Product(
        "Windows Server 2019",
        ["windows server 2019", "win server 2019"],
        ["microsoft:windows_server_2019"],
        "Operating system",
    ),
    Product(
        "Microsoft Exchange Server",
        ["microsoft exchange server", "microsoft exchange", "exchange server",
         "exchange"],
        ["microsoft:exchange_server"],
        "Mail server",
    ),
    Product(
        "Microsoft Edge",
        ["microsoft edge", "msedge", "edge browser"],
        ["microsoft:edge", "microsoft:edge_chromium"],
        "Web browser",
    ),
    Product(
        "Mozilla Firefox",
        ["mozilla firefox", "firefox", "firefox esr"],
        ["mozilla:firefox", "mozilla:firefox_esr"],
        "Web browser",
    ),
    Product(
        "Apache Log4j",
        ["apache log4j", "log4j", "log4j2", "log4shell"],
        ["apache:log4j"],
        "Logging library",
    ),
    Product(
        "nginx",
        ["nginx", "nginx web server", "nginx open source", "nginx plus"],
        ["f5:nginx_open_source", "f5:nginx_plus", "nginx:nginx"],
        "Web server",
    ),
    Product(
        "MySQL",
        ["mysql", "my sql", "mysql server", "mysql community server"],
        ["oracle:mysql", "oracle:mysql_server"],
        "Database",
    ),
    Product(
        "PostgreSQL",
        ["postgresql", "postgres", "postgre sql"],
        ["postgresql:postgresql"],
        "Database",
    ),
    Product(
        "PHP",
        ["php", "php runtime"],
        ["php:php"],
        "Runtime",
    ),
    Product(
        "Node.js",
        ["node.js", "nodejs", "node js", "node"],
        ["nodejs:node.js"],
        "Runtime",
    ),
    Product(
        "Fortinet FortiOS",
        ["fortinet fortios", "fortios", "fortigate", "forti os"],
        ["fortinet:fortios"],
        "Network firmware",
    ),
    Product(
        "7-Zip",
        ["7-zip", "7zip", "seven zip", "7 zip"],
        ["7-zip:7-zip"],
        "Utility",
    ),
    # Verified expansion: widely run, frequently exploited enterprise software.
    # Every CPE target below was confirmed present in the real 2024/2025 NVD feed.
    Product(
        "Microsoft Office",
        ["microsoft office", "ms office", "office 2019", "office 2021",
         "office ltsc", "word", "excel"],
        ["microsoft:office", "microsoft:word", "microsoft:excel"],
        "Productivity",
    ),
    Product(
        "Microsoft Outlook",
        ["microsoft outlook", "outlook"],
        ["microsoft:outlook"],
        "Email client",
    ),
    Product(
        "Microsoft SharePoint",
        ["microsoft sharepoint", "sharepoint", "sharepoint server"],
        ["microsoft:sharepoint_server", "microsoft:sharepoint_enterprise_server"],
        "Collaboration",
    ),
    Product(
        "Atlassian Confluence",
        ["atlassian confluence", "confluence", "confluence server",
         "confluence data center"],
        ["atlassian:confluence_server", "atlassian:confluence_data_center"],
        "Collaboration",
    ),
    Product(
        "Atlassian Jira",
        ["atlassian jira", "jira", "jira software", "jira server"],
        ["atlassian:jira_server", "atlassian:jira_data_center"],
        "Collaboration",
    ),
    Product(
        "Apache Tomcat",
        ["apache tomcat", "tomcat"],
        ["apache:tomcat"],
        "Web server",
    ),
    Product(
        "Apache Struts",
        ["apache struts", "struts", "struts2"],
        ["apache:struts"],
        "Web framework",
    ),
    Product(
        "Drupal",
        ["drupal", "drupal core"],
        ["drupal:drupal"],
        "Content management",
    ),
    Product(
        "Joomla",
        ["joomla", "joomla cms"],
        ["joomla:joomla*"],
        "Content management",
    ),
    Product(
        "Adobe ColdFusion",
        ["adobe coldfusion", "coldfusion"],
        ["adobe:coldfusion"],
        "Web application platform",
    ),
    Product(
        "GitLab",
        ["gitlab", "gitlab ce", "gitlab ee", "gitlab community edition"],
        ["gitlab:gitlab"],
        "DevOps platform",
    ),
    Product(
        "Jenkins",
        ["jenkins", "jenkins ci", "jenkins automation server"],
        ["jenkins:jenkins"],
        "CI/CD",
    ),
    Product(
        "Grafana",
        ["grafana", "grafana labs"],
        ["grafana:grafana"],
        "Monitoring",
    ),
    Product(
        "Elasticsearch",
        ["elasticsearch", "elastic search", "elastic stack", "kibana", "elk"],
        ["elastic:elasticsearch", "elastic:kibana"],
        "Search platform",
    ),
    Product(
        "Redis",
        ["redis", "redis server"],
        ["redis:redis"],
        "Database",
    ),
    Product(
        "MongoDB",
        ["mongodb", "mongo db", "mongo"],
        ["mongodb:mongodb"],
        "Database",
    ),
    Product(
        "Citrix NetScaler ADC",
        ["citrix netscaler", "netscaler", "citrix adc",
         "netscaler adc", "citrix gateway", "netscaler gateway", "citrixbleed"],
        ["citrix:netscaler_application_delivery_controller",
         "citrix:netscaler_gateway"],
        "Network security",
    ),
    Product(
        "Ivanti Connect Secure",
        ["ivanti connect secure", "ivanti", "connect secure", "pulse secure",
         "ivanti policy secure"],
        ["ivanti:connect_secure", "ivanti:policy_secure"],
        "Remote access",
    ),
    Product(
        "Palo Alto PAN-OS",
        ["palo alto", "pan-os", "panos", "globalprotect",
         "palo alto networks"],
        ["paloaltonetworks:pan-os", "paloaltonetworks:globalprotect"],
        "Network security",
    ),
    Product(
        "SonicWall SonicOS",
        ["sonicwall", "sonicos", "sonicwall firewall"],
        ["sonicwall:sonicos"],
        "Network security",
    ),
    Product(
        "Sophos Firewall",
        ["sophos firewall", "sophos xg", "sophos xg firewall"],
        ["sophos:firewall"],
        "Network security",
    ),
    Product(
        "OpenVPN",
        ["openvpn", "open vpn", "openvpn connect"],
        ["openvpn:openvpn", "openvpn:connect"],
        "Remote access",
    ),
    Product(
        "Progress MOVEit Transfer",
        ["moveit", "moveit transfer", "progress moveit", "moveit automation"],
        ["progress:moveit_transfer", "progress:moveit_automation"],
        "Managed file transfer",
    ),
    Product(
        "Veeam Backup & Replication",
        ["veeam", "veeam backup", "veeam backup and replication",
         "veeam backup & replication"],
        ["veeam:backup", "veeam:veeam_backup_&_replication"],
        "Backup",
    ),
]


def alias_index() -> List[tuple[str, Product]]:
    """Flatten the catalogue to (alias, product) pairs for fuzzy matching.

    The product's canonical name is included as a self-alias so an exact
    canonical input always matches with full confidence.
    """
    pairs: List[tuple[str, Product]] = []
    for product in CATALOG:
        seen = set()
        for alias in [product.name] + product.aliases:
            key = alias.strip().lower()
            if key and key not in seen:
                seen.add(key)
                pairs.append((key, product))
    return pairs


def all_cpe_targets() -> List[str]:
    """Every CPE target across the catalogue (used to scope the data subset)."""
    targets: List[str] = []
    for product in CATALOG:
        targets.extend(product.cpe)
    return sorted(set(targets))
