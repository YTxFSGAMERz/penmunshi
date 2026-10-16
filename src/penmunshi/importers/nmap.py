"""Deterministic Nmap XML parser. Converts open services and script results to finding folders."""

from __future__ import annotations

from pathlib import Path

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # fallback

from .common import ImportedFinding, slugify


def parse_nmap_xml(xml_content: str | bytes) -> list[ImportedFinding]:
    """Parse Nmap XML output into a list of ImportedFinding objects."""
    findings: list[ImportedFinding] = []
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    root = ET.fromstring(xml_content)
    if root.tag != "nmaprun":
        raise ValueError("Not a valid Nmap XML output (missing <nmaprun> root tag)")

    for host in root.findall("host"):
        # Check host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Get IP address
        ip = "unknown"
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", ip)
                break

        # Get hostnames
        hostnames: list[str] = []
        for hn in host.findall("hostnames/hostname"):
            name = hn.get("name")
            if name:
                hostnames.append(name)
        host_label = hostnames[0] if hostnames else ip

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            protocol = port.get("protocol", "tcp")
            portid = port.get("portid", "")
            asset = f"{ip}:{portid}"

            service_el = port.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""

            service_banner = " ".join(part for part in [service_name, product, version, extrainfo] if part).strip()

            scripts = port.findall("script")
            if scripts:
                for script in scripts:
                    script_id = script.get("id", "script")
                    output = script.get("output", "").strip()

                    title = f"Nmap script {script_id} on {asset} ({service_name})"
                    slug = slugify(f"{ip}-{portid}-{script_id}")

                    notes = f"""# {title}

- **Asset**: `{asset}` ({host_label})
- **Service**: `{service_banner}`
- **Protocol**: `{protocol.upper()}/{portid}`
- **Script ID**: `{script_id}`

## Observations
Nmap NSE script `{script_id}` reported the following output:
```
{output}
```
"""
                    tool_output = f"""HOST: {ip} ({host_label})
PORT: {portid}/{protocol}
SERVICE: {service_banner}
NSE_SCRIPT: {script_id}
OUTPUT:
{output}
"""
                    findings.append(
                        ImportedFinding(
                            slug=slug,
                            title=title,
                            asset=asset,
                            notes=notes,
                            tool_output=tool_output,
                            severity="Medium" if "vuln" in script_id.lower() else "Low",
                            confidence="likely",
                        )
                    )
            else:
                # Open port without specific scripts
                title = f"Exposed {service_name} service on {asset}"
                slug = slugify(f"{ip}-{portid}-{service_name}")

                notes = f"""# {title}

- **Asset**: `{asset}` ({host_label})
- **Service**: `{service_banner}`
- **Protocol**: `{protocol.upper()}/{portid}`

## Observations
Port `{portid}/{protocol}` is open on `{asset}` running `{service_banner}`.
"""
                tool_output = f"""HOST: {ip} ({host_label})
PORT: {portid}/{protocol}
SERVICE: {service_name}
PRODUCT: {product}
VERSION: {version}
EXTRAINFO: {extrainfo}
"""
                findings.append(
                    ImportedFinding(
                        slug=slug,
                        title=title,
                        asset=asset,
                        notes=notes,
                        tool_output=tool_output,
                        severity="Low",
                        confidence="confirmed",
                    )
                )

    return findings


def import_nmap(file_path: Path | str, out_dir: Path | str) -> list[Path]:
    """Parse Nmap XML file and write findings to output directory."""
    path = Path(file_path)
    xml_data = path.read_text(encoding="utf-8")
    findings = parse_nmap_xml(xml_data)
    from .common import write_imported_findings

    return write_imported_findings(findings, Path(out_dir))
