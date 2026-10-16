"""Unit tests for deterministic tool importers (Nmap, Burp Suite)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from penmunshi.importers import detect_format, import_tool_output
from penmunshi.importers.burp import parse_burp_xml
from penmunshi.importers.common import clean_html_text, slugify
from penmunshi.importers.nmap import parse_nmap_xml

FICTIONAL_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p 21,80 192.168.1.50" start="1697300000" version="7.94">
  <host starttime="1697300001" endtime="1697300010">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames>
      <hostname name="fileserver.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4" extrainfo="Anonymous enabled"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;drwxr-xr-x   2 0        0            4096 Oct 15 10:00 pub"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
  <host starttime="1697300011" endtime="1697300015">
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

REQ_RAW = b"GET /search?q=test HTTP/1.1\r\nHost: portal.corp.test\r\n\r\n"
RESP_RAW = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Search: test</body></html>"

FICTIONAL_BURP_XML = f"""<?xml version="1.0"?>
<issues burpVersion="2026.1" exportTime="Mon Oct 15 12:00:00 UTC 2026">
  <issue>
    <serialNumber>987654321</serialNumber>
    <type>1048832</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="10.10.10.25">https://portal.corp.test</host>
    <path>/search</path>
    <location>/search [q]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;Reflected cross-site scripting occurs when user input is included in response.&lt;/p&gt;</issueBackground>
    <remediationBackground>&lt;p&gt;Context-dependent encode output before rendering.&lt;/p&gt;</remediationBackground>
    <issueDetail>The value of parameter &lt;b&gt;q&lt;/b&gt; was reflected without HTML escaping: &lt;code&gt;&amp;lt;script&amp;gt;&lt;/code&gt;</issueDetail>
    <requestresponse>
      <request base64="true">{base64.b64encode(REQ_RAW).decode('ascii')}</request>
      <response base64="true">{base64.b64encode(RESP_RAW).decode('ascii')}</response>
    </requestresponse>
  </issue>
</issues>
"""


def test_slugify_and_clean_html():
    assert slugify("Cross-site Scripting (Reflected)! in /search?q=1") == "cross-site-scripting-reflected-in-searchq1"
    assert clean_html_text("<p>Hello &amp; <b>world</b>!<br>New line</p>") == "Hello & world!\nNew line"


def test_parse_nmap_xml():
    findings = parse_nmap_xml(FICTIONAL_NMAP_XML)
    # Port 21 with ftp-anon script + Port 80 without script = 2 findings
    assert len(findings) == 2

    ftp_f = findings[0]
    assert "ftp-anon" in ftp_f.slug
    assert ftp_f.asset == "192.168.1.50:21"
    assert "vsftpd 2.3.4" in ftp_f.notes
    assert "Anonymous FTP login allowed" in ftp_f.notes
    assert "OUTPUT:\nAnonymous FTP login allowed" in ftp_f.tool_output
    assert ftp_f.confidence == "likely"

    http_f = findings[1]
    assert "http" in http_f.slug
    assert http_f.asset == "192.168.1.50:80"
    assert "Apache httpd 2.4.41" in ftp_f.notes or "Apache httpd 2.4.41" in http_f.notes


def test_parse_burp_xml():
    findings = parse_burp_xml(FICTIONAL_BURP_XML)
    assert len(findings) == 1

    xss = findings[0]
    assert "cross-site-scripting-reflected" in xss.slug
    assert xss.asset == "https://portal.corp.test/search"
    assert xss.severity == "High"
    assert xss.confidence == "confirmed"
    assert "The value of parameter q was reflected without HTML escaping" in xss.notes
    assert "=== REQUEST ===" in xss.tool_output
    assert "GET /search?q=test HTTP/1.1" in xss.tool_output
    assert "=== RESPONSE ===" in xss.tool_output
    assert "HTTP/1.1 200 OK" in xss.tool_output


def test_import_tool_output_end_to_end(tmp_path: Path):
    nmap_file = tmp_path / "nmap.xml"
    nmap_file.write_text(FICTIONAL_NMAP_XML, encoding="utf-8")

    burp_file = tmp_path / "burp.xml"
    burp_file.write_text(FICTIONAL_BURP_XML, encoding="utf-8")

    assert detect_format(nmap_file) == "nmap"
    assert detect_format(burp_file) == "burp"

    # Test auto import nmap
    nmap_out = tmp_path / "findings_nmap"
    dirs = import_tool_output(nmap_file, nmap_out)
    assert len(dirs) == 2
    assert (dirs[0] / "notes.md").is_file()
    assert (dirs[0] / "tool_output.txt").is_file()
    assert (dirs[0] / "finding.yml").is_file()

    # Test auto import burp
    burp_out = tmp_path / "findings_burp"
    b_dirs = import_tool_output(burp_file, burp_out)
    assert len(b_dirs) == 1
    assert (b_dirs[0] / "notes.md").is_file()
    assert (b_dirs[0] / "tool_output.txt").is_file()
    assert (b_dirs[0] / "finding.yml").is_file()
    assert "severity: High" in (b_dirs[0] / "finding.yml").read_text(encoding="utf-8")


def test_detect_format_unknown(tmp_path: Path):
    dummy = tmp_path / "other.txt"
    dummy.write_text("random file content", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not automatically detect scanner format"):
        detect_format(dummy)
