from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from cai.sdk.agents import function_tool  # decorator used across CAI tools


def _safe_text(elem: Optional[ET.Element]) -> str:
    return "" if elem is None or elem.text is None else elem.text.strip()


def _tags_to_dict(host_properties_elem: Optional[ET.Element]) -> Dict[str, str]:
    props: Dict[str, str] = {}
    if host_properties_elem is None:
        return props
    for tag in host_properties_elem.findall("tag"):
        name = tag.get("name") or ""
        if name:
            props[name] = _safe_text(tag)
    return props


def _split_csv(text: str) -> List[str]:
    if not text:
        return []
    return [x.strip() for x in text.replace(";", ",").split(",") if x.strip()]


@function_tool
def parse_nessus_report(file_path: str) -> str:
    """
    Parse a Nessus XML report and return a normalized JSON string.

    Output JSON schema (simplified):
    {
      "report_name": str,
      "hosts": [
        {
          "name": str,
          "properties": { "host-ip": "...", ... },
          "findings": [
            {
              "plugin_id": "19506",
              "plugin_name": "...",
              "severity": 0..4,
              "risk_factor": "None|Low|Medium|High|Critical",
              "cvss_base_score": float|None,
              "cvss3_base_score": float|None,
              "cves": ["CVE-..."],
              "port": "443",
              "protocol": "tcp",
              "svc_name": "https",
              "description": "...",
              "solution": "...",
              "see_also": ["..."],
              "plugin_output": "trimmed..."
            }
          ]
        }
      ]
    }
    """
    tree = ET.parse(file_path)
    root = tree.getroot()

    report_elem = root.find("Report")
    report_name = report_elem.get("name") if report_elem is not None else "NessusReport"

    hosts_json: List[Dict[str, Any]] = []
    if report_elem is not None:
        for host in report_elem.findall("ReportHost"):
            host_name = host.get("name") or ""
            host_props = _tags_to_dict(host.find("HostProperties"))

            findings: List[Dict[str, Any]] = []
            for item in host.findall("ReportItem"):
                plugin_id = item.get("pluginID") or ""
                severity = int(item.get("severity") or "0")
                port = item.get("port") or "0"
                protocol = item.get("protocol") or ""
                svc_name = item.get("svc_name") or ""

                # common fields
                plugin_name = item.get("pluginName") or _safe_text(item.find("plugin_name"))
                risk_factor = _safe_text(item.find("risk_factor"))
                cvss_base = _safe_text(item.find("cvss_base_score"))
                cvss3_base = _safe_text(item.find("cvss3_base_score"))
                cve_text = _safe_text(item.find("cve"))
                description = _safe_text(item.find("description"))
                solution = _safe_text(item.find("solution"))
                see_also_raw = _safe_text(item.find("see_also"))
                plugin_output = _safe_text(item.find("plugin_output"))

                # normalize
                def _to_float(s: str) -> Optional[float]:
                    try:
                        return float(s)
                    except Exception:
                        return None

                finding = {
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "severity": severity,
                    "risk_factor": risk_factor,
                    "cvss_base_score": _to_float(cvss_base),
                    "cvss3_base_score": _to_float(cvss3_base),
                    "cves": _split_csv(cve_text),
                    "port": str(port),
                    "protocol": protocol,
                    "svc_name": svc_name,
                    "description": description,
                    "solution": solution,
                    "see_also": _split_csv(see_also_raw),
                    # tránh context quá dài
                    "plugin_output": plugin_output[:2000] if plugin_output else "",
                }
                findings.append(finding)

            hosts_json.append(
                {
                    "name": host_name,
                    "properties": host_props,
                    "findings": findings,
                }
            )

    result = {
        "report_name": report_name,
        "hosts": hosts_json,
    }
    return json.dumps(result, ensure_ascii=False)


def compile_nessus_report_with_verification_impl(
    original_report_path: str,
    decisions_json: str,
    output_path: str = ""
) -> str:
    """
    Inject CAI verification results into original Nessus XML and return the new XML (also writes to file if output_path).
    """
    decisions = json.loads(decisions_json or "{}")
    entries = decisions.get("decisions", [])
    decisions_index: Dict[str, Dict[str, Any]] = {}

    def key(host: str, plugin_id: str, port: str, protocol: str) -> str:
        return f"{host}|{plugin_id}|{port}|{(protocol or '').lower()}"

    for d in entries:
        decisions_index[key(d.get("host",""), d.get("plugin_id",""), str(d.get("port","0")), d.get("protocol",""))] = d

    NS = "https://aliasrobotics.com/"
    ET.register_namespace("cai", NS)

    tree = ET.parse(original_report_path)
    root = tree.getroot()

    report_elem = root.find("Report")
    if report_elem is not None:
        for host in report_elem.findall("ReportHost"):
            host_name = host.get("name") or ""
            for item in host.findall("ReportItem"):
                plugin_id = item.get("pluginID") or ""
                port = str(item.get("port") or "0")
                protocol = (item.get("protocol") or "").lower()

                d = decisions_index.get(key(host_name, plugin_id, port, protocol))
                if not d:
                    continue

                ver = ET.SubElement(item, f"{{{NS}}}verification")
                ver.set("status", d.get("status", "uncertain"))
                ver.set("confidence", str(d.get("confidence", 0.0)))
                ver.set("score", str(d.get("score", 0)))

                ev = ET.SubElement(ver, f"{{{NS}}}evidence")
                ev.text = d.get("rationale", "")

                tests = d.get("recommended_tests") or []
                if tests:
                    tests_el = ET.SubElement(ver, f"{{{NS}}}recommended_tests")
                    for t in tests:
                        t_el = ET.SubElement(tests_el, f"{{{NS}}}test")
                        t_el.text = str(t)

    new_xml = ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(new_xml)
    return new_xml


# Optional: giữ lại bản tool để LLM có thể gọi nếu sau này bật vào tool list
@function_tool
def compile_nessus_report_with_verification(
    original_report_path: str,
    decisions_json: str,
    output_path: str = ""
) -> str:
    return compile_nessus_report_with_verification_impl(
        original_report_path=original_report_path,
        decisions_json=decisions_json,
        output_path=output_path,
    )