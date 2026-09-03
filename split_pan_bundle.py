#!/usr/bin/env python3
"""
split_pan_bundle.py

Split PAN-OS device state bundles (device_state_cfg.tgz) or standalone
running-config XML files into small per-control-area fragments plus a
manifest, for AI-assisted management plane assessment.
"""
import argparse
import csv
import hashlib
import os
import re
import shutil
import sys
import tarfile
import xml.etree.ElementTree as ET
from datetime import datetime

# Full script is on the laptop. This GitHub copy must compile.
# See local split_pan_bundle.py for comments.

FRAGMENT_MAP = [
    ("MGT_deviceconfig-system", [".//deviceconfig/system"]),
    ("MGT_setting-management", [".//deviceconfig/setting/management"]),
    ("AUTH_mgt-config", [".//mgt-config"]),
    ("AUTH_authentication-profile", [
        ".//shared/authentication-profile[entry]",
        ".//vsys/entry/authentication-profile[entry]",
        ".//authentication-profile[entry]",
    ]),
    ("AUTH_certificate-profile", [
        ".//shared/certificate-profile[entry]",
        ".//certificate-profile[entry]",
    ]),
    ("AUTH_server-profiles", [
        ".//shared/server-profile[entry]",
        ".//server-profile[entry]",
    ]),
    ("AUTH_admin-role", [
        ".//shared/admin-role[entry]",
        ".//admin-role[entry]",
    ]),
    ("IMP_interface-mgmt-profiles",
     [".//network/profiles/interface-management-profile"]),
    ("IMP_interfaces", [".//network/interface"]),
    ("NSC_zones", [".//vsys/entry/zone[entry]", ".//zone[entry]"]),
    ("NSC_rulebase-security", [
        ".//vsys/entry/rulebase/security",
        ".//rulebase/security",
    ]),
    ("NSC_pre-rulebase-security", [".//pre-rulebase/security"]),
    ("NSC_post-rulebase-security", [".//post-rulebase/security"]),
    ("NSC_rulebase-nat", [
        ".//vsys/entry/rulebase/nat",
        ".//rulebase/nat",
        ".//pre-rulebase/nat",
        ".//post-rulebase/nat",
    ]),
    ("NSC_address-objects", [
        ".//vsys/entry/address[entry]",
        ".//shared/address[entry]",
        ".//address[entry]",
    ]),
    ("NSC_address-groups", [
        ".//vsys/entry/address-group[entry]",
        ".//shared/address-group[entry]",
        ".//address-group[entry]",
    ]),
    ("SVC_ssl-tls-service-profile", [
        ".//shared/ssl-tls-service-profile[entry]",
        ".//ssl-tls-service-profile[entry]",
    ]),
    ("SVC_snmp", [".//deviceconfig/system/snmp-setting", ".//snmp-setting"]),
    ("LOG_log-settings", [".//shared/log-settings", ".//log-settings"]),
    ("LOG_syslog-profiles", [
        ".//shared/log-settings/syslog[entry]",
        ".//syslog[entry]",
    ]),
    ("MGT_service-routes", [
        ".//deviceconfig/system/route",
        ".//deviceconfig/system/service",
    ]),
    ("SVC_certificates", [
        ".//shared/certificate[entry]",
        ".//certificate[entry]",
    ]),
    ("IMP_globalprotect", [".//vsys/entry/global-protect", ".//global-protect"]),
    ("MGT_high-availability", [".//deviceconfig/high-availability"]),
]

COUNT_MAP = [
    ("interfaces_ethernet",  [".//network/interface/ethernet/entry"]),
    ("interfaces_aggregate", [".//network/interface/aggregate-ethernet/entry"]),
    ("interfaces_loopback",  [".//network/interface/loopback/units/entry"]),
    ("interfaces_tunnel",    [".//network/interface/tunnel/units/entry"]),
    ("interfaces_vlan",      [".//network/interface/vlan/units/entry"]),
    ("mgmt_profiles", [".//network/profiles/interface-management-profile/entry"]),
    ("admin_users",          [".//mgt-config/users/entry"]),
    ("admin_roles",          [".//admin-role/entry"]),
    ("auth_profiles",        [".//authentication-profile/entry"]),
    ("zones",                [".//zone/entry"]),
    ("security_rules_local", [".//rulebase/security/rules/entry"]),
    ("security_rules_pre",   [".//pre-rulebase/security/rules/entry"]),
    ("security_rules_post",  [".//post-rulebase/security/rules/entry"]),
    ("nat_rules", [
        ".//rulebase/nat/rules/entry",
        ".//pre-rulebase/nat/rules/entry",
        ".//post-rulebase/nat/rules/entry",
    ]),
    ("permitted_ip_mgt",     [".//deviceconfig/system/permitted-ip/entry"]),
    ("ssl_tls_profiles",     [".//ssl-tls-service-profile/entry"]),
    ("certificates",         [".//certificate/entry"]),
    ("gp_gateways",          [".//global-protect-gateway/entry"]),
]

REDACT_ELEMENTS = {
    "phash", "password", "private-key", "public-key", "preshared-key",
    "bind-password", "secret", "api-key", "auth-password", "priv-password",
    "community", "shared-secret", "client-key", "master-key",
    "snmp-community-string", "authpwd", "privpwd",
}

FRAGMENTABLE_ROLES = {
    "local-config", "pushed-template", "pushed-device-group",
    "config-unclassified",
}

ROLE_PREFIX = {
    "local-config": "LOCAL",
    "pushed-template": "TEMPLATE",
    "pushed-device-group": "DEVGROUP",
    "config-unclassified": "UNCLASS",
}

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()

def count_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0

def safe_extract(tar, dest):
    dest_abs = os.path.realpath(dest)
    refused = []
    members = []
    for m in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, m.name))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            refused.append(m.name)
            continue
        if not (m.isfile() or m.isdir()):
            refused.append(m.name + " (non-regular)")
            continue
        members.append(m)
    kwargs = {"path": dest, "members": members}
    if sys.version_info >= (3, 12):
        kwargs["filter"] = "data"
    tar.extractall(**kwargs)
    return refused

def looks_like_xml(path):
    if path.lower().endswith(".xml"):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(512).lstrip()
        lt = chr(60)
        return head.startswith(lt + "?xml") or head.startswith(lt)
    except OSError:
        return False

def classify_pan_xml(root):
    tag = root.tag
    has_deviceconfig = root.find(".//deviceconfig/system") is not None
    has_mgt_config = root.find(".//mgt-config") is not None
    has_template = (tag == "template") or (root.find("./template") is not None)
    has_dg = (
        tag == "device-group"
        or root.find(".//device-group") is not None
        or root.find(".//pre-rulebase") is not None
        or root.find(".//post-rulebase") is not None
    )
    if has_template:
        return "pushed-template"
    if has_dg and not has_deviceconfig:
        return "pushed-device-group"
    if tag == "config" and (has_deviceconfig or has_mgt_config):
        return "local-config"
    if tag == "config":
        return "config-unclassified"
    return "other"

def redact_tree(root):
    count = 0
    for el in root.iter():
        tag = el.tag.split("}")[-1] if isinstance(el.tag, str) else ""
        if tag not in REDACT_ELEMENTS:
            continue
        el.text = "REDACTED"
        del el[:]
        count += 1
    return count

def indent_tree(elem, level=0):
    pad = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad + "  "
        for child in elem:
            indent_tree(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = pad
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = pad

def write_fragment(node, out_path):
    import copy
    clone = copy.deepcopy(node)
    indent_tree(clone)
    xml_bytes = ET.tostring(clone, encoding="utf-8")
    with open(out_path, "wb") as fh:
        fh.write((chr(60) + '?xml version="1.0" encoding="utf-8"?>\n').encode("utf-8"))
        fh.write(xml_bytes)
        fh.write(b"\n")

def gather_inputs(input_path):
    if os.path.isdir(input_path):
        out = []
        for name in sorted(os.listdir(input_path)):
            full = os.path.join(input_path, name)
            if not os.path.isfile(full):
                continue
            low = name.lower()
            if low.endswith((".tgz", ".tar.gz", ".tar", ".gz", ".xml")):
                out.append(full)
        return out
    return [input_path]

def role_fragment_prefix(role, source_name, role_total, role_index):
    prefix = ROLE_PREFIX.get(role, "UNCLASS")
    if role_total > 1:
        stem = os.path.splitext(os.path.basename(source_name))[0]
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "file"
        return "%s_%02d_%s" % (prefix, role_index, stem)
    return prefix

def reset_device_output(dev_out, extract_dir, frag_dir):
    for path in (extract_dir, frag_dir):
        if os.path.isdir(path):
            shutil.rmtree(path)
    for name in ("MANIFEST.txt", "MANIFEST.csv.txt"):
        manifest_path = os.path.join(dev_out, name)
        if os.path.isfile(manifest_path):
            os.remove(manifest_path)
    os.makedirs(extract_dir)
    os.makedirs(frag_dir)

def process_bundle(item, output_root, do_redact):
    device_name = os.path.basename(item)
    for ext in (".tar.gz", ".tgz", ".tar", ".gz", ".xml"):
        if device_name.lower().endswith(ext):
            device_name = device_name[: -len(ext)]
            break
    dev_out = os.path.join(output_root, device_name)
    extract_dir = os.path.join(dev_out, "_extracted")
    frag_dir = os.path.join(dev_out, "fragments")
    reset_device_output(dev_out, extract_dir, frag_dir)
    print("=== %s -> %s" % (os.path.basename(item), dev_out))
    manifest = []
    if item.lower().endswith(".xml"):
        shutil.copy2(item, extract_dir)
    else:
        try:
            with tarfile.open(item, "r:*") as tar:
                refused = safe_extract(tar, extract_dir)
            for r in refused:
                print("  WARNING refused unsafe archive member: %s" % r)
        except tarfile.TarError as exc:
            print("  ERROR: cannot read archive (%s); skipping" % exc)
            return
        for dirpath, _dirnames, filenames in list(os.walk(extract_dir)):
            for fn in filenames:
                if fn.lower().endswith((".tgz", ".tar.gz", ".tar", ".gz")):
                    nested_path = os.path.join(dirpath, fn)
                    nested = os.path.join(
                        extract_dir, "nested_" + os.path.splitext(fn)[0])
                    os.makedirs(nested, exist_ok=True)
                    try:
                        with tarfile.open(nested_path, "r:*") as t2:
                            refused2 = safe_extract(t2, nested)
                        for r in refused2:
                            print("  WARNING refused unsafe nested member (%s): %s" % (fn, r))
                    except tarfile.TarError as exc:
                        print("  WARNING nested file is not a tar (%s): %s; left packed" % (fn, exc))
    source_xmls = []
    for dirpath, _dirnames, filenames in os.walk(extract_dir):
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, extract_dir)
            role, root_el = "non-xml", ""
            if looks_like_xml(full):
                try:
                    tree = ET.parse(full)
                    root = tree.getroot()
                    root_el = root.tag
                    role = classify_pan_xml(root)
                    if role in FRAGMENTABLE_ROLES:
                        source_xmls.append(
                            {"path": full, "name": fn, "root": root, "role": role})
                except ET.ParseError:
                    role = "xml-parse-failed"
            manifest.append({
                "Kind": "source-file", "Name": rel, "Role": role,
                "RootElement": root_el, "Lines": count_lines(full),
                "SHA256": sha256_file(full), "Detail": "",
            })
    if not any(s["role"] == "local-config" for s in source_xmls):
        print("  WARNING: no local-config identified. Check manifest before proceeding.")
    role_totals = {}
    role_index = {}
    for src in source_xmls:
        role_totals[src["role"]] = role_totals.get(src["role"], 0) + 1
    for src in source_xmls:
        role_index[src["role"]] = role_index.get(src["role"], 0) + 1
        prefix = role_fragment_prefix(
            src["role"], src["name"],
            role_totals[src["role"]], role_index[src["role"]])
        redacted = redact_tree(src["root"]) if do_redact else 0
        for frag_name, xpaths in FRAGMENT_MAP:
            found = False
            for xp in xpaths:
                nodes = src["root"].findall(xp)
                if not nodes:
                    continue
                found = True
                for i, node in enumerate(nodes):
                    suffix = "_%d" % i if len(nodes) > 1 else ""
                    out_name = "%s_%s%s.xml.txt" % (prefix, frag_name, suffix)
                    out_path = os.path.join(frag_dir, out_name)
                    write_fragment(node, out_path)
                    manifest.append({
                        "Kind": "fragment",
                        "Name": os.path.join("fragments", out_name),
                        "Role": src["role"],
                        "RootElement": node.tag,
                        "Lines": count_lines(out_path),
                        "SHA256": sha256_file(out_path),
                        "Detail": "xpath=%s; from=%s" % (xp, src["name"]),
                    })
                break
            if not found:
                manifest.append({
                    "Kind": "fragment",
                    "Name": "%s_%s" % (prefix, frag_name),
                    "Role": src["role"], "RootElement": "",
                    "Lines": 0, "SHA256": "",
                    "Detail": "NOT-PRESENT in this source (all xpaths empty)",
                })
        for count_name, xpaths in COUNT_MAP:
            n = sum(len(src["root"].findall(xp)) for xp in xpaths)
            manifest.append({
                "Kind": "count", "Name": "%s_%s" % (prefix, count_name),
                "Role": src["role"], "RootElement": "", "Lines": n,
                "SHA256": "", "Detail": " | ".join(xpaths),
            })
        if do_redact:
            manifest.append({
                "Kind": "redaction",
                "Name": "%s_redacted_values" % prefix,
                "Role": src["role"], "RootElement": "", "Lines": redacted,
                "SHA256": "",
                "Detail": "secret-bearing element values masked before fragment write",
            })
    csv_path = os.path.join(dev_out, "MANIFEST.csv.txt")
    txt_path = os.path.join(dev_out, "MANIFEST.txt")
    cols = ["Kind", "Name", "Role", "RootElement", "Lines", "SHA256", "Detail"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(manifest)
    lines = []
    lines.append("PAN-OS bundle split manifest")
    lines.append("Device bundle : %s" % os.path.basename(item))
    lines.append("Source SHA256 : %s" % sha256_file(item))
    lines.append("Generated     : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Redaction     : %s" % ("ON" if do_redact else "OFF - do not upload unredacted fragments"))
    lines.append("")
    lines.append("--- SOURCE FILES (role determined by content, not filename) ---")
    for r in manifest:
        if r["Kind"] == "source-file":
            lines.append("%-22s %7d lines  %s" % (r["Role"], r["Lines"], r["Name"]))
    lines.append("")
    lines.append("--- FRAGMENTS ---")
    for r in manifest:
        if r["Kind"] == "fragment":
            if r["Lines"] > 0:
                lines.append("%-55s %6d lines" % (r["Name"], r["Lines"]))
            else:
                lines.append("%-55s NOT-PRESENT" % r["Name"])
    lines.append("")
    lines.append("--- GROUND-TRUTH COUNTS (AI extraction must reconcile to these) ---")
    for r in manifest:
        if r["Kind"] == "count":
            lines.append("%-45s %d" % (r["Name"], r["Lines"]))
    for r in manifest:
        if r["Kind"] == "redaction":
            lines.append("%-45s %d" % (r["Name"], r["Lines"]))
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    written = sum(1 for r in manifest if r["Kind"] == "fragment" and r["Lines"] > 0)
    missing = sum(1 for r in manifest if r["Kind"] == "fragment" and r["Lines"] == 0)
    print("  fragments: %d written, %d not present; manifest at %s" % (written, missing, txt_path))

def main():
    ap = argparse.ArgumentParser(
        description="Split PAN-OS device state bundles into per-control-area fragments plus a manifest, for AI-assisted assessment.")
    ap.add_argument("-i", "--input", required=True, help="A .tgz/.tar.gz/.xml file, or a folder of them.")
    ap.add_argument("-o", "--output", required=True, help="Folder to write per-device output into.")
    ap.add_argument("--redact", action="store_true", help="Mask secrets in fragments (recommended before any AI upload).")
    args = ap.parse_args()
    inputs = gather_inputs(args.input)
    if not inputs:
        sys.exit("No .tgz/.tar.gz/.xml inputs found at %s" % args.input)
    os.makedirs(args.output, exist_ok=True)
    for item in inputs:
        process_bundle(item, args.output, args.redact)
    print("\nDone. Review each MANIFEST.txt before uploading anything.")
    print("Reminder: only redacted fragments and manifests go to USAI, never the raw bundle.")
    if not args.redact:
        print("WARNING: --redact was NOT used. Fragments may contain secrets.")

if __name__ == "__main__":
    main()
