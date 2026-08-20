#!/usr/bin/env python3
"""
split_pan_bundle.py

Split PAN-OS device state bundles (device_state_cfg.tgz) or standalone
running-config XML files into small per-control-area fragments plus a
manifest, for AI-assisted management plane assessment.

WHY THIS EXISTS
---------------
The assessment AI (USAI.gov chat) cannot execute code and cannot untar
archives, and feeding it a whole 40,000-line config invites silent
truncation and fabricated findings. This script does the deterministic
work locally so the AI only ever sees small, verifiable fragments.

WHAT IT DOES
------------
  1. Extracts the archive (tarfile, stdlib).
  2. Identifies every XML file by CONTENT (root element and structural
     markers), never by filename, because bundle-internal filenames are
     undocumented by Palo Alto and vary across PAN-OS versions.
  3. Classifies each XML as local-config, pushed-template,
     pushed-device-group, config-unclassified, or other. The class
     becomes the fragment prefix (LOCAL_/TEMPLATE_/DEVGROUP_) so that
     "where did this setting come from" survives into the AI sessions.
  4. Extracts control-area fragments via XPath. A fragment the source
     genuinely lacks is recorded as NOT-PRESENT rather than silently
     skipped, so "absent" is always an explicit, reviewable claim.
  5. Optionally redacts secrets so fragments are safe to upload.
  6. Writes MANIFEST.txt and MANIFEST.csv.txt with file roles, SHA256
     hashes, fragment line counts, and ground-truth element counts that
     the AI's extraction output must reconcile against.

USAGE
-----
  python3 split_pan_bundle.py -i /path/to/bundles -o /path/to/split --redact
  python3 split_pan_bundle.py -i device_state.tgz -o ./split --redact

Requires Python 3.6+. Standard library only (no pip installs).
Read-only with respect to inputs.

SECURITY NOTE
-------------
Extraction is guarded against path traversal ("tar slip"): archive
members resolving outside the destination directory are refused.
On Python 3.12+ extractall also uses filter="data".
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

# ===========================================================================
# CONFIGURATION TABLES
# Everything assessment-specific lives in these three tables. To add a new
# control area, add a FRAGMENT_MAP entry; to add a new reconciliation
# count, add a COUNT_MAP entry; to redact a new secret element, add its
# tag name to REDACT_ELEMENTS. No other code changes needed.
# ===========================================================================

# FRAGMENT_MAP: control-area name -> ordered list of candidate XPaths.
#
# Each area's XPaths are tried IN ORDER; the FIRST that matches wins, and
# every node it returns is written as its own fragment. Later paths are
# fallbacks for alternative placements, not additive searches.
#
# './/' (descendant) rather than absolute paths: pushed template files
# wrap the same elements under \u003ctemplate>\u003centry>\u003cconfig>\u003cdevices>..., so
# an absolute path would miss them. PAN-OS config XML has no namespaces,
# which keeps these simple.
#
# Prefixes match the assessment workbook sections:
#   MGT=management interface/system, AUTH=authn/accounts/roles,
#   IMP=interface mgmt profiles+interfaces, NSC=network security controls,
#   SVC=service hardening, LOG=logging.
FRAGMENT_MAP = [
    # deviceconfig/system: MGT IP, permitted-ip, service toggles, DNS/NTP.
    # Highest-value single fragment for MGT checks.
    ("MGT_deviceconfig-system", [".//deviceconfig/system"]),

    # setting/management: idle-timeout, admin-lockout. NOTE for analysis:
    # if NOT-PRESENT, PAN-OS defaults apply (idle-timeout 60 min, lockout
    # disabled). Absence here is NOT "unknown".
    ("MGT_setting-management", [".//deviceconfig/setting/management"]),

    # mgt-config: local admin users + password complexity. Lives at config
    # root, outside \u003cdevices>.
    ("AUTH_mgt-config", [".//mgt-config"]),

    # NOTE on the [entry] predicate used below: several of these tag names
    # appear BOTH as definition containers (which have \u003centry> children)
    # and as bare reference leaves elsewhere in the config, e.g.
    #   \u003cserver-profile>TEST-RAD-SRV\u003c/server-profile>   (a reference)
    # inside an authentication profile. Without the [entry] guard, the
    # reference leaf matches first and a 2-line file gets labelled as the
    # server-profile definitions - false presence, which is worse than a
    # missing fragment because it looks like evidence. Requiring an
    # \u003centry> child matches only real definition containers.
    ("AUTH_authentication-profile", [
        ".//shared/authentication-profile[entry]",
        ".//vsys/entry/authentication-profile[entry]",
        ".//authentication-profile[entry]",
    ]),
    ("AUTH_certificate-profile", [
        ".//shared/certificate-profile[entry]",
        ".//certificate-profile[entry]",
    ]),
    # RADIUS/TACACS+/LDAP/SAML/Kerberos target DEFINITIONS (not the
    # references to them that live inside authentication profiles).
    ("AUTH_server-profiles", [
        ".//shared/server-profile[entry]",
        ".//server-profile[entry]",
    ]),
    # Custom roles only; built-in roles never appear in config, so
    # NOT-PRESENT means "no custom roles", not "no roles exist".
    ("AUTH_admin-role", [
        ".//shared/admin-role[entry]",
        ".//admin-role[entry]",
    ]),

    # Which services a data-plane interface will answer, plus per-profile
    # permitted-ip.
    ("IMP_interface-mgmt-profiles",
     [".//network/profiles/interface-management-profile"]),

    # Full interface tree: shows which interfaces BIND a profile and what
    # zone/IP they carry. Often the largest fragment; acceptable.
    ("IMP_interfaces", [".//network/interface"]),

    ("NSC_zones", [".//vsys/entry/zone[entry]", ".//zone[entry]"]),

    # Local rulebase = middle layer of effective policy
    # (PRE -> LOCAL -> POST).
    ("NSC_rulebase-security", [
        ".//vsys/entry/rulebase/security",
        ".//rulebase/security",
    ]),
    ("NSC_pre-rulebase-security", [".//pre-rulebase/security"]),
    ("NSC_post-rulebase-security", [".//post-rulebase/security"]),

    # NAT from any layer: a destination-NAT to a management IP is a direct
    # exposure path.
    ("NSC_rulebase-nat", [
        ".//vsys/entry/rulebase/nat",
        ".//rulebase/nat",
        ".//pre-rulebase/nat",
        ".//post-rulebase/nat",
    ]),
    # Needed to resolve what rule source/destination names mean in IP terms.
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

    # Definition container only: deviceconfig/system references the
    # profile by name, and that reference must not match here.
    ("SVC_ssl-tls-service-profile", [
        ".//shared/ssl-tls-service-profile[entry]",
        ".//ssl-tls-service-profile[entry]",
    ]),
    ("SVC_snmp", [
        ".//deviceconfig/system/snmp-setting",
        ".//snmp-setting",
    ]),
    ("LOG_log-settings", [".//shared/log-settings", ".//log-settings"]),
    ("LOG_syslog-profiles", [
        ".//shared/log-settings/syslog[entry]",
        ".//syslog[entry]",
    ]),
    ("MGT_service-routes", [
        ".//deviceconfig/system/route",
        ".//deviceconfig/system/service",
    ]),

    # Certificate store: the TLS profile only NAMES its certificate, so
    # the [entry] guard is essential here - without it the name reference
    # inside the TLS profile matches and masquerades as the store.
    ("SVC_certificates", [
        ".//shared/certificate[entry]",
        ".//certificate[entry]",
    ]),

    # GlobalProtect: VPN termination and client pools that may create an
    # indirect path to the management network (workbook check MGT-04).
    ("IMP_globalprotect", [
        ".//vsys/entry/global-protect",
        ".//global-protect",
    ]),

    # HA1 is itself a management-plane path between peers.
    ("MGT_high-availability", [".//deviceconfig/high-availability"]),
]

# COUNT_MAP: reconciliation counts computed here, locally, as ground truth.
# When the AI extracts records from a fragment, its record count MUST match
# these numbers. This is the completeness check a chat-only AI cannot
# perform for itself. Unlike FRAGMENT_MAP, every path is evaluated (no
# first-match-wins), because a count of zero is itself information.
COUNT_MAP = [
    ("interfaces_ethernet",  [".//network/interface/ethernet/entry"]),
    ("interfaces_aggregate", [".//network/interface/aggregate-ethernet/entry"]),
    ("interfaces_loopback",  [".//network/interface/loopback/units/entry"]),
    ("interfaces_tunnel",    [".//network/interface/tunnel/units/entry"]),
    ("interfaces_vlan",      [".//network/interface/vlan/units/entry"]),
    ("mgmt_profiles",
     [".//network/profiles/interface-management-profile/entry"]),
    ("admin_users",          [".//mgt-config/users/entry"]),
    ("admin_roles",          [".//admin-role/entry"]),
    ("auth_profiles",        [".//authentication-profile/entry"]),
    ("zones",                [".//zone/entry"]),
    ("security_rules_local", [".//rulebase/security/rules/entry"]),
    ("security_rules_pre",   [".//pre-rulebase/security/rules/entry"]),
    ("security_rules_post",  [".//post-rulebase/security/rules/entry"]),
    # ElementTree has no XPath union operator, so the three NAT placements
    # are summed in code instead.
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

# REDACT_ELEMENTS: element TAG NAMES whose entire content is replaced
# with 'REDACTED' before fragments are written (text and children).
#
# Matching is by exact tag name, so 'community' does NOT cover
# 'snmp-community-string' - both must be listed. That exact miss was
# caught by the synthetic test vector. If you find another secret-bearing
# element in a real fragment, add its tag name here.
REDACT_ELEMENTS = {
    "phash", "password", "private-key", "public-key", "preshared-key",
    "bind-password", "secret", "api-key", "auth-password", "priv-password",
    "community", "shared-secret", "client-key", "master-key",
    "snmp-community-string", "authpwd", "privpwd",
}

# Roles that get fragmented (config-unclassified included so nothing is
# silently dropped; it is flagged for human review in the manifest).
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


# ===========================================================================
# HELPERS
# ===========================================================================

def sha256_file(path):
    """SHA256 of a file, for chain of custody on every artifact assessed."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def count_lines(path):
    """Line count, tolerant of odd encodings inside vendor bundles."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def safe_extract(tar, dest):
    """
    Extract a tarball, refusing members that would escape dest
    (path traversal / "tar slip"). Returns list of refused member names.
    """
    dest_abs = os.path.realpath(dest)
    refused = []
    members = []
    for m in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, m.name))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            refused.append(m.name)
            continue
        # Skip device nodes / fifos; configs are regular files and dirs.
        if not (m.isfile() or m.isdir()):
            refused.append(m.name + " (non-regular)")
            continue
        members.append(m)
    kwargs = {"path": dest, "members": members}
    # PEP 706: Python 3.12+; skips special files the member list already
    # dropped, and is the extraction mode 3.14 will default to.
    if sys.version_info >= (3, 12):
        kwargs["filter"] = "data"
    tar.extractall(**kwargs)
    return refused


def looks_like_xml(path):
    """
    True if the file starts like XML. Bundle internals do not always carry
    .xml extensions, so extension alone cannot be trusted.
    """
    if path.lower().endswith(".xml"):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(512).lstrip()
        return head.startswith("\u003c?xml") or head.startswith("\u003c")
    except OSError:
        return False


def classify_pan_xml(root):
    """
    Classify a parsed PAN-OS config by structure, never by filename.

    Priority order:
      1. Contains \u003ctemplate>            -> pushed-template
      2. device-group / pre|post-rulebase markers WITHOUT deviceconfig
                                        -> pushed-device-group
         (the 'without deviceconfig' guard matters: a merged running
         config can contain pre/post rulebases AND deviceconfig, and that
         file is a local/merged config, not a pushed policy file)
      3. root \u003cconfig> with deviceconfig/system or mgt-config
                                        -> local-config
      4. root \u003cconfig>, none of the above -> config-unclassified
      5. anything else                  -> other
    """
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
    """
    Replace every secret-bearing element with a REDACTED leaf.
    Clears child nodes, not only el.text, so nested private-key / shared-key
    XML cannot leak into fragments. Operates on the in-memory tree only,
    so files under _extracted/ keep their original content as local evidence.

    Returns how many matching elements were masked. A redaction count of 0
    on a local config that has admin users is itself suspicious.
    """
    count = 0
    for el in root.iter():
        # Strip any namespace prefix before comparing tag names.
        tag = el.tag.split("}")[-1] if isinstance(el.tag, str) else ""
        if tag not in REDACT_ELEMENTS:
            continue
        el.text = "REDACTED"
        del el[:]
        count += 1
    return count


def indent_tree(elem, level=0):
    """
    Pretty-print in place (stdlib ET has no indent() before 3.9).
    Indentation matters: the AI-side protocol has the model quote verbatim
    snippets which a human then greps, so stable formatting is required.
    """
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
    """Write one element to disk as an indented, self-contained XML file."""
    import copy
    clone = copy.deepcopy(node)
    indent_tree(clone)
    xml_bytes = ET.tostring(clone, encoding="utf-8")
    with open(out_path, "wb") as fh:
        fh.write(b'\u003c?xml version="1.0" encoding="utf-8"?>\n')
        fh.write(xml_bytes)
        fh.write(b"\n")


def gather_inputs(input_path):
    """One file, or the top level of a folder (no recursion, by design)."""
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
    """
    LOCAL / TEMPLATE / DEVGROUP, plus a disambiguator only when two XML
    files share that role so fragments do not overwrite each other.
    A single local-config keeps the un-suffixed names the test vector
    and playbook expect.
    """
    prefix = ROLE_PREFIX.get(role, "UNCLASS")
    if role_total \u003c= 1:
        return prefix
    stem = os.path.splitext(os.path.basename(source_name))[0]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "file"
    return "%s_%02d_%s" % (prefix, role_index, stem)


def reset_device_output(dev_out, extract_dir, frag_dir):
    """Drop prior split artifacts so a re-run cannot leave stale fragments."""
    for path in (extract_dir, frag_dir):
        if os.path.isdir(path):
            shutil.rmtree(path)
    for name in ("MANIFEST.txt", "MANIFEST.csv.txt"):
        manifest_path = os.path.join(dev_out, name)
        if os.path.isfile(manifest_path):
            os.remove(manifest_path)
    os.makedirs(extract_dir)
    os.makedirs(frag_dir)


# ===========================================================================
# MAIN PER-BUNDLE PROCESSING
# ===========================================================================

def process_bundle(item, output_root, do_redact):
    device_name = os.path.basename(item)
    for ext in (".tar.gz", ".tgz", ".tar", ".gz", ".xml"):
        if device_name.lower().endswith(ext):
            device_name = device_name[: -len(ext)]
            break

    dev_out = os.path.join(output_root, device_name)
    extract_dir = os.path.join(dev_out, "_extracted")   # raw, UNREDACTED
    frag_dir = os.path.join(dev_out, "fragments")       # upload-safe
    reset_device_output(dev_out, extract_dir, frag_dir)

    print("=== %s -> %s" % (os.path.basename(item), dev_out))
    manifest = []   # list of dicts

    # --- Step 1: extract or copy -------------------------------------
    if item.lower().endswith(".xml"):
        shutil.copy2(item, extract_dir)
    else:
        try:
            with tarfile.open(item, "r:*") as tar:   # r:* auto-detects gz
                refused = safe_extract(tar, extract_dir)
            for r in refused:
                print("  WARNING refused unsafe archive member: %s" % r)
        except tarfile.TarError as exc:
            print("  ERROR: cannot read archive (%s); skipping" % exc)
            return

        # Bundles sometimes nest archives one level deep. Extract each into
        # its own folder so name collisions cannot clobber files. One level
        # only, by design: deeper nesting is unexpected and a human should
        # look at it rather than have it auto-unpacked.
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
                            print("  WARNING refused unsafe nested member "
                                  "(%s): %s" % (fn, r))
                    except tarfile.TarError as exc:
                        print("  WARNING nested file is not a tar (%s): %s; "
                              "left packed" % (fn, exc))

    # --- Steps 2-3: inventory + classify every file by CONTENT --------
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
                    role = "xml-parse-failed"   # recorded, not fatal
            manifest.append({
                "Kind": "source-file", "Name": rel, "Role": role,
                "RootElement": root_el, "Lines": count_lines(full),
                "SHA256": sha256_file(full), "Detail": "",
            })

    # Sanity gate: no identifiable local config means classification failed
    # or the export is not what we think it is.
    if not any(s["role"] == "local-config" for s in source_xmls):
        print("  WARNING: no local-config identified. Check manifest "
              "before proceeding.")

    # --- Steps 4-5: fragment extraction (redaction first) -------------
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
                        # Line count feeds the AI-side truncation check:
                        # the model must confirm it received this many.
                        "Lines": count_lines(out_path),
                        "SHA256": sha256_file(out_path),
                        "Detail": "xpath=%s; from=%s" % (xp, src["name"]),
                    })
                break   # first matching xpath wins for this fragment
            if not found:
                # Explicit NOT-PRESENT row: the tooling-level version of
                # the four-state presence model. Absence is a recorded
                # claim, never an inference from silence.
                manifest.append({
                    "Kind": "fragment",
                    "Name": "%s_%s" % (prefix, frag_name),
                    "Role": src["role"], "RootElement": "",
                    "Lines": 0, "SHA256": "",
                    "Detail": "NOT-PRESENT in this source (all xpaths empty)",
                })

        # --- Step 6a: ground-truth counts -----------------------------
        # Counted on the same in-memory tree the fragments came from, so
        # fragments and counts can never disagree. (Redaction masks values
        # only; it cannot change element counts.)
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
                "Detail": "secret-bearing element values masked before "
                          "fragment write",
            })

    # --- Step 6b: write the two manifests -----------------------------
    # MANIFEST.csv.txt: machine-readable, stays local. The .txt suffix only
    # exists so it COULD be uploaded if ever needed.
    # MANIFEST.txt: human-readable; this is the copy that goes into the
    # USAI inventory session (P0) and anchors every reconciliation.
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
    lines.append("Generated     : %s"
                 % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Redaction     : %s"
                 % ("ON" if do_redact
                    else "OFF - do not upload unredacted fragments"))
    lines.append("")
    lines.append("--- SOURCE FILES (role determined by content, not filename) ---")
    for r in manifest:
        if r["Kind"] == "source-file":
            lines.append("%-22s %7d lines  %s"
                         % (r["Role"], r["Lines"], r["Name"]))
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

    written = sum(1 for r in manifest
                  if r["Kind"] == "fragment" and r["Lines"] > 0)
    missing = sum(1 for r in manifest
                  if r["Kind"] == "fragment" and r["Lines"] == 0)
    print("  fragments: %d written, %d not present; manifest at %s"
          % (written, missing, txt_path))


def main():
    ap = argparse.ArgumentParser(
        description="Split PAN-OS device state bundles into per-control-area "
                    "fragments plus a manifest, for AI-assisted assessment.")
    ap.add_argument("-i", "--input", required=True,
                    help="A .tgz/.tar.gz/.xml file, or a folder of them.")
    ap.add_argument("-o", "--output", required=True,
                    help="Folder to write per-device output into.")
    ap.add_argument("--redact", action="store_true",
                    help="Mask secrets in fragments (recommended before "
                         "any AI upload).")
    args = ap.parse_args()

    inputs = gather_inputs(args.input)
    if not inputs:
        sys.exit("No .tgz/.tar.gz/.xml inputs found at %s" % args.input)

    os.makedirs(args.output, exist_ok=True)
    for item in inputs:
        process_bundle(item, args.output, args.redact)

    print("\nDone. Review each MANIFEST.txt before uploading anything.")
    print("Reminder: only redacted fragments and manifests go to USAI, "
          "never the raw bundle.")
    if not args.redact:
        print("WARNING: --redact was NOT used. Fragments may contain "
              "secrets.")


if __name__ == "__main__":
    main()
