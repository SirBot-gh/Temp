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
    ("SVC_certificates", [
        ".//shared/certificate[entry]",
        ".//certificate[entry]",
    ]),
    ("IMP_globalprotect", [
        ".//vsys/entry/global-protect",
        ".//global-protect",
    ]),
    ("MGT_high-availability", [".//deviceconfig/high-availability"]),
]
