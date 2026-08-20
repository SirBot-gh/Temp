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
