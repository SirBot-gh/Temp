PALO ALTO MANAGEMENT PLANE ASSESSMENT TOOLKIT
==============================================
Generated: see file dates. Companion to the assessment workbook and
assessor guide.

WHAT THIS IS
------------
A pipeline for assessing Palo Alto firewall management plane security
from exported device state bundles, using a chat-only AI (USAI.gov)
that cannot execute code.

The core idea: your machine does everything mechanical and countable
(unpacking, splitting, counting, redacting). The AI only does what
needs judgment, and everything it claims can be checked against a
number your own machine produced.


FILES
-----
  split_pan_bundle.py      Splitter, Python 3.6+, Linux/macOS/Windows.
                           PREFERRED - this version has been executed
                           and verified against the test bundle.

  Split-PanBundle.ps1      Same tool for Windows PowerShell 5.1.
                           Logic-equivalent; not executed in testing.
                           Use only if Python is unavailable.

  TESTFW-01_device_state.tgz
                           Synthetic test bundle. Entirely fabricated
                           data, safe to run anywhere. Contains a local
                           config, a pushed template, a pushed device
                           group, and deliberate secret "canaries" that
                           redaction must catch.

  EXPECTED_RESULTS.txt     Exactly what the test bundle must produce.
                           Compare your run against this before
                           trusting the script on real data.

  USAI_Prompt_Playbook.md  The full prompt set (P0-P9): record schema,
                           PAN-OS defaults table, extraction prompts per
                           control area, exposure inference, cross-device
                           correlation, adversarial review.

  PAN_Mgmt_Plane_Assessment_Workbook.xlsx
                           4-sheet assessment workbook: Cover, Checklist
                           (31 items, 7 sections), Findings Notes,
                           Evidence Index.

  PAN_Mgmt_Plane_Assessor_Guide.docx
                           8-section companion guide: scope,
                           prerequisites, execution, result
                           interpretation, evidence, findings,
                           limitations.


ORDER OF OPERATIONS
-------------------
STEP 1 - Prove the tool works (5 minutes)

    python3 split_pan_bundle.py -i TESTFW-01_device_state.tgz \
        -o ./test-out --redact

  Compare test-out/TESTFW-01_device_state/MANIFEST.txt against
  EXPECTED_RESULTS.txt. Expect 21 fragments written, 51 NOT-PRESENT,
  redaction count of 3 on LOCAL. Then confirm no secrets leaked:

    grep -r "TESTHASH\|CANARY-COMMUNITY" test-out/*/fragments/   # must find nothing
    grep -r "TESTFW-CANARY-01" test-out/*/fragments/             # must find something

  If anything deviates, stop and investigate before using real data.

STEP 2 - Run against real bundles

    python3 split_pan_bundle.py -i /path/to/bundles -o /path/to/split --redact

  Review each MANIFEST.txt. Two things matter most:
    - Which source ROLES were identified. If no pushed-template or
      pushed-device-group appears, source attribution and override
      detection are not possible for that device (prompt P6 gets
      skipped).
    - Which fragments came back NOT-PRESENT. In a Panorama environment,
      interface and profile config often arrives via TEMPLATE rather
      than LOCAL; check both prefixes before concluding something is
      missing.

STEP 3 - Spot-check redaction on real data

  The redaction list is best-effort from known PAN-OS element names.
  Eyeball a few fragments before the first upload. If you find a
  secret-bearing element that was missed, add its TAG NAME to
  REDACT_ELEMENTS in the script (Python) or $RedactElements
  (PowerShell) and re-run.

STEP 4 - Test how USAI handles uploads (2 minutes, do once)

  Upload one fragment and ask the model to state its first line, last
  line, and total line count. Compare against MANIFEST.txt. If it
  can't do this accurately, uploads are being chunked or summarized:
  paste fragments into the chat box instead for the whole engagement.

STEP 5 - Run the prompt sessions

  Follow USAI_Prompt_Playbook.md. Per device: P0, then P1-P5
  extraction, then P6 (if pushed sources exist) and P7. Then P8 across
  the fleet, draft findings into the workbook, and P9 adversarial
  review before anything reaches the customer.

STEP 6 - Record results in the workbook

  Every checklist result should trace to an extraction record, and
  every record to a config path you can verify.


BEFORE YOU START: ONE THING TO GET FROM THE CUSTOMER
-----------------------------------------------------
The documented list of authorized administrative source subnets and
jump hosts. Without it, the AI can flag a permitted-IP entry as broad
but cannot say whether a given subnet is legitimate. Prompt P7
requires this as an input.

If the customer cannot produce that list, record it as a finding in
its own right: they cannot state who is supposed to have management
access.


DATA HANDLING
-------------
  _extracted/    UNREDACTED originals. Local evidence. NEVER upload.
  fragments/     Redacted, upload-safe. This is what goes to USAI.
  MANIFEST.txt   Upload-safe. Goes into prompt P0.
  MANIFEST.csv.txt  Machine-readable copy for your own use.

Raw bundles never go to USAI. Only redacted fragments and manifests.


WHAT CONFIG ANALYSIS CANNOT TELL YOU
-------------------------------------
These need sources outside the config, and the prompts are written to
say so rather than guess:

  - Actual internet reachability. Config shows what the firewall would
    answer; upstream filtering may block it. Only live external
    scanning confirms exposure.
  - Whether MFA actually fires. With RADIUS/SAML this is enforced on
    the identity provider, invisible from the firewall.
  - Whether logs arrive and alerts fire. Config proves forwarding is
    configured, not that the SIEM receives or acts on it.
  - Password strength and default credentials. Hashes are redacted and
    are not assessable this way.


KNOWN BEHAVIOR WORTH UNDERSTANDING
-----------------------------------
Definition-container XPaths require an <entry> child. This is
deliberate: several PAN-OS tag names appear both as real definition
containers and as bare name references elsewhere (e.g. a TLS profile
naming its certificate). Without the guard, a reference leaf produces
a tiny fragment that LOOKS like evidence but contains only a name.
False presence is worse than a missing fragment, so references are
excluded and the fragment reports NOT-PRESENT instead.
