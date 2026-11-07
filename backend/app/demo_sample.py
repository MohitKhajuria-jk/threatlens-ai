"""A harmless text file that stands in for the demo attack's trojan.

Its SHA-256 is the hash the demo Windows logs record for svc.exe, and the demo feed lists it,
so "Check a file" can be tried end to end. It contains only this text and can't run.
"""

import hashlib

NAME = "svc-demo-sample.txt"
CONTENT = (
    "ThreatLens demo sample\n"
    "======================\n"
    "This harmless text file stands in for svc.exe, the fictional trojan in the ThreatLens demo logs.\n"
    "Its hash is listed in the ThreatLens demo feed, so checking it on the Threat intel page shows a malicious verdict.\n"
    "It is not malware and contains nothing that can run.\n"
).encode("utf-8")
SHA256 = hashlib.sha256(CONTENT).hexdigest()
SHA1 = hashlib.sha1(CONTENT).hexdigest()
MD5 = hashlib.md5(CONTENT).hexdigest()
