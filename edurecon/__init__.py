"""edu-recon: authorized recon & triage orchestrator for education-sector CTF/red-team exercises.

Pipeline: host discovery -> nmap fingerprint -> web dir discovery -> exposures
          -> nuclei CVE/misconfig -> sqlmap -> weak-password -> wp2shell -> triage -> report.

Only scans hosts explicitly listed in the target file (scope-locked).
"""

__version__ = "0.1.0"
