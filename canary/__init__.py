"""AI Data-Leakage Canary System.

A defensive security tool for the security team: plant unique, fully
fabricated "internal facts" into systems the company owns, then watch two
detection points (an S3 honeytoken and an outbound public-AI probe) that only
trigger if the fact escapes the building.

Nothing in this package attacks or exploits anything. It runs on
company-owned infrastructure and contains only synthetic data.
"""

__version__ = "1.0.0"
