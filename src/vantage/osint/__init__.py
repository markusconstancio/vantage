"""OSINT / social-engineering risk assessment module.

Automates the methodology in docs/osint-methodology.md: it derives the six risk
factors from a subject's structured footprint + breach data, produces a 0-100
score, maps attack scenarios, and emits remediation. Subjects are consent-gated
(see docs/safety-framework.md rule 3); only synthetic personas are committed.
"""
