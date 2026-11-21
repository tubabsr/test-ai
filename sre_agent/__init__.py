"""Evidence-based Kubernetes incident analysis.

The analysis core (models, detection, evidence, root_cause, five_whys, remediation,
pipeline, rca) uses only the standard library. Network clients live in sources.py
and service.py and are imported on demand.
"""

__version__ = "0.1.0"
