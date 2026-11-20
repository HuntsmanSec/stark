"""S.T.A.R.K - Security Threat Assessment and Reputation Kit.

Query many OSINT / threat-intelligence reputation sources for an observable
(IP, domain, URL, hash, email) and get one consolidated verdict.

Library use::

    from stark import Stark
    report = Stark().query("8.8.8.8")
    print(report.verdict)
"""

__version__ = "0.3.1"
__title__ = "S.T.A.R.K"
__description__ = "Security Threat Assessment and Reputation Kit"


def __getattr__(name):  # lazy import keeps `import stark` cheap
    if name == "Stark":
        from .engine import Stark
        return Stark
    raise AttributeError(name)
