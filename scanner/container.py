"""
Container & Cloud API Checks - Docker, Kubernetes, etcd.
"""

import ssl
from dataclasses import dataclass
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from scanner.obfuscate import get_http_headers


@dataclass
class ContainerFinding:
    """Container/cloud API finding."""
    host: str
    port: int
    service: str
    check: str
    vulnerable: bool
    details: str
    severity: str = "critical"


def check_docker_api(host: str, port: int, use_tls: bool, timeout: float = 5.0) -> Optional[ContainerFinding]:
    """Check Docker API for unauthenticated access. Port 2375=HTTP, 2376=HTTPS."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/version"
    ctx = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read(2048).decode("utf-8", errors="ignore")
            if "ApiVersion" in data or "Version" in data:
                return ContainerFinding(
                    host, port, "Docker", "Unauthenticated API",
                    True, "Docker API accessible without auth - list containers/images possible",
                    "critical",
                )
    except (HTTPError, URLError, OSError):
        pass
    return None


def check_kubernetes_api(host: str, port: int, timeout: float = 5.0) -> Optional[ContainerFinding]:
    """Check Kubernetes API for anonymous access. Ports 6443, 443, 8443."""
    for path in ["/version", "/api/v1/namespaces", "/api"]:
        url = f"https://{host}:{port}{path}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = Request(url, headers=get_http_headers(extra={"Authorization": "Bearer "}))
            with urlopen(req, timeout=timeout, context=ctx) as r:
                data = r.read(4096).decode("utf-8", errors="ignore")
                if "namespaces" in data or "k8s" in data.lower() or "gitVersion" in data:
                    return ContainerFinding(
                        host, port, "Kubernetes", "Anonymous/weak auth",
                        True, "Kubernetes API may allow anonymous access - check system:anonymous",
                        "critical",
                    )
        except (HTTPError, URLError, OSError):
            continue
    return None


def check_etcd(host: str, port: int, timeout: float = 5.0) -> Optional[ContainerFinding]:
    """Check etcd (2379) for unauthenticated read of cluster state."""
    url = f"http://{host}:{port}/version"
    try:
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout) as r:
            data = r.read(2048).decode("utf-8", errors="ignore")
            if "etcdserver" in data or "etcd" in data.lower():
                return ContainerFinding(
                    host, port, "etcd", "Unauthenticated",
                    True, "etcd exposed - cluster state readable without auth",
                    "critical",
                )
    except (HTTPError, URLError, OSError):
        pass
    return None


def run_container_checks(host: str, ports: List[int], timeout: float = 5.0) -> List[ContainerFinding]:
    """Run container/cloud API checks on relevant ports."""
    results = []
    for port in ports:
        if port == 2375:
            f = check_docker_api(host, port, use_tls=False, timeout=timeout)
            if f:
                results.append(f)
        elif port == 2376:
            f = check_docker_api(host, port, use_tls=True, timeout=timeout)
            if f:
                results.append(f)
        elif port == 2379:
            f = check_etcd(host, port, timeout=timeout)
            if f:
                results.append(f)
        elif port in (6443, 443, 8443):
            f = check_kubernetes_api(host, port, timeout=timeout)
            if f:
                results.append(f)
    return results
