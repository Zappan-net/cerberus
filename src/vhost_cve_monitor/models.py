from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class NginxLocation:
    path: str
    proxy_pass: Optional[str] = None
    fastcgi_pass: Optional[str] = None
    uwsgi_pass: Optional[str] = None
    includes: List[str] = field(default_factory=list)


@dataclass
class VhostConfig:
    file_path: str
    server_names: List[str] = field(default_factory=list)
    roots: List[str] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)
    proxy_passes: List[str] = field(default_factory=list)
    fastcgi_passes: List[str] = field(default_factory=list)
    uwsgi_passes: List[str] = field(default_factory=list)
    upstream_paths: List[str] = field(default_factory=list)
    locations: List[NginxLocation] = field(default_factory=list)

    @property
    def is_redirect_only(self) -> bool:
        has_returns = bool(self.returns)
        has_local_or_upstream_app = bool(self.roots or self.proxy_passes or self.fastcgi_passes or self.uwsgi_passes)
        return has_returns and not has_local_or_upstream_app

    @property
    def primary_server_name(self) -> str:
        return self.server_names[0] if self.server_names else self.file_path

    @property
    def primary_root(self) -> Optional[str]:
        return self.roots[0] if self.roots else None


@dataclass
class StackMatch:
    stack_name: str
    confidence: str
    reasons: List[str]
    root_path: Optional[str] = None


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    source: str
    source_line: Optional[int] = None
    locations: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    vuln_id: str
    source: str
    severity: str
    summary: str
    details: str
    published: Optional[str]
    modified: Optional[str]
    package_name: str
    ecosystem: str
    affected_version: str
    references: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)


@dataclass
class AuditIssue:
    dependency: Dependency
    vulnerability: Vulnerability
    detection_method: str


@dataclass
class ScanFailure:
    scope: str
    reason: str
    detail: Optional[str] = None


@dataclass
class StackScanResult:
    stack: StackMatch
    dependencies: List[Dependency] = field(default_factory=list)
    issues: List[AuditIssue] = field(default_factory=list)
    failures: List[ScanFailure] = field(default_factory=list)
    audit_commands: List[str] = field(default_factory=list)


@dataclass
class VhostScanResult:
    vhost: VhostConfig
    stacks: List[StackScanResult] = field(default_factory=list)
    failures: List[ScanFailure] = field(default_factory=list)


@dataclass
class NotificationEvent:
    category: str
    fingerprint: str
    subject: str
    body: str
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
