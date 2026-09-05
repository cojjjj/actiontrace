from dataclasses import asdict, dataclass, field
import hashlib
import json


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int
    message: str


@dataclass(frozen=True)
class Flow:
    source: str
    evidence: tuple[Evidence, ...]

    def via(self, evidence: Evidence) -> "Flow":
        return Flow(self.source, self.evidence + (evidence,))


@dataclass
class Finding:
    rule: str
    severity: str
    confidence: str
    title: str
    message: str
    remediation: str
    path: str
    line: int
    job: str
    trace: list[Evidence]
    fingerprint: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    files_scanned: int = 0

    def diagnostic(self, path: str, message: str, level: str = "warning") -> None:
        self.diagnostics.append(dict(path=path, level=level, message=message))

    def to_dict(self) -> dict:
        return {"schema_version": 1, "tool": "actiontrace", **asdict(self)}


def fingerprint(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()
