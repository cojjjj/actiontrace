"""Conservative expression reference extraction, including bracket notation."""
import re
from .model import Evidence, Flow

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
TOKEN = re.compile(r"'(?:''|[^'])*'|[A-Za-z_][A-Za-z0-9_-]*|\d+|\S")
ROOTS = {"github", "env", "inputs", "matrix", "needs", "steps"}
UNTRUSTED = re.compile(
    r"^github\.(?:head_ref$|event\.(?:"
    r"pull_request\.(?:title|body|head\.(?:ref|label))$|"
    r"(?:issue|discussion)\.(?:title|body)$|"
    r"(?:comment|review|review_comment)\.body$|"
    r"commits\.[^.]+\.(?:message|author\.(?:name|email))$|"
    r"head_commit\.(?:message|author\.(?:name|email))$))"
)


def references(expression: str) -> list[str]:
    tokens = TOKEN.findall(expression)
    result = []
    i = 0
    while i < len(tokens):
        if tokens[i] not in ROOTS:
            i += 1
            continue
        parts = [tokens[i]]
        i += 1
        while i < len(tokens):
            if tokens[i] == "." and i + 1 < len(tokens) and re.fullmatch(r"[\w*-]+", tokens[i+1]):
                parts.append(tokens[i+1])
                i += 2
            elif tokens[i] == "[" and i + 2 < len(tokens) and tokens[i+2] == "]" and tokens[i+1].startswith("'"):
                parts.append(tokens[i+1][1:-1].replace("''", "'"))
                i += 3
            else:
                break
        if len(parts) > 1:
            result.append(".".join(parts))
    return result


def unique(flows: list[Flow]) -> list[Flow]:
    result = {}
    for flow in flows:
        result.setdefault(flow.source, flow)
    return list(result.values())


class Context:
    def __init__(self, seeds=None, definitions=None):
        self.seeds = seeds or {}
        self.definitions = definitions or {}

    def resolve(self, ref: str, location: Evidence, active=frozenset()) -> list[Flow]:
        if len(active) > 64:
            raise ValueError("Expression binding depth exceeds 64; analysis incomplete")
        if ref in active:
            return []
        if ref in self.definitions:
            value, origin = self.definitions[ref]
            return [f.via(origin) for f in self.flows(value, origin, active | {ref})]
        if ref in self.seeds:
            return self.seeds[ref]
        if UNTRUSTED.fullmatch(ref):
            return [Flow(ref, (Evidence(location.path, location.line, f"Untrusted event data: {ref}"),))]
        return []

    def flows(self, value, location: Evidence, active=frozenset()) -> list[Flow]:
        if not isinstance(value, str):
            return []
        result = []
        for match in EXPR.finditer(value):
            for ref in references(match.group(1)):
                result.extend(self.resolve(ref, location, active))
        return unique(result)
