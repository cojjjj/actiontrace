"""Bounded, location-preserving YAML reader. Never constructs Python objects."""
from dataclasses import dataclass
from pathlib import Path
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

MAX_BYTES = 1_000_000
MAX_NODES = 30_000
MAX_DEPTH = 80


class ParseError(ValueError):
    pass


@dataclass
class Document:
    path: str
    data: dict
    lines: dict[tuple, int]

    def line(self, *keys) -> int:
        key = tuple(keys)
        while key not in self.lines and key:
            key = key[:-1]
        return self.lines.get(key, 1)


def read_document(path: Path, root: Path) -> Document:
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ParseError("YAML exceeds 1 MB input limit")
    try:
        node = yaml.compose(raw.decode("utf-8-sig"), Loader=yaml.BaseLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise ParseError(f"Cannot parse YAML: {exc}") from exc
    lines: dict[tuple, int] = {}
    count = 0

    def visit(item, keys=(), active=frozenset()):
        nonlocal count
        count += 1
        if count > MAX_NODES or len(keys) > MAX_DEPTH:
            raise ParseError("YAML expansion/depth limit exceeded")
        if id(item) in active:
            raise ParseError("Recursive YAML alias is unsupported")
        active = active | {id(item)}
        lines[keys] = item.start_mark.line + 1
        if item.tag not in {"tag:yaml.org,2002:str", "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq", "tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float", "tag:yaml.org,2002:null"}:
            raise ParseError("Unsupported explicit YAML tag")
        if isinstance(item, ScalarNode):
            return item.value
        if isinstance(item, SequenceNode):
            return [visit(child, keys + (i,), active) for i, child in enumerate(item.value)]
        if isinstance(item, MappingNode):
            result = {}
            for key, value in item.value:
                if not isinstance(key, ScalarNode):
                    raise ParseError("Mapping keys must be scalar")
                if key.value == "<<":
                    raise ParseError("YAML merge keys are unsupported; expand them explicitly")
                if key.value in result:
                    raise ParseError(f"Duplicate YAML key: {key.value}")
                result[key.value] = visit(value, keys + (key.value,), active)
            return result
        raise ParseError("Unsupported YAML node")

    data = visit(node) if node else {}
    if not isinstance(data, dict):
        raise ParseError("Workflow/action must be a mapping")
    return Document(relative, data, lines)
