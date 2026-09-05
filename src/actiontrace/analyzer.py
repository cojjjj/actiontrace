"""Static trust propagation through workflow scopes and local composite actions."""
from pathlib import Path
import re

from .expressions import Context, EXPR, references
from .model import Evidence, Flow, Finding, Report, fingerprint
from .parse import Document, read_document

RULES = {
    "AT001": ("Untrusted data interpolated into executable code", "Move data into an environment variable and consume it as quoted data. Avoid eval, dynamic code construction, and shell reinterpretation."),
    "AT002": ("Untrusted checkout followed by possible code execution", "Build pull request code in a separate unprivileged workflow. Keep privileged automation on trusted code and validate transferred data."),
    "AT003": ("Mutable external action reference", "Pin repository actions to reviewed full commit SHAs and container actions to sha256 digests. Maintain pins with an update process."),
    "AT004": ("Pull request event uses a self-hosted runner", "Use isolated ephemeral runners for untrusted contributions; review fork approval and repository access policies."),
    "AT005": ("Broad write-all token permissions", "Declare only the individual token permissions required by each job."),
}
EXECUTION = re.compile(r"(?:^|[\s;&|])(?:npm|npx|yarn|pnpm|make|cmake|gradle|mvn|cargo|go|pytest|tox|pip|bundle|rake|dotnet|bash|sh|pwsh|powershell|python\d*|node|ruby|perl|source|\./[^\s]+)(?:\s|$)", re.M)
UNTRUSTED_CHECKOUT = re.compile(r"github\.(?:head_ref|event\.(?:pull_request\.(?:head\.|merge_commit_sha)|workflow_run\.head_))|refs/pull/")


def mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def disabled(value) -> bool:
    return isinstance(value, str) and value.strip().lower() in {"false", "${{ false }}"}


class Analyzer:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.report = Report()
        self.cache: dict[Path, Document] = {}

    def document(self, path: Path) -> Document | None:
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root):
            self.report.diagnostic(str(path.name), "Path escapes repository boundary", "error")
            return None
        if resolved in self.cache:
            return self.cache[resolved]
        try:
            doc = read_document(resolved, self.root)
        except (OSError, ValueError, RecursionError) as exc:
            self.report.diagnostic(resolved.relative_to(self.root).as_posix(), str(exc), "error")
            return None
        self.cache[resolved] = doc
        self.report.files_scanned += 1
        return doc

    def evidence(self, doc, keys, message):
        return Evidence(doc.path, doc.line(*keys), message)

    def emit(self, rule, severity, confidence, doc, keys, job, identity, message, trace=()):
        location = self.evidence(doc, keys, RULES[rule][0])
        self.report.findings.append(Finding(
            rule, severity, confidence, RULES[rule][0], message, RULES[rule][1],
            doc.path, location.line, job, [*trace, location],
            fingerprint(rule, doc.path, job, identity, message),
        ))

    def scan(self, paths=None) -> Report:
        if paths is None:
            folder = self.root / ".github" / "workflows"
            paths = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
        for path in paths:
            doc = self.document(path)
            if doc:
                try:
                    self.workflow(doc)
                except (ValueError, RecursionError) as exc:
                    self.report.diagnostic(doc.path, f"Analysis incomplete: {exc}", "error")
        if not self.cache:
            self.report.diagnostic(".", "No workflow files were scanned", "error")
        self.report.findings.sort(key=lambda f: (f.path, f.line, f.rule, f.fingerprint))
        return self.report

    def env_definitions(self, doc, keys, values):
        return {f"env.{key}": (value, self.evidence(doc, (*keys, key), f"Environment binding: {key}"))
                for key, value in mapping(values).items()}

    def workflow(self, doc):
        data = doc.data
        triggers = data.get("on", {})
        event_values = list(triggers) if isinstance(triggers, (list, dict)) else [triggers]
        if not event_values or any(not isinstance(event, str) or not event for event in event_values):
            self.report.diagnostic(doc.path, "Workflow on must specify named events", "error")
            return
        events = set(event_values)
        if not isinstance(data.get("jobs"), dict) or not data["jobs"]:
            self.report.diagnostic(doc.path, "Workflow must contain a nonempty jobs mapping", "error")
            return
        seeds = {}
        # Callable/dispatch inputs are caller-controlled, not necessarily public attacker input.
        for event in ("workflow_call", "workflow_dispatch"):
            for name, config in mapping(mapping(mapping(triggers).get(event)).get("inputs")).items():
                if mapping(config).get("type") in {"boolean", "number"}:
                    continue
                origin = self.evidence(doc, ("on", event, "inputs", name), f"Caller-controlled {event} input: {name}")
                flow = Flow(f"inputs.{name}", (origin,))
                seeds[f"inputs.{name}"] = [flow]
                seeds[f"github.event.inputs.{name}"] = [flow]
        workflow_env = self.env_definitions(doc, ("env",), data.get("env"))
        if data.get("permissions") == "write-all":
            self.emit("AT005", "medium", "high", doc, ("permissions",), "*", "workflow-permissions", "Workflow declares write-all; job-level permission overrides may reduce exposure.")
        for job, config in data["jobs"].items():
            if not isinstance(config, dict):
                self.report.diagnostic(doc.path, f"Job {job} must be a mapping", "error")
                continue
            if disabled(config.get("if")):
                continue
            base = ("jobs", job)
            if config.get("uses"):
                self.check_pin(doc, (*base, "uses"), job, f"job:{job}", config["uses"])
                self.report.diagnostic(doc.path, f"Reusable workflow in job {job} is not expanded; scan its file separately. Caller-to-callee input flow is not modeled.")
                continue
            if not isinstance(config.get("steps"), list):
                self.report.diagnostic(doc.path, f"Job {job} must contain a steps sequence", "error")
                continue
            if config.get("permissions") == "write-all":
                self.emit("AT005", "medium", "high", doc, (*base, "permissions"), job, "job-permissions", "Job explicitly requests write-all token permissions.")
            runner = config.get("runs-on", "")
            if "self-hosted" in str(runner) and events & {"pull_request", "pull_request_target"}:
                self.emit("AT004", "high", "medium", doc, (*base, "runs-on"), job, "runner", "A pull request trigger can select a self-hosted runner. Actual exposure depends on repository visibility, approvals, access policies, and runner isolation.")
            definitions = {**workflow_env, **self.env_definitions(doc, (*base, "env"), config.get("env"))}
            ctx = Context(dict(seeds), definitions)
            matrix = mapping(config.get("strategy")).get("matrix", {})
            for key, value in mapping(matrix).items():
                if key in {"include", "exclude"}:
                    continue
                choices = value if isinstance(value, list) else [value]
                loc = self.evidence(doc, (*base, "strategy", "matrix", key), f"Matrix axis: {key}")
                ctx.seeds[f"matrix.{key}"] = [f.via(loc) for v in choices for f in ctx.flows(v, loc)]
            for row in mapping(matrix).get("include", []) if isinstance(mapping(matrix).get("include", []), list) else []:
                for key, value in mapping(row).items():
                    loc = self.evidence(doc, (*base, "strategy", "matrix", "include"), f"Matrix include: {key}")
                    ctx.seeds.setdefault(f"matrix.{key}", []).extend(f.via(loc) for f in ctx.flows(value, loc))
            if isinstance(matrix, str):
                self.report.diagnostic(doc.path, f"Dynamic matrix in job {job} is not expanded")
            self.steps(doc, config["steps"], (*base, "steps"), job, ctx, events, (), ())

    def check_pin(self, doc, keys, job, identity, uses):
        if not isinstance(uses, str) or uses.startswith("./"):
            return
        if uses.startswith("docker://"):
            pinned = bool(re.search(r"@sha256:[a-fA-F0-9]{64}$", uses))
        else:
            pinned = bool(re.search(r"@[a-fA-F0-9]{40}$", uses))
        if not pinned:
            self.emit("AT003", "low", "high", doc, keys, job, identity, f"External action/workflow reference is mutable or unresolved: {uses}")

    def steps(self, doc, steps, base, job, parent_ctx, events, stack, call_trace):
        checkout = None
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                self.report.diagnostic(doc.path, f"Step {index + 1} in {job} must be a mapping", "error")
                continue
            if disabled(step.get("if")):
                continue
            keys = (*base, index)
            identity = "/".join((*stack, str(step.get("id", f"step-{index}"))))
            ctx = Context(parent_ctx.seeds, {**parent_ctx.definitions, **self.env_definitions(doc, (*keys, "env"), step.get("env"))})
            uses = step.get("uses", "")
            if not isinstance(uses, str):
                self.report.diagnostic(doc.path, f"Step uses must be a string in {job}", "error")
                continue
            self.check_pin(doc, (*keys, "uses"), job, identity, uses) if uses else None
            if uses.lower().startswith("actions/checkout@"):
                settings = mapping(step.get("with"))
                ref = str(settings.get("ref", ""))
                repository = str(settings.get("repository", ""))
                expanded = ref + " " + repository
                # Follow env aliases in checkout inputs without treating immutable SHAs as shell input.
                for match in EXPR.finditer(expanded):
                    for reference in references(match.group(1)):
                        if reference in ctx.definitions:
                            expanded += " " + str(ctx.definitions[reference][0])
                if events & {"pull_request_target", "workflow_run"} and UNTRUSTED_CHECKOUT.search(expanded):
                    unsafe = str(settings.get("allow-unsafe-pr-checkout", "false")).lower()
                    note = "Checkout protection explicitly disabled." if unsafe == "true" else "Checkout version protection is unresolved; current protected versions can block fork checkout."
                    checkout = (self.evidence(doc, keys, f"Checkout selects PR-related code. {note}"), note)
                # Keep evidence after later checkouts: multiple workspace paths may coexist.
            sinks = [("run", step.get("run"))]
            if uses.lower().startswith("actions/github-script@"):
                sinks.append(("script", mapping(step.get("with")).get("script")))
            for kind, code in sinks:
                if not isinstance(code, str):
                    continue
                sink_keys = (*keys, "run") if kind == "run" else (*keys, "with", "script")
                loc = self.evidence(doc, sink_keys, f"Interpolated into executable {kind}")
                for flow in ctx.flows(code, loc):
                    self.emit("AT001", "high", "medium", doc, sink_keys, job, identity,
                              f"{flow.source} reaches {kind} through expression interpolation. Review expression transformations, trigger reachability, and script semantics before assigning exploitability.",
                              (*call_trace, *flow.evidence))
                if re.search(r"\$\{\{\s*(?:steps|needs)\.", code):
                    self.report.diagnostic(doc.path, f"Step/job output interpolation in {job} is unresolved; output taint is not modeled")
            if checkout and ((isinstance(step.get("run"), str) and EXECUTION.search(step["run"])) or uses.startswith("./")):
                self.emit("AT002", "high", "medium", doc, keys, job, identity,
                          f"PR-related checkout precedes a command or local action that may execute workspace code. {checkout[1]} Conditions, checkout paths, and command effects need review.",
                          (*call_trace, checkout[0]))
            if uses.startswith("./"):
                self.composite(uses, mapping(step.get("with")), ctx, doc, keys, job, events, (*stack, f"{doc.path}:{job}:{index}"), call_trace)

    def composite(self, uses, arguments, caller, doc, keys, job, events, stack, call_trace):
        target = (self.root / uses).resolve()
        if not target.is_relative_to(self.root):
            self.report.diagnostic(doc.path, f"Local action escapes repository: {uses}", "error")
            return
        target_key = target.relative_to(self.root).as_posix()
        if len(stack) > 24 or target_key in stack:
            self.report.diagnostic(doc.path, f"Local action recursion/depth limit: {uses}", "error")
            return
        path = next((target / name for name in ("action.yml", "action.yaml") if (target / name).is_file()), None)
        if path is None:
            self.report.diagnostic(doc.path, f"Local action definition missing: {uses}", "error")
            return
        action = self.document(path)
        if not action:
            return
        runs = mapping(action.data.get("runs"))
        if runs.get("using") != "composite":
            self.report.diagnostic(action.path, "JavaScript/Docker action internals are not analyzed")
            return
        if not isinstance(runs.get("steps"), list):
            self.report.diagnostic(action.path, "Composite action requires steps", "error")
            return
        seeds = {key: value for key, value in caller.seeds.items() if not key.startswith("inputs.")}
        for name, definition in mapping(action.data.get("inputs")).items():
            if name in arguments:
                loc = self.evidence(doc, (*keys, "with", name), f"Passed to local action input: {name}")
                seeds[f"inputs.{name}"] = [f.via(loc) for f in caller.flows(arguments[name], loc)]
            else:
                loc = self.evidence(action, ("inputs", name, "default"), f"Default local action input: {name}")
                seeds[f"inputs.{name}"] = caller.flows(mapping(definition).get("default", ""), loc)
        call = self.evidence(doc, (*keys, "uses"), f"Call local composite action: {uses}")
        self.steps(action, runs["steps"], ("runs", "steps"), job, Context(seeds, caller.definitions), events, (*stack, target_key), (*call_trace, call))
