# Contributing

Start with a minimal local workflow fixture. Describe which actor controls the input, the transformation path, the code boundary, and what remains unknown.

For rule changes, include one dangerous example and one realistic safe counterexample. Assert source location and evidence, not just a finding count. Add an explicit diagnostic when an important unsupported construct would otherwise appear analyzed.

Keep scans offline and read-only. Do not add network callbacks, workflow execution, credential discovery, or automated report submission. Avoid claims of confirmed exploitability based only on a syntactic pattern.

Run `python -m pytest -q`, `actiontrace . --strict --fail-on low`, and `python -m build` before submitting a change. If behavior changes, update the rule and limitation documentation.
