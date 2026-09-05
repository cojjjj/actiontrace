# ActionTrace

**Follow untrusted data across GitHub Actions trust boundaries.**

ActionTrace is an offline static analyzer that explains how event data can reach executable workflow code. It follows environment aliases, matrix values, and inputs into local composite actions, then emits source-to-sink evidence paths for review.

It also highlights privileged checkout/execution sequences, mutable action references, self-hosted pull request runners, and broad token permissions.

**Status: experimental 0.1.** Findings are review candidates, not confirmed exploits. No production accuracy benchmark or independent security audit has been performed. This is a focused, inspectable research tool; use it alongside established tools such as [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint).

## Try it in a minute

Requires Python 3.11 or newer. Run these commands from this repository:

```sh
git clone https://github.com/cojjjj/actiontrace.git
cd actiontrace
python -m pip install -e .
actiontrace examples/demo --format html --output reports/demo.html --fail-on none
actiontrace examples/demo
actiontrace examples/safe --strict
```

Open `reports/demo.html` for a self-contained, filterable report. The second command intentionally returns exit code 1 because the demo contains high-severity review candidates. Demo workflows are nested under `examples/` and are not active repository workflows.

Scan another local checkout:

```sh
actiontrace /path/to/repository
actiontrace /path/to/repository --format sarif --output reports/results.sarif
actiontrace /path/to/workflow.yml --root /path/to/repository --format json
```

The scan performs no network requests, executes no workflow code, and does not modify scanned files. Installation downloads the Python dependency. Workflow discovery scans only the immediate `.github/workflows/*.yml` and `*.yaml` files; referenced local composite action definitions are loaded separately.

## What makes this useful

An unsafe expression can be several bindings away from its origin:

```text
github.event.pull_request.title
  -> workflow env.REVIEW_TITLE
  -> job/step env.DISPLAY
  -> local action input message
  -> composite run: echo "${{ inputs.message }}"
```

ActionTrace preserves file and line evidence along these modeled paths. JSON reports expose the trace; SARIF reports include `codeFlows` and deterministic fingerprints; HTML reports provide severity filters without a server or external assets.

Passing text through an environment variable and reading it as quoted shell data does not trigger the interpolation rule:

```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: printf '%s\n' "$TITLE"
```

Interpolating `${{ env.TITLE }}` back into `run:` crosses the code boundary again and is flagged. Shell reinterpretation through `eval` or a nested shell is outside the current model, so the safe example must not be generalized to arbitrary environment-variable usage.

## Rules

| ID | Check | Default severity | Evidence |
| --- | --- | --- | --- |
| AT001 | Untrusted expression reaches `run:` or `actions/github-script` | High | Source, bindings, local action call, sink |
| AT002 | PR-related checkout then likely workspace execution on a privileged trigger | High | Checkout and later execution candidate |
| AT003 | External action/reusable workflow lacks immutable pin | Low | Mutable or unresolved reference |
| AT004 | Pull request trigger selects a self-hosted runner | High | Runner declaration; exposure needs review |
| AT005 | Workflow/job declares `write-all` | Medium | Permission declaration |

Severity indicates review priority, not CVSS. AT001, AT002, and AT004 use medium confidence because expression semantics, authorization, conditions, and execution effects are not proven. AT003 and AT005 use high confidence for their configuration observations, not exploitability.

### Current checkout protections

GitHub added protections against common fork PR checkouts in privileged events in 2026. AT002 explicitly calls out unresolved checkout-version protections, and identifies an explicit `allow-unsafe-pr-checkout: true`. It does not assume a SHA or floating version lacks protection. A checkout alone is insufficient: AT002 also requires a later recognized execution command or local action in the same analyzed step list.

## CLI and automation

| Option | Meaning |
| --- | --- |
| `--format text/json/sarif/html` | Select report representation |
| `--output PATH` | Write a report instead of stdout |
| `--fail-on high/medium/low/none` | Findings threshold; default high |
| `--strict` | Treat coverage warnings as incomplete analysis |
| `--root PATH` | Resolve local actions for an individual workflow |

Exit codes: **0** no findings at the threshold, **1** findings at the threshold, **2** input/analysis errors (or coverage warnings in strict mode). `--fail-on none` does not suppress analysis errors. No workflows found is an error, not a clean scan.

The included CI runs tests, scans its own workflows with `--strict --fail-on low`, and builds the package on Python 3.11–3.13. CI dependencies are pinned to commit SHAs. Dependabot is configured to maintain action and Python dependency updates. The CI matrix is configuration, not a claim that all platforms have already been tested.

## Architecture and limits

See [ARCHITECTURE.md](ARCHITECTURE.md) for the model, parser boundaries, and extension points.

Current limits are deliberate and material:

- No arbitrary shell/JavaScript interpretation, expression evaluation, conditional path solving, or proof of exploitability. References inside transformations can be over-reported even when a transformation constrains the result.
- No step-output/job-output propagation, `$GITHUB_ENV` mutations, artifact/cache taint, or caller-to-reusable-workflow expansion. Direct output interpolation and reusable calls produce coverage warnings; hidden variants can still be missed.
- Only scalar matrix axes/include entries are modeled; dynamic matrices warn. Object-valued matrix axes and dynamic bracket indexes are not followed.
- Remote action internals are not fetched. Local JavaScript/Docker action internals warn and are not analyzed.
- AT002 uses a command-name heuristic, not a filesystem execution proof. Checkout paths, repeated checkouts, aliases, wrappers, cross-composite checkout state, custom git operations, and conditions may cause misses or false positives.
- Repository visibility, fork approvals, environment approvals, token defaults, actual secret availability, and OIDC cloud trust policies are unknown. A write permission alone does not prove compromise.
- YAML parsing preserves scalar text and source marks. It rejects duplicate keys, merge keys, recursive aliases, oversized files, and excessive expansion/depth; it is not a full GitHub workflow schema validator.
- Fingerprints tolerate line-only changes, but inserting/reordering unnamed steps can change them. Locations point to YAML value starts, not individual characters in multiline scripts.

A clean report means no modeled findings were detected. It is not a security certification.

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
python -m build
```

Tests cover dangerous and safe patterns, source locations, aliases, scope overrides, composite input propagation, recursion, malformed YAML, output escaping, reporting, and CLI failure behavior. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule responsibly.

## Publish your copy

1. Put the contents of this folder at your repository root, including the hidden `.github` folder.
2. Create an empty GitHub repository named `actiontrace` (or choose another name).
3. From this folder:

```sh
git init
git add .
git commit -m "Initial ActionTrace release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/actiontrace.git
git push -u origin main
```

Suggested description: **Offline GitHub Actions security analysis with source-to-sink evidence, composite-action tracing, and SARIF reports.**

Suggested topics: `security`, `github-actions`, `static-analysis`, `supply-chain-security`, `sarif`, `python`.

The distribution name is a local project choice; availability on PyPI and trademark clearance have not been checked. No package or repository is automatically published.

## References

- [GitHub: Script injections](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub: Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub: 2026 checkout protection changes](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

MIT licensed. Built with AI assistance; findings and code should receive human review before operational use.
