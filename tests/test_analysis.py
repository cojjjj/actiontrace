from pathlib import Path
import json
import textwrap
import pytest

from actiontrace.analyzer import Analyzer
from actiontrace.cli import main
from actiontrace.expressions import references
from actiontrace.parse import ParseError, read_document
from actiontrace.render import html_report, sarif

SHA = "a" * 40


def write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    return path


def workflow(root, steps, header="on: pull_request_target", job_extra=""):
    content = header + "\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    if job_extra:
        content += textwrap.indent(textwrap.dedent(job_extra).strip(), "    ") + "\n"
    content += "    steps:\n" + textwrap.indent(textwrap.dedent(steps).strip(), "      ") + "\n"
    return write(root, ".github/workflows/ci.yml", content)


def rules(root):
    return [f.rule for f in Analyzer(root).scan().findings]


@pytest.mark.parametrize("expression", [
    "github.event.pull_request.title", "github['event']['pull_request']['title']",
    "github.event.comment.body", "github.head_ref",
])
def test_direct_sources(tmp_path, expression):
    workflow(tmp_path, '- run: echo "${{ ' + expression + ' }}"')
    report = Analyzer(tmp_path).scan()
    finding = report.findings[0]
    assert finding.rule == "AT001"
    assert finding.line == 6
    assert finding.trace[0].message.startswith("Untrusted event data")


@pytest.mark.parametrize("expression", ["github.sha", "github.event.pull_request.head.sha", "'github.event.pull_request.title'"])
def test_immutable_or_literal_is_not_shell_taint(tmp_path, expression):
    workflow(tmp_path, '- run: echo "${{ ' + expression + ' }}"')
    assert "AT001" not in rules(tmp_path)


def test_quoted_env_consumption_is_safe_boundary(tmp_path):
    workflow(tmp_path, '''
    - env:
        TITLE: ${{ github.event.pull_request.title }}
      run: printf '%s\\n' "$TITLE"
    ''')
    assert not rules(tmp_path)


def test_env_chain_and_override(tmp_path):
    workflow(tmp_path, '''
    - run: echo "${{ env.ALIAS }}"
    - env:
        TITLE: safe
      run: echo "${{ env.TITLE }}"
    ''', header='on: pull_request\nenv:\n  TITLE: ${{ github.event.pull_request.title }}', job_extra='env:\n  ALIAS: ${{ env.TITLE }}')
    report = Analyzer(tmp_path).scan()
    assert len(report.findings) == 1
    assert len(report.findings[0].trace) == 4


def test_env_cycle_terminates(tmp_path):
    workflow(tmp_path, '- run: echo "${{ env.A }}"', job_extra='env:\n  A: ${{ env.B }}\n  B: ${{ env.A }}')
    assert not rules(tmp_path)


def test_matrix_taint(tmp_path):
    workflow(tmp_path, '- run: echo "${{ matrix.title }}"', job_extra='strategy:\n  matrix:\n    title: ["${{ github.event.issue.title }}"]')
    assert "AT001" in rules(tmp_path)


def test_matrix_include_taint(tmp_path):
    workflow(tmp_path, '- run: echo "${{ matrix.title }}"', job_extra='strategy:\n  matrix:\n    include:\n      - title: ${{ github.head_ref }}')
    assert "AT001" in rules(tmp_path)


def test_local_action_flow_and_lines(tmp_path):
    workflow(tmp_path, '''
    - uses: ./.github/actions/print
      with:
        text: ${{ github.event.issue.body }}
    ''')
    write(tmp_path, ".github/actions/print/action.yml", '''
    name: print
    inputs:
      text:
        required: true
    runs:
      using: composite
      steps:
        - shell: bash
          run: echo "${{ inputs.text }}"
    ''')
    report = Analyzer(tmp_path).scan()
    assert report.files_scanned == 2
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.path == ".github/actions/print/action.yml"
    assert finding.line == 9
    assert any("Passed to local action" in n.message for n in finding.trace)


def test_local_action_recursion(tmp_path):
    workflow(tmp_path, '- uses: ./action')
    write(tmp_path, 'action/action.yml', 'runs:\n  using: composite\n  steps:\n    - uses: ./action')
    report = Analyzer(tmp_path).scan()
    assert any("recursion" in d['message'] for d in report.diagnostics)


def test_checkout_chain_requires_later_execution(tmp_path):
    workflow(tmp_path, f'''
    - run: npm test
    - uses: actions/checkout@{SHA}
      with:
        ref: ${{{{ github.event.pull_request.head.sha }}}}
    - run: echo hello
    ''')
    assert "AT002" not in rules(tmp_path)
    workflow(tmp_path, f'''
    - uses: actions/checkout@{SHA}
      with:
        ref: ${{{{ github.event.pull_request.head.sha }}}}
        allow-unsafe-pr-checkout: true
    - run: npm test
    ''')
    report = Analyzer(tmp_path).scan()
    assert [f.rule for f in report.findings] == ["AT002"]
    assert "explicitly disabled" in report.findings[0].message


def test_checkout_protection_is_not_claimed_exploitable(tmp_path):
    workflow(tmp_path, '''
    - uses: actions/checkout@v7
      with:
        ref: ${{ github.event.pull_request.head.sha }}
    - run: make test
    ''')
    finding = next(f for f in Analyzer(tmp_path).scan().findings if f.rule == 'AT002')
    assert "can block fork checkout" in finding.message
    assert finding.confidence == 'medium'


def test_unprivileged_checkout_no_privileged_chain(tmp_path):
    workflow(tmp_path, f'''
    - uses: actions/checkout@{SHA}
      with:
        ref: ${{{{ github.event.pull_request.head.sha }}}}
    - run: npm test
    ''', header="on: pull_request")
    assert not rules(tmp_path)


@pytest.mark.parametrize("uses,expected", [(f"actions/checkout@{SHA}", False), ("actions/checkout@v4", True), ("docker://alpine:3", True), ("docker://alpine@sha256:" + "b"*64, False)])
def test_pin_detection(tmp_path, uses, expected):
    workflow(tmp_path, f"- uses: {uses}")
    assert ("AT003" in rules(tmp_path)) is expected


def test_permissions_and_runner(tmp_path):
    workflow(tmp_path, '- run: echo hello', header='on: [pull_request, push]\npermissions: write-all', job_extra='permissions: write-all')
    path = tmp_path / '.github/workflows/ci.yml'
    path.write_text(path.read_text().replace('ubuntu-latest', '[self-hosted, linux]'))
    assert rules(tmp_path).count('AT005') == 2
    assert 'AT004' in rules(tmp_path)


def test_disabled_step(tmp_path):
    workflow(tmp_path, '- if: false\n  run: echo "${{ github.head_ref }}"')
    assert not rules(tmp_path)


def test_dispatch_input_types(tmp_path):
    workflow(tmp_path, '- run: echo "${{ inputs.text }} ${{ inputs.enabled }}"', header='on:\n  workflow_dispatch:\n    inputs:\n      text:\n        type: string\n      enabled:\n        type: boolean')
    report = Analyzer(tmp_path).scan()
    assert len(report.findings) == 1
    assert 'inputs.text' in report.findings[0].message


def test_github_script_sink(tmp_path):
    workflow(tmp_path, f'- uses: actions/github-script@{SHA}\n  with:\n    script: console.log("${{{{ github.event.issue.title }}}}")')
    assert rules(tmp_path) == ['AT001']


@pytest.mark.parametrize("content", ['on: push\non: pull_request\njobs: {}', 'a: &a [*a]', 'a: [', 'a: &a {x: y}\nb: {<<: *a}', '!!python/object/apply:os.system [echo unsafe]'])
def test_bad_yaml_is_diagnostic(tmp_path, content):
    write(tmp_path, '.github/workflows/bad.yml', content)
    report = Analyzer(tmp_path).scan()
    assert any(d['level'] == 'error' for d in report.diagnostics)


def test_aliases_and_on_key(tmp_path):
    path = write(tmp_path, 'ci.yml', 'on: push\nenv: &env\n  FOO: yes\ncopy: *env\njobs: {}')
    doc = read_document(path, tmp_path)
    assert doc.data['on'] == 'push'
    assert doc.data['copy']['FOO'] == 'yes'


def test_path_escape(tmp_path):
    workflow(tmp_path, '- uses: ./../outside')
    report = Analyzer(tmp_path).scan()
    assert any('escapes' in d['message'] for d in report.diagnostics)


def test_unresolved_output_is_visible(tmp_path):
    workflow(tmp_path, '- run: echo "${{ needs.build.outputs.text }}"')
    assert any('output' in d['message'] for d in Analyzer(tmp_path).scan().diagnostics)


def test_html_escaping_and_sarif_paths(tmp_path):
    workflow(tmp_path, '- uses: "evil/<script>alert(1)</script>@main"')
    report = Analyzer(tmp_path).scan()
    rendered = html_report(report)
    assert '<script>alert(1)</script>' not in rendered
    assert '&lt;script&gt;' in rendered
    data = sarif(report)
    assert data['version'] == '2.1.0'
    assert data['runs'][0]['results'][0]['codeFlows']
    assert data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'] == 6


def test_fingerprints_stable_after_blank_line(tmp_path):
    path = workflow(tmp_path, '- run: echo "${{ github.head_ref }}"')
    before = Analyzer(tmp_path).scan().findings[0].fingerprint
    path.write_text('\n' + path.read_text())
    assert Analyzer(tmp_path).scan().findings[0].fingerprint == before


def test_cli_exit_codes_and_json(tmp_path, capsys):
    workflow(tmp_path, '- run: echo "${{ github.head_ref }}"')
    assert main([str(tmp_path), '--format', 'json']) == 1
    assert json.loads(capsys.readouterr().out)['schema_version'] == 1
    assert main([str(tmp_path), '--fail-on', 'none']) == 0
    assert main([str(tmp_path / 'missing')]) == 2


def test_empty_and_strict(tmp_path):
    assert main([str(tmp_path)]) == 2
    workflow(tmp_path, '- run: echo "${{ steps.a.outputs.b }}"')
    assert main([str(tmp_path), '--strict']) == 2


def test_prevent_yaml_overwrite(tmp_path):
    path = workflow(tmp_path, '- run: echo hello')
    before = path.read_bytes()
    assert main([str(tmp_path), '--output', str(path)]) == 2
    assert path.read_bytes() == before


def test_expression_string_literal_is_skipped():
    assert references("format('github.head_ref', github['head_ref'])") == ['github.head_ref']


@pytest.mark.parametrize('trigger', ['[{bad: value}]', '[]', ''])
def test_invalid_trigger_does_not_crash(tmp_path, trigger):
    workflow(tmp_path, '- run: echo hello', header=f'on: {trigger}')
    assert any(d['level'] == 'error' for d in Analyzer(tmp_path).scan().diagnostics)


def test_oversized_yaml(tmp_path):
    write(tmp_path, '.github/workflows/ci.yml', '#' + 'x' * 1_000_001)
    report = Analyzer(tmp_path).scan()
    assert any('1 MB' in d['message'] for d in report.diagnostics)


def test_nested_local_action_propagation(tmp_path):
    workflow(tmp_path, '- uses: ./outer\n  with:\n    value: ${{ github.head_ref }}')
    write(tmp_path, 'outer/action.yml', '''
    inputs:
      value: {}
    runs:
      using: composite
      steps:
        - uses: ./inner
          with:
            text: ${{ inputs.value }}
    ''')
    write(tmp_path, 'inner/action.yml', '''
    inputs:
      text: {}
    runs:
      using: composite
      steps:
        - shell: bash
          run: echo "${{ inputs.text }}"
    ''')
    report = Analyzer(tmp_path).scan()
    assert len(report.findings) == 1
    assert report.findings[0].path == 'inner/action.yml'
    assert sum('Passed to' in node.message for node in report.findings[0].trace) == 2


def test_composite_fingerprint_portable(tmp_path):
    import shutil
    first = tmp_path / 'first'
    workflow(first, '- uses: ./action\n  with:\n    text: ${{ github.head_ref }}')
    write(first, 'action/action.yml', 'inputs:\n  text: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo "${{ inputs.text }}"')
    second = tmp_path / 'second'
    shutil.copytree(first, second)
    assert Analyzer(first).scan().findings[0].fingerprint == Analyzer(second).scan().findings[0].fingerprint


def test_separate_composite_calls_have_distinct_identity(tmp_path):
    workflow(tmp_path, '- uses: ./action\n  with:\n    text: ${{ github.head_ref }}\n- uses: ./action\n  with:\n    text: ${{ github.head_ref }}')
    write(tmp_path, 'action/action.yml', 'inputs:\n  text: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo "${{ inputs.text }}"')
    findings = Analyzer(tmp_path).scan().findings
    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 2


def test_checkout_in_other_job_does_not_taint(tmp_path):
    write(tmp_path, '.github/workflows/ci.yml', f'''
    on: pull_request_target
    jobs:
      checkout:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
            with:
              ref: ${{{{ github.event.pull_request.head.sha }}}}
      test:
        runs-on: ubuntu-latest
        steps:
          - run: npm test
    ''')
    assert 'AT002' not in rules(tmp_path)


def test_reusable_call_diagnostic(tmp_path):
    write(tmp_path, '.github/workflows/ci.yml', 'on: push\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml')
    assert any('not expanded' in d['message'] for d in Analyzer(tmp_path).scan().diagnostics)


def test_deep_env_bindings_report_incomplete(tmp_path):
    bindings = '\n'.join('  A' + str(i) + ': ${{ env.A' + str(i + 1) + ' }}' for i in range(100))
    workflow(tmp_path, '- run: echo "${{ env.A0 }}"', header='on: push\nenv:\n' + bindings)
    assert any('depth' in d['message'] for d in Analyzer(tmp_path).scan().diagnostics)
