# Release verification

Verified locally on Windows with Python 3.12:

- 49 regression tests passed.
- Repository CI workflow: zero findings and zero coverage diagnostics with strict mode.
- Insecure demo: five expected findings, two analyzed files, zero coverage diagnostics.
- Safe demo: zero findings and zero coverage diagnostics.
- Source distribution and wheel built successfully.
- Built wheel smoke test: demo and safe scans passed using the wheel's extracted package, independently of the editable source installation.
- JSON/SARIF serialization, source locations, HTML escaping, and CLI exit behavior tested.

The CI configuration includes Python 3.11, 3.12, and 3.13 on Linux; those remote CI jobs have not yet run.
Browser policy prevented visual inspection of the local HTML report. Automated rendering/escaping tests passed; the interactive filter has not been browser-tested.
No real-repository accuracy benchmark or independent audit has been performed.
This local verification was recorded before the initial GitHub upload. No public Python package has been published.
