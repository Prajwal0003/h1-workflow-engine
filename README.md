# H1 Workflow Engine

A Python CLI for organizing authorized HackerOne research. It can retrieve program scope, run reconnaissance, and group scan candidates by endpoint and vulnerability family. The regression suite shows how the engine decides whether a result has enough evidence for reporting.

## Try the evidence checks

Use Python 3.11 or 3.12. From a fresh checkout, create an isolated environment and install the Python dependencies:

```sh
git clone https://github.com/Prajwal0003/h1-workflow-engine.git
cd h1-workflow-engine
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux or macOS, or `.\.venv\Scripts\Activate.ps1` in Windows PowerShell. Then run:

```sh
python -m pip install -r requirements.txt
python h1_workflow.py --help
python -m unittest discover -s tests -v
```

The regression tests use synthetic inputs and mocked responses. They need no target, account credentials, external scanner binaries or browser installation. For example, the SQL timing tests compare repeated injected requests against control requests. An unstable baseline leaves the result in the review queue. The report gate also rejects an AI-generated success marker as independent evidence.

## Project map

| Entry point | Purpose |
| --- | --- |
| [h1_workflow.py](h1_workflow.py) | Program search, scope, disclosed reports, reconnaissance and dashboard commands |
| [modules/finding_quality.py](modules/finding_quality.py) | Deduplication, evidence checks and readiness decisions |
| [tests/test_precision_controls.py](tests/test_precision_controls.py) | Reproducible examples of evidence thresholds and false positives |
| [autopilot.py](autopilot.py) | Active scanning and local review output for explicitly authorized targets |

For live work, first verify the program's current scope, allowed techniques and rate limits. External tools and credentials are optional for the offline path above. Setup scripts download additional tools. Review those scripts and upstream rights before running them. Keep authenticated sessions, real target evidence and logs outside Git and shared build artifacts.

See [maintenance and validation](docs/MAINTENANCE.md) for CI, credential handling and release status. The [MIT license](LICENSE) covers the maintainer's original work. [Third-party notices and exceptions](THIRD_PARTY.md) describe the limits of that grant.
