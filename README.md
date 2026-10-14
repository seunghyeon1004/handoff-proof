# Handoff Proof

**Handoff Proof** is a small, local Python CLI prototype for preparing a reviewable handoff of another Python CLI project. It was started on October 14, 2026 for the DEV Hacktoberfest Open-Source AI Challenge Week 2: Side Hustle.

A local open-weight Qwen model reads selected source files and proposes a Python entry file with cited source lines and inferred dependencies. A human reviews the exact included file hashes, command, arguments, and expected result before typing a plan fingerprint to approve validation. The verifier copies the owned sample into a fresh directory and venv, runs it, checks the real result, assembles a delivery bundle, then runs a copy of that finalized bundle again. A failed program or wrong generated artifact remains **failed**, even when the process exits 0.

This is a prototype of a possible paid handoff review service for small AI-app builders and freelancers. No customer, sale, pricing test, or production deployment is claimed.

## Requirements

- Windows and Python 3.12. The application itself uses only the Python standard library.
- Locally running [Ollama](https://github.com/ollama/ollama) with the `qwen2.5:14b` model available at `127.0.0.1:11434`. The model is **not bundled**; it occupied about 9.3 GB while loaded in our test. Allow enough disk space, RAM, and CPU time. This project does not automatically download or install the model.
- No cloud AI key. The model adapter has no cloud fallback and rejects redirects.

Model/license sources: [Qwen2.5-14B-Instruct model card (Apache-2.0)](https://huggingface.co/Qwen/Qwen2.5-14B-Instruct), [Ollama license (MIT)](https://github.com/ollama/ollama/blob/main/LICENSE). This project's MIT license applies to its original code, not to downloaded model weights or the Ollama runtime.

## Reproduce an owned sample with manual plan review

Run the commands from this folder. The expected SHA-256 values below come from independent expected HTML strings in `tests/test_report_flow.py`; they were not copied from the program's first output. Choose fresh names for each plan and bundle because the CLI refuses to overwrite them.

```powershell
python -m unittest discover -s tests -v

python -m handoff analyze samples\report_ok --goal "Generate a synthetic spending HTML report" --run-arg=--input --run-arg=data.csv --run-arg=--config --run-arg=config.json --run-arg=--template --run-arg=template.html --run-arg=--output --run-arg=../../generated/report.html --expect-artifact-sha256=1348a60f88a9cbeda949ab477ad832d69058e97b01473ae1fe0c033a9b0548dc --out normal.plan.json
```

Read `normal.plan.json` and the displayed file hashes, evidence, and command. Copy **its displayed fingerprint** into the next command:

```powershell
python -m handoff verify normal.plan.json --approve <fingerprint-from-this-plan> --out normal.bundle
```

Repeat with `samples\report_calc_bug`, a new `bug.plan.json`, and `bug.bundle`, keeping the same reviewed arguments and expected SHA-256. The two samples have identical CSV, config, template, and entry script. Only the calculation module differs: the synthetic bug adds one to the total. The normal CSV totals **2500 KRW**; the defective program emits **2501 KRW** with exit code 0. `verify` reports `failed` because the HTML hash differs. The verifier CLI itself exits 1 for that intentional failure.

Each bundle contains copied source, `RUNME.md`, `dependencies.json`, `result.json`, `sha256.json`, and a generated `output/report.html` when available. A sibling `<bundle>.verification.json` records the replay of a copy of the **finalized** bundle. Read both the result and replay evidence before sharing a handoff.

## Saved evidence

The `evidence/` folder contains path-free summaries of the seven real local-Qwen report cases, an independent same-PC replay audit, and the actual normal and defective HTML artifacts. In the corrected audit, the normal case had input/output totals of 2500/2500 KRW; the calculation-defect case had 2500/2501 KRW. Both processes exited 0; only the normal case passed. The earlier `report_wrong_total` case had a CSV that itself totaled 2501 KRW, so it demonstrates an **input/approved-expectation mismatch**, not a calculation bug. See [validation details](docs/VALIDATION.md).

The saved demo evidence was collected by an automation script that passed each plan fingerprint directly to the verifier. It does not show a person approving those runs. The CLI workflow above has a separate review step where a person can read the plan and type the exact fingerprint into `verify --approve`.

[Watch the 51-second demo](demo/handoff-proof-demo.mp4). It is a rendered explanation of real saved automated runs, not a live terminal recording. The same file is listed in the SHA-256 manifest.

The full local test suite ran 37 tests: 36 passed, one Windows symlink creation test was skipped due to host permissions. Measured local-model analysis on four report cases took 84.76 to 96.79 seconds each on the test machine. A later fresh demo-evidence run measured 203.05 seconds for the normal plan and 110.70 seconds for the calculation-defect plan; its validation steps took 1.51 and 1.52 seconds. Independent finalized-bundle replay took 0.58 to 0.63 seconds per case, including fresh venv creation. These timings are examples, not performance guarantees.

## Safety and scope

- `verify` **rejects arbitrary user-provided source**. Only thirteen newly authored, fully reviewed, hash-pinned synthetic sample variants are executable; the report variants also require one exact argument list. A changed source file or command invalidates approval.
- Fresh folders and Python venvs isolate dependencies but are **not security sandboxes**. There is no verified network, filesystem, process, or OS-level isolation. Do not use this tool to run untrusted projects.
- The file collector applies size and type limits and screens common secret patterns; detection is incomplete. Review every included file and bundle manually before sharing. Environment-variable names can be noted, but values are not included.
- External dependency installation, arbitrary project execution, another-PC reproduction, EXE source recovery, deployment, accounts, payment, and automatic cleanup are outside this prototype.
- Only selected source files are hashed and preserved; that does not prove every file in the original folder was transferred. Model suggestions never become arbitrary shell commands.

## Development and license

Run `python -m unittest discover -s tests -v` after changes. The original Handoff Proof code is released under the MIT license in `LICENSE`, with the copyright notice retained. This repository does not include Qwen model files or Ollama binaries.
