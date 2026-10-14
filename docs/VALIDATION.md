# Validation evidence

This package was prepared on October 14, 2026 from newly authored synthetic code. It includes the original CLI source, owned samples, tests, real local-model result summaries, and an independent replay audit. The raw development plans were left out because they contain host paths.

## What the evidence supports

`evidence/report_cases.json` was extracted from seven `qwen2.5:14b via local Ollama` plans, their resulting bundles, and external finalized-bundle replay records. It includes the cited entry lines, planned command, source hashes, predefined expected and actual artifact hashes, status, exit code, and replay outcome. The model does not decide pass/fail; the predefined assertion and actual execution do.

These evidence runs were automated. The collection script supplied the fingerprint to `verify_bundle`; no person typed approval during those runs. The CLI separately exposes a plan review and `verify --approve` input field.

`evidence/report_independent_replay.json` comes from a separate audit script. It copied finalized bundles to fresh paths, created fresh venvs, ran only the exact hash-pinned synthetic code, independently summed CSV rows, checked all bundle-file and Python-module hashes, and compared output HTML and exit codes. The subprocesses had no `PYTHONPATH` and no original-project path in their command. This remains a **same-PC** test, not a security sandbox or a different-machine test.

`evidence/demo_run.json` records a later fresh execution from this staged code with real local Qwen. The normal plan took 203.05 seconds to analyze and 1.51 seconds to verify; the calculation-defect plan took 110.70 seconds to analyze and 1.52 seconds to verify. Both processes exited 0, but their actual report hashes led to passed and failed verdicts respectively. The companion MP4 is a rendered walkthrough of these saved real results, not a live desktop recording.

| Case | CSV sum | Generated total | Process exit | Handoff Proof status | Interpretation |
| --- | ---: | ---: | ---: | --- | --- |
| `report_ok` | 2500 | 2500 | 0 | passed | Expected HTML matched |
| `report_missing` | no CSV | no HTML | 1 | failed | Required file absent |
| `report_config_bad` | 2500 | no HTML | 1 | failed | Unsupported USD config |
| `report_wrong_total` | 2501 | 2501 | 0 | failed | CSV conflicts with approved 2500 target; **not** a calculation bug |
| `report_calc_bug` | 2500 | 2501 | 0 | failed | Same normal CSV, defective calculation adds 1 |
| `report_reordered` | 2500 | 2500 | 0 | passed | Reordered rows matched their own expected HTML |
| `report_added` | 2800 | 2800 | 0 | passed | Added row matched its own expected HTML |

The initial `report_missing` model response identified `__main__.main` instead of an included file; validation rejected it before execution. A single grounded retry returned the validation error and allowed file paths to the model. The accepted plan records two attempts. The raw initial model response was printed during diagnostics but was not saved as a file; no reconstructed transcript is presented here. Qwen correctly identified the invalid currency cause in `report_config_bad` but suggested checking arguments rather than the JSON file, an imprecise manual instruction.

## Limits

The 37-test suite had 36 passes and one skipped Windows symlink-creation test. Complete secret detection, safe execution of arbitrary Python programs, dependency installation, network isolation, execution on another PC, and non-developer usability have not been validated. Neither the selected-source hashes nor successful replay prove full original-folder coverage.
