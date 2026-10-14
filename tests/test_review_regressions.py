"""Regression probes from the independent safety review. No live model calls."""

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

from handoff import core


ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_AWS = 'AKIA' + 'A' * 16


def response(line):
    return {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': line}],
            'dependencies': [], 'env_names': [], 'notes': ''}


class ReviewRegressionTests(unittest.TestCase):
    def test_hash_uses_the_exact_bytes_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td); file = source / 'main.py'
            file.write_bytes(b'print("first")\n')
            original_read = Path.read_bytes
            reads = 0
            def read(path):
                nonlocal reads
                if path == file:
                    reads += 1
                    return b'print("first")\n' if reads == 1 else b'print("second")\n'
                return original_read(path)
            with patch.object(Path, 'read_bytes', read):
                inventory = core.scan_source(source)
            self.assertEqual(inventory['hashes']['main.py'], hashlib.sha256(inventory['files']['main.py'].encode()).hexdigest())
            self.assertEqual(reads, 1)

    def test_source_change_during_model_call_aborts_plan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            file = source / 'main.py'; file.write_text('print("first")\n')
            out = root / 'plan.json'
            def model(_):
                file.write_text('print("second")\n')
                return response('print("first")')
            with self.assertRaises(ValueError): core.make_plan(source, 'Print first', out, model)
            self.assertFalse(out.exists())

    def test_plan_creation_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            out = root / 'plan.json'; out.write_text('KEEP ME')
            with self.assertRaises(FileExistsError):
                core.make_plan(source, 'Print ok', out, lambda _: response('print("ok")'))
            self.assertEqual(out.read_text(), 'KEEP ME')

    def test_output_path_redirect_into_source_during_model_call_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            out = root / 'output' / 'plan.json'
            original_resolve = Path.resolve
            redirected = False
            def resolve(path, *args, **kwargs):
                if path == out and redirected:
                    return source / 'plan.json'
                return original_resolve(path, *args, **kwargs)
            def model(_):
                nonlocal redirected
                redirected = True
                return response('print("ok")')
            with patch.object(Path, 'resolve', resolve):
                with self.assertRaises(ValueError): core.make_plan(source, 'Print ok', out, model)
            self.assertFalse(out.exists())

    def test_synthetic_secret_stays_out_of_model_and_plan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            (source / 'other.py').write_text(f'print("{SYNTHETIC_AWS}")\n')
            (source / f'{SYNTHETIC_AWS}.py').write_text('pass\n')
            prompts = []
            plan = core.make_plan(source, 'Print ok', root / 'plan.json', lambda prompt: prompts.append(prompt) or response('print("ok")'))
            self.assertFalse(SYNTHETIC_AWS in prompts[0])
            self.assertFalse(SYNTHETIC_AWS in json.dumps(plan))
            self.assertFalse(SYNTHETIC_AWS in (root / 'plan.json').read_text())

    def test_secret_goal_is_blocked_before_model_call(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            calls = []
            with self.assertRaises(ValueError):
                core.make_plan(source, f'Print {SYNTHETIC_AWS}', root / 'plan.json', lambda prompt: calls.append(prompt))
            self.assertEqual(len(calls), 0)

    def test_secret_model_response_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            answer = response('print("ok")'); answer['notes'] = SYNTHETIC_AWS
            with self.assertRaises(ValueError): core.make_plan(source, 'Print ok', root / 'plan.json', lambda _: answer)
            self.assertFalse((root / 'plan.json').exists())

    def test_original_hashes_recorded_before_and_after_validation(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            result = core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / '한글 space # bundle')
            self.assertTrue(result['selected_source_files_preserved'])
            self.assertEqual(result['selected_source_hashes_before'], result['selected_source_hashes_after'])
            self.assertEqual(result['selected_source_hashes_before'], plan['hashes'])

    def test_finalized_bundle_copy_replays_with_external_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            bundle = Path(td) / 'bundle'
            real_run = subprocess.run
            executions = []
            def run(command, *args, **kwargs):
                if not ('-m' in command and 'venv' in command):
                    executions.append(command)
                return real_run(command, *args, **kwargs)
            with patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_file, plan['fingerprint'], bundle)
            self.assertEqual(len(executions), 2)
            evidence_path = Path(td) / 'bundle.verification.json'
            self.assertTrue(evidence_path.is_file())
            evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
            self.assertEqual(evidence['finalized_bundle_reproduction'], 'reproduced')
            self.assertTrue(evidence['final_bundle_files_unchanged'])
            self.assertTrue(evidence['selected_source_files_preserved_after_replay'])
            self.assertTrue(result['final_bundle_reproduced'])
            manifest = json.loads((bundle / 'sha256.json').read_text(encoding='utf-8'))
            for rel, sha in manifest.items():
                self.assertEqual(hashlib.sha256((bundle / rel).read_bytes()).hexdigest(), sha)
            self.assertEqual(hashlib.sha256((bundle / 'sha256.json').read_bytes()).hexdigest(), evidence['final_bundle_manifest_sha256'])

    def test_near_match_stdout_is_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            real_run = subprocess.run
            def run(command, *args, **kwargs):
                if '-m' in command and 'venv' in command:
                    return real_run(command, *args, **kwargs)
                return subprocess.CompletedProcess(command, 0, stdout='NOT_HANDOFF_OK\n', stderr='')
            with patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / 'bundle')
            self.assertNotEqual(result['status'], 'passed')

    def test_suspected_secret_in_stdout_is_not_exposed_or_sent_to_model(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            real_run = subprocess.run
            def run(command, *args, **kwargs):
                if '-m' in command and 'venv' in command:
                    return real_run(command, *args, **kwargs)
                return subprocess.CompletedProcess(command, 0, stdout='HANDOFF_OK\n' + SYNTHETIC_AWS, stderr='')
            explanations = []
            with patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / 'bundle', explanations.append)
            self.assertNotEqual(result['status'], 'passed')
            self.assertFalse(SYNTHETIC_AWS in json.dumps(result))
            self.assertFalse(SYNTHETIC_AWS in (Path(td) / 'bundle' / 'result.json').read_text())
            self.assertEqual(len(explanations), 0)

    def test_secret_crossing_output_limit_is_fully_withheld(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            real_run = subprocess.run
            def run(command, *args, **kwargs):
                if '-m' in command and 'venv' in command:
                    return real_run(command, *args, **kwargs)
                return subprocess.CompletedProcess(command, 0, stdout='X' * 3998 + SYNTHETIC_AWS, stderr='')
            with patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / 'bundle')
            self.assertEqual(result['stdout'], '<redacted: suspected secret in process output>')

    def test_change_after_bundle_copy_blocks_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'samples' / 'hello'; source.mkdir(parents=True)
            file = source / 'main.py'; file.write_bytes(b'print("safe")\n')
            plan_path = root / 'plan.json'
            plan = core.make_plan(source, 'Print safe', plan_path, lambda _: response('print("safe")'), expect_stdout_line='safe')
            real_copy = core.shutil.copytree
            def copied(src, dst, *args, **kwargs):
                result = real_copy(src, dst, *args, **kwargs)
                file.write_text('print("changed")\n')
                return result
            trusted = {'hello': {'main.py': hashlib.sha256(b'print("safe")\n').hexdigest()}}
            with patch.object(core, 'ROOT', root), patch.dict(core.TRUSTED_SAMPLES, trusted, clear=True), patch.object(core.shutil, 'copytree', copied):
                with self.assertRaises(ValueError):
                    core.verify_bundle(plan_path, plan['fingerprint'], root / 'bundle')

    def test_source_mutation_during_run_is_recorded_as_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'samples' / 'hello'; source.mkdir(parents=True)
            file = source / 'main.py'; file.write_bytes(b'print("safe")\n')
            plan_path = root / 'plan.json'
            plan = core.make_plan(source, 'Print safe', plan_path, lambda _: response('print("safe")'), expect_stdout_line='safe')
            real_run = subprocess.run
            def run(command, *args, **kwargs):
                result = real_run(command, *args, **kwargs)
                if not ('-m' in command and 'venv' in command):
                    file.write_text('print("changed")\n')
                return result
            trusted = {'hello': {'main.py': hashlib.sha256(b'print("safe")\n').hexdigest()}}
            with patch.object(core, 'ROOT', root), patch.dict(core.TRUSTED_SAMPLES, trusted, clear=True), patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_path, plan['fingerprint'], root / 'bundle')
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['selected_source_files_preserved'])
            self.assertNotEqual(result['selected_source_hashes_before'], result['selected_source_hashes_after'])

    def test_unicode_and_punctuation_in_source_and_bundle_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / '한글 space # root'; source = root / 'samples' / 'hello'; source.mkdir(parents=True)
            file = source / 'main.py'; file.write_bytes(b'print("safe")\n')
            plan_path = root / '계획 파일 #.json'
            plan = core.make_plan(source, 'Print safe', plan_path, lambda _: response('print("safe")'), expect_stdout_line='safe')
            trusted = {'hello': {'main.py': hashlib.sha256(b'print("safe")\n').hexdigest()}}
            with patch.object(core, 'ROOT', root), patch.dict(core.TRUSTED_SAMPLES, trusted, clear=True):
                result = core.verify_bundle(plan_path, plan['fingerprint'], root / '꾸러미 # space')
            self.assertEqual(result['status'], 'passed')

    def test_unsupported_behavior_is_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Show a greeting', plan_file, lambda _: response("print('HANDOFF_OK')"))
            self.assertEqual(plan['assertion'], {'type': 'unverified'})
            self.assertIn('provided response', plan['model'])
            result = core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / 'bundle')
            self.assertEqual(result['status'], 'unverified')

    def test_source_root_link_swap_is_rejected_with_simulated_link(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'; plan_file = Path(td) / 'plan.json'
            plan = core.make_plan(source, 'Print HANDOFF_OK', plan_file, lambda _: response("print('HANDOFF_OK')"), expect_stdout_line='HANDOFF_OK')
            original = Path.is_symlink
            def swapped(path):
                return path == source or original(path)
            with patch.object(Path, 'is_symlink', swapped):
                with self.assertRaises(ValueError):
                    core.verify_bundle(plan_file, plan['fingerprint'], Path(td) / 'bundle')

    def test_same_bytes_replacement_during_run_is_not_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'samples' / 'hello'; source.mkdir(parents=True)
            file = source / 'main.py'; raw = b'print("safe")\n'; file.write_bytes(raw)
            plan_path = root / 'plan.json'
            plan = core.make_plan(source, 'Print safe', plan_path, lambda _: response('print("safe")'), expect_stdout_line='safe')
            real_run = subprocess.run
            def run(command, *args, **kwargs):
                result = real_run(command, *args, **kwargs)
                if not ('-m' in command and 'venv' in command):
                    file.unlink(); file.write_bytes(raw)
                return result
            trusted = {'hello': {'main.py': hashlib.sha256(raw).hexdigest()}}
            with patch.object(core, 'ROOT', root), patch.dict(core.TRUSTED_SAMPLES, trusted, clear=True), patch.object(core.subprocess, 'run', run):
                result = core.verify_bundle(plan_path, plan['fingerprint'], root / 'bundle')
            self.assertEqual(result['selected_source_hashes_before'], result['selected_source_hashes_after'])
            self.assertFalse(result['selected_source_files_preserved'])
            self.assertEqual(result['status'], 'failed')

    def test_cli_shows_included_files_and_exact_assertion_for_review(self):
        from handoff import __main__ as cli
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("ok")\n')
            class MockModel:
                provenance = 'mock fixture; no live model call'
                def __call__(self, prompt): return response('print("ok")')
            output = io.StringIO()
            with patch.object(cli, 'OllamaModel', MockModel), redirect_stdout(output):
                code = cli.main(['analyze', str(source), '--goal', 'Print ok', '--expect-stdout-line', 'ok',
                                 '--out', str(Path(td) / 'plan.json')])
            self.assertEqual(code, 0)
            review = json.loads(output.getvalue())
            self.assertEqual(review['assertion_to_review'], {'type': 'stdout_equals', 'value': 'ok\n'})
            self.assertIn('main.py', review['included_files_to_review'])
            self.assertEqual(review['execution_to_review']['dependency_install'], 'disabled')


if __name__ == '__main__':
    unittest.main()
