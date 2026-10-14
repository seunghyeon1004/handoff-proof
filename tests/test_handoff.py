import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from handoff.core import scan_source, validate_analysis, make_plan, verify_bundle
from handoff.model import decode_analysis_response, LocalOnlyRedirect


ROOT = Path(__file__).resolve().parents[1]


class HandoffTests(unittest.TestCase):
    def test_scan_omits_suspect_and_hidden_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'main.py').write_text('print("ok")\n')
            (root / 'private.py').write_text('API_KEY = "a-long-secret-value"\n')
            (root / '.env').write_text('PASSWORD=abc\n')
            (root / 'photo.jpg').write_bytes(b'personal photo')
            result = scan_source(root)
            self.assertEqual(list(result['files']), ['main.py'])
            self.assertEqual(len(result['skipped']), 3)
            self.assertNotIn('private.py', str(result['skipped']))
            self.assertNotIn('.env', str(result['skipped']))

    def test_scan_omits_token_inside_ordinary_source_and_rejects_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'ordinary.py').write_text('print("sk-exampletoken123456")\n')
            (root / 'large.py').write_text('x' * 9000)
            inventory = scan_source(root)
            self.assertNotIn('ordinary.py', inventory['files'])
            self.assertNotIn('large.py', inventory['files'])
            self.assertIn('ordinary.py', inventory['skipped'])
            self.assertIn('large.py', inventory['skipped'])

    def test_scan_enforces_file_count(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            for i in range(25): (source / f'm{i}.py').write_text('pass\n')
            with self.assertRaises(ValueError): scan_source(source)

    def test_scan_enforces_link_boundary_when_windows_allows_links(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            outside = root / 'outside.py'; outside.write_text('print("outside")\n')
            try:
                (source / 'link.py').symlink_to(outside)
            except OSError:
                self.skipTest('Windows symlink creation is unavailable')
            self.assertIn('link.py', scan_source(source)['skipped'])
            linked_root = root / 'linked_root'
            linked_root.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError): scan_source(linked_root)

    def test_secret_content_never_reaches_model_prompt_or_plan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("safe")\n')
            (source / 'ordinary.py').write_text('print("sk-exampletoken123456")\n')
            prompts = []
            def model(prompt):
                prompts.append(prompt)
                return {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': 'print("safe")'}], 'dependencies': [], 'env_names': [], 'notes': ''}
            plan = make_plan(source, 'run', root / 'plan.json', model)
            self.assertNotIn('sk-exampletoken123456', prompts[0])
            self.assertNotIn('sk-exampletoken123456', json.dumps(plan))
            self.assertNotIn('ordinary.py', plan['hashes'])

    def test_model_invalid_json_is_an_error(self):
        with self.assertRaises(ValueError): decode_analysis_response('{not json')
        with self.assertRaises(ValueError): decode_analysis_response('[]')

    def test_local_model_refuses_redirects(self):
        with self.assertRaises(ValueError):
            LocalOnlyRedirect().redirect_request(None, None, 302, 'moved', {}, 'https://example.com')

    def test_changed_source_invalidates_approval(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'source'; source.mkdir()
            file = source / 'main.py'; file.write_text('print("one")\n')
            plan_path = Path(td) / 'plan.json'
            plan = make_plan(source, 'run', plan_path, lambda _: {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': 'print("one")'}], 'dependencies': [], 'env_names': [], 'notes': ''})
            file.write_text('print("two")\n')
            with self.assertRaises(ValueError): verify_bundle(plan_path, plan['fingerprint'], Path(td) / 'bundle')

    def test_zero_exit_with_wrong_output_is_not_passed(self):
        with tempfile.TemporaryDirectory() as td:
            source = ROOT / 'samples' / 'hello'
            plan_path = Path(td) / 'plan.json'
            plan = make_plan(source, 'Print WRONG_MARKER', plan_path, lambda _: {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': "print('HANDOFF_OK')"}], 'dependencies': [], 'env_names': [], 'notes': ''}, expect_stdout_line='WRONG_MARKER')
            result = verify_bundle(plan_path, plan['fingerprint'], Path(td) / 'bundle')
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['status'], 'failed')

    def test_plan_rejects_fabricated_evidence_and_unsafe_entry(self):
        source = scan_source(ROOT / 'samples' / 'hello')
        valid = {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': "print('HANDOFF_OK')"}], 'dependencies': [], 'env_names': [], 'notes': 'Prints marker'}
        self.assertEqual(validate_analysis(valid, source)['entry'], 'main.py')
        bad = dict(valid, evidence=[{'path': 'main.py', 'line': 9, 'text': 'made up'}])
        with self.assertRaises(ValueError): validate_analysis(bad, source)
        with self.assertRaises(ValueError): validate_analysis(dict(valid, entry='../other.py'), source)
        with self.assertRaises(ValueError): validate_analysis(dict(valid, argv=['-c', 'print(1)']), source)
        self.assertEqual(validate_analysis(dict(valid, dependencies=['pathlib']), source)['dependencies'], [])

    def test_approval_and_generic_execution_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / 'source'; source.mkdir()
            (source / 'main.py').write_text('print("NOT_EXECUTED")\n')
            plan_file = root / 'plan.json'
            make_plan(source, 'print marker', plan_file, lambda _: {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': 'print("NOT_EXECUTED")'}], 'dependencies': [], 'env_names': [], 'notes': ''})
            with self.assertRaises(ValueError): verify_bundle(plan_file, 'bad', root / 'bundle')
            plan = json.loads(plan_file.read_text())
            with self.assertRaises(PermissionError): verify_bundle(plan_file, plan['fingerprint'], root / 'bundle')

    def test_output_inside_source_is_rejected_and_original_bytes_kept(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / 'source'; source.mkdir()
            raw = b'print("ok")\r\n'
            (source / 'main.py').write_bytes(raw)
            response = lambda _: {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': 'print("ok")'}], 'dependencies': [], 'env_names': [], 'notes': ''}
            with self.assertRaises(ValueError): make_plan(source, 'run', source / 'output' / 'plan.json', response)
            plan = make_plan(source, 'run', root / 'plan.json', response)
            self.assertEqual(plan['hashes']['main.py'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(plan['execution'], {'command': ['python', '-B', 'main.py'], 'cwd': 'bundle/source', 'environment_changes': [], 'dependency_install': 'disabled'})

    def test_three_owned_samples_report_truth_and_manifest(self):
        for name, expected in [('hello', 'passed'), ('resource_ok', 'passed'), ('config_ok', 'passed'),
                               ('missing_file', 'failed'), ('bad_dependency', 'failed'), ('config_bad', 'failed')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                source = ROOT / 'samples' / name
                line = (source / 'main.py').read_text().splitlines()[0]
                plan_file = Path(td) / 'plan.json'
                marker = {'hello': 'HANDOFF_OK', 'resource_ok': 'RESOURCE_OK', 'config_ok': 'CONFIG_OK',
                          'missing_file': 'RESOURCE_OK', 'bad_dependency': 'never', 'config_bad': 'CONFIG_OK'}[name]
                make_plan(source, f'Print {marker}', plan_file, lambda _, line=line: {'entry': 'main.py', 'argv': [], 'evidence': [{'path': 'main.py', 'line': 1, 'text': line}], 'dependencies': [], 'env_names': [], 'notes': ''}, expect_stdout_line=marker)
                approval = json.loads(plan_file.read_text())['fingerprint']
                bundle = Path(td) / 'bundle'
                result = verify_bundle(plan_file, approval, bundle)
                self.assertEqual(result['status'], expected)
                self.assertTrue(result['final_bundle_reproduced'])
                self.assertTrue((bundle / 'source' / 'main.py').is_file())
                self.assertTrue((bundle / 'RUNME.md').is_file())
                self.assertIn('cd source', (bundle / 'RUNME.md').read_text(encoding='utf-8'))
                self.assertTrue((bundle / 'dependencies.json').is_file())
                manifest = json.loads((bundle / 'sha256.json').read_text())
                for rel, digest in manifest.items():
                    self.assertEqual(hashlib.sha256((bundle / rel).read_bytes()).hexdigest(), digest)
                self.assertTrue(result['ran_from_bundle_copy'])
                self.assertEqual(result['executed_source_sha256'], manifest['source/main.py'])
                if expected == 'passed': self.assertEqual(result['returncode'], 0)
                else: self.assertNotEqual(result['returncode'], 0)
                if name == 'hello': self.assertIn('HANDOFF_OK', result['stdout'])
                if name == 'resource_ok': self.assertIn('RESOURCE_OK', result['stdout'])
                if name == 'config_ok': self.assertIn('CONFIG_OK', result['stdout'])
                self.assertNotIn('C:\\Users\\', result['stderr'])


if __name__ == '__main__': unittest.main()
