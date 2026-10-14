"""Artifact checks use an independently specified HTML value, not stdout."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from handoff.core import make_plan, verify_bundle, scan_source, validate_analysis


ROOT = Path(__file__).resolve().parents[1]
ARGS = ['--input', 'data.csv', '--config', 'config.json', '--template', 'template.html',
        '--output', '../../generated/report.html']
EXPECTED_HTML = ('<html><h1>October synthetic spending</h1><ul>'
                 '<li>Groceries: 1200 KRW</li><li>Transport: 800 KRW</li>'
                 '<li>Books: 500 KRW</li></ul><p>Total: 2500 KRW</p></html>\n')
EXPECTED_SHA = hashlib.sha256(EXPECTED_HTML.encode('utf-8')).hexdigest()
REORDERED_HTML = ('<html><h1>October synthetic spending</h1><ul>'
                  '<li>Books: 500 KRW</li><li>Groceries: 1200 KRW</li>'
                  '<li>Transport: 800 KRW</li></ul><p>Total: 2500 KRW</p></html>\n')
ADDED_HTML = ('<html><h1>October synthetic spending</h1><ul>'
              '<li>Groceries: 1200 KRW</li><li>Transport: 800 KRW</li>'
              '<li>Books: 500 KRW</li><li>Stationery: 300 KRW</li>'
              '</ul><p>Total: 2800 KRW</p></html>\n')


def mock_analysis(_prompt):
    return {'entry': 'main.py', 'argv': [],
            'evidence': [{'path': 'main.py', 'line': 1, 'text': 'from argparse import ArgumentParser'}],
            'dependencies': [], 'env_names': [], 'notes': ''}


class ReportFlowTests(unittest.TestCase):
    def test_calculation_bug_uses_same_input_but_wrong_total(self):
        normal = ROOT / 'samples' / 'report_ok'
        broken = ROOT / 'samples' / 'report_calc_bug'
        for name in ('data.csv', 'config.json', 'template.html', 'main.py'):
            self.assertEqual((broken / name).read_bytes(), (normal / name).read_bytes())
        self.assertNotEqual((broken / 'report.py').read_bytes(), (normal / 'report.py').read_bytes())
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            plan = make_plan(broken, 'Create expected synthetic report', base / 'plan.json',
                             mock_analysis, run_args=ARGS, expect_artifact_sha256=EXPECTED_SHA)
            result = verify_bundle(base / 'plan.json', plan['fingerprint'], base / 'bundle')
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(result['final_bundle_reproduced'])
            actual = (base / 'bundle' / 'output' / 'report.html').read_text(encoding='utf-8')
            self.assertIn('<p>Total: 2501 KRW</p>', actual)
            self.assertIn('<p>Total: 2500 KRW</p>', EXPECTED_HTML)
            self.assertNotEqual(result['actual_artifact_sha256'], EXPECTED_SHA)

    def test_invalid_model_entry_gets_one_grounded_retry(self):
        with tempfile.TemporaryDirectory() as td:
            responses = [dict(mock_analysis(''), entry='__main__.main'), mock_analysis('')]
            prompts = []
            def model(prompt):
                prompts.append(prompt)
                return responses.pop(0)
            plan = make_plan(ROOT / 'samples' / 'report_missing', 'Create report',
                             Path(td) / 'plan.json', model, run_args=ARGS,
                             expect_artifact_sha256=EXPECTED_SHA)
            self.assertEqual(len(prompts), 2)
            self.assertIn('allowed_entries', prompts[1])
            self.assertEqual(plan['analysis_attempts'], 2)
            self.assertEqual(plan['model_rejections'],
                             ['Model entry is not an included Python source file'])

    def test_cited_first_line_is_kept_when_model_appends_another_line(self):
        inventory = scan_source(ROOT / 'samples' / 'report_ok')
        response = mock_analysis('')
        response['evidence'] = [{'path': 'main.py', 'line': 21,
                                 'text': "if __name__ == '__main__':\n21:     main()"}]
        checked = validate_analysis(response, inventory)
        self.assertEqual(checked['evidence'][0]['text'], "if __name__ == '__main__':")

    def test_report_artifact_and_three_defects(self):
        for name, status, code, expected_html in [
            ('report_ok', 'passed', 0, EXPECTED_HTML),
            ('report_missing', 'failed', 1, EXPECTED_HTML),
            ('report_config_bad', 'failed', 1, EXPECTED_HTML),
            ('report_wrong_total', 'failed', 0, EXPECTED_HTML),
            ('report_reordered', 'passed', 0, REORDERED_HTML),
            ('report_added', 'passed', 0, ADDED_HTML),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                source = ROOT / 'samples' / name
                plan_file = base / 'plan.json'
                plan = make_plan(source, 'Create the expected synthetic HTML spending report', plan_file,
                                 mock_analysis, run_args=ARGS,
                                 expect_artifact_sha256=hashlib.sha256(expected_html.encode('utf-8')).hexdigest())
                self.assertEqual(plan['execution']['command'][3:], ARGS)
                result = verify_bundle(plan_file, plan['fingerprint'], base / 'bundle',
                                       explain=lambda _failure: 'called for error log')
                self.assertEqual(result['status'], status)
                self.assertEqual(result['returncode'], code)
                self.assertEqual(result['approved_artifact_sha256'],
                                 hashlib.sha256(expected_html.encode('utf-8')).hexdigest())
                if name == 'report_wrong_total':
                    self.assertIsNone(result['model_explanation'])
                self.assertTrue(result['final_bundle_reproduced'])
                evidence = json.loads((base / 'bundle.verification.json').read_text(encoding='utf-8'))
                self.assertEqual(evidence['finalized_bundle_reproduction'], 'reproduced')
                output = base / 'bundle' / 'output' / 'report.html'
                if status == 'passed':
                    self.assertEqual(output.read_text(encoding='utf-8'), expected_html)
                elif name == 'report_wrong_total':
                    self.assertTrue(output.exists())
                    self.assertNotEqual(hashlib.sha256(output.read_bytes()).hexdigest(), EXPECTED_SHA)
                else:
                    self.assertFalse(output.exists())

    def test_unreviewed_arguments_and_generic_source_stay_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = ROOT / 'samples' / 'report_ok'
            plan_file = base / 'plan.json'
            plan = make_plan(source, 'Create report', plan_file, mock_analysis,
                             run_args=ARGS[:-1] + ['../../elsewhere/report.html'],
                             expect_artifact_sha256=EXPECTED_SHA)
            with self.assertRaises(PermissionError):
                verify_bundle(plan_file, plan['fingerprint'], base / 'bundle')


if __name__ == '__main__':
    unittest.main()
