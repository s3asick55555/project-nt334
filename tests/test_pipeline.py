from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from malware_analysis.agents import ArtifactInspectorAgent, BytecodeReverserAgent
from malware_analysis.compiler import ReportCompiler
from malware_analysis.orchestrator import AnalysisPipeline
from malware_analysis.router import DataIngestionRouter
from malware_analysis.schemas import ArtifactReport, FinalReport, IOC


class FakeLLMClient:
    def __init__(self) -> None:
        self.json_calls: list[dict[str, object]] = []

    def generate_json(self, *, model, prompt, payload, schema, temperature):
        self.json_calls.append(
            {
                'model': model,
                'prompt': prompt,
                'payload': payload,
                'schema': schema,
                'temperature': temperature,
            }
        )
        if schema is ArtifactReport:
            return ArtifactReport(
                iocs=[
                    IOC(
                        ioc_type='file_path',
                        value='C:/Users/Public/startup.exe',
                        context='Persisted payload path',
                    )
                ],
                suspicious_imports=['winreg', 'subprocess'],
            )

        return FinalReport(
            summary='Synthetic report',
            key_iocs=['C:/Users/Public/startup.exe'],
            behavioral_analysis=[
                'Reads config, copies itself, and schedules execution.',
                'Uses registry-backed startup persistence.',
            ],
            mitre_attack_mapping=['Persistence - T1547.001'],
            overall_capability='Establishes persistence and runs on startup.',
        )


class PipelineTests(unittest.TestCase):
    def _write_report(self, directory: Path, payload: dict[str, object], name: str = 'report.json') -> Path:
        report_path = directory / name
        report_path.write_text(json.dumps(payload), encoding='utf-8')
        return report_path

    def test_router_loads_and_routes_report(self):
        with TemporaryDirectory() as tmp_dir:
            report_path = self._write_report(
                Path(tmp_dir),
                {
                    'classes': [{'name': 'Loader'}],
                    'modules': ['os', 'winreg'],
                    'code_objects': [{'name': 'start', 'opcodes': ['LOAD_GLOBAL']}],
                    'extra_context': {'sample': 'value'},
                },
            )

            router = DataIngestionRouter()
            report = router.load_report(report_path)
            routed = router.route(report)

            self.assertEqual(
                routed.artifacts_payload,
                {
                    'classes': [{'name': 'Loader'}],
                    'modules': ['os', 'winreg'],
                },
            )
            self.assertEqual(
                routed.bytecode_payload,
                {
                    'code_objects': [{'name': 'start', 'opcodes': ['LOAD_GLOBAL']}],
                },
            )

    def test_router_rejects_invalid_json(self):
        with TemporaryDirectory() as tmp_dir:
            report_path = Path(tmp_dir) / 'broken.json'
            report_path.write_text('{not-valid-json', encoding='utf-8')

            with self.assertRaisesRegex(ValueError, 'Invalid JSON file.'):
                DataIngestionRouter().load_report(report_path)

    def test_pipeline_runs_end_to_end_with_two_model_calls(self):
        with TemporaryDirectory() as tmp_dir:
            report_path = self._write_report(
                Path(tmp_dir),
                {
                    'classes': [{'name': 'Loader'}],
                    'modules': ['os', 'winreg'],
                    'code_objects': [{'name': 'start', 'opcodes': ['LOAD_GLOBAL']}],
                },
            )

            client = FakeLLMClient()
            pipeline = AnalysisPipeline(
                router=DataIngestionRouter(),
                artifact_agent=ArtifactInspectorAgent(client=client),
                bytecode_agent=BytecodeReverserAgent(client=client),
                compiler=ReportCompiler(),
            )

            progress_messages: list[str] = []
            result = pipeline.run(report_path, progress=progress_messages.append)

            self.assertEqual(result.artifact_report.suspicious_imports, ['winreg', 'subprocess'])
            self.assertEqual(result.structured_report.summary, 'Synthetic report')
            self.assertIn('## Key IOCs', result.final_report)
            self.assertEqual(len(client.json_calls), 2)
            self.assertEqual(client.json_calls[0]['model'], 'openai/gpt-5.1')
            self.assertEqual(client.json_calls[1]['model'], 'openai/gpt-5.1')
            self.assertIn('artifact_report', client.json_calls[1]['payload'])
            self.assertEqual(
                progress_messages,
                [
                    '[Router] Parsed input and validated the top-level report schema.',
                    '[Agent A] Inspecting artifacts and extracting IOCs...',
                    '[Agent B] Reversing Python opcodes, combining artifacts, and drafting the final report...',
                ],
            )


if __name__ == '__main__':
    unittest.main()
