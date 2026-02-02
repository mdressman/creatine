"""Test harness for security evaluation.

Runs test datasets through detectors and generates reports with metrics.
"""

import asyncio
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

from .dataset import Dataset, TestPrompt, DatasetRegistry


@dataclass
class TestResult:
    """Result of testing a single prompt."""
    prompt: TestPrompt
    detected_as_threat: bool
    risk_score: str
    attack_types_detected: List[str]
    response_time_ms: float
    correct: bool
    error: Optional[str] = None
    raw_response: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt": self.prompt.prompt[:100] + "..." if len(self.prompt.prompt) > 100 else self.prompt.prompt,
            "expected_malicious": self.prompt.is_malicious,
            "detected_as_threat": self.detected_as_threat,
            "risk_score": self.risk_score,
            "attack_types_detected": self.attack_types_detected,
            "response_time_ms": self.response_time_ms,
            "correct": self.correct,
            "error": self.error,
        }


@dataclass
class TestReport:
    """Aggregated results from a test run."""
    dataset_name: str
    total_prompts: int
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    errors: int = 0
    avg_response_time_ms: float = 0.0
    results: List[TestResult] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    
    @property
    def accuracy(self) -> float:
        correct = self.true_positives + self.true_negatives
        total = self.total_prompts - self.errors
        return correct / total if total > 0 else 0.0
    
    @property
    def precision(self) -> float:
        """Of all detected threats, how many were actually malicious?"""
        detected = self.true_positives + self.false_positives
        return self.true_positives / detected if detected > 0 else 0.0
    
    @property
    def recall(self) -> float:
        """Of all malicious prompts, how many were detected?"""
        malicious = self.true_positives + self.false_negatives
        return self.true_positives / malicious if malicious > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    
    def summary(self) -> str:
        """Generate a human-readable summary."""
        return f"""
=== Test Report: {self.dataset_name} ===
Total Prompts: {self.total_prompts}
Duration: {self.started_at} - {self.completed_at}

Performance Metrics:
  Accuracy:  {self.accuracy:.2%}
  Precision: {self.precision:.2%}
  Recall:    {self.recall:.2%}
  F1 Score:  {self.f1_score:.2%}

Confusion Matrix:
  True Positives:  {self.true_positives}
  True Negatives:  {self.true_negatives}
  False Positives: {self.false_positives}
  False Negatives: {self.false_negatives}
  Errors:          {self.errors}

Avg Response Time: {self.avg_response_time_ms:.2f}ms
"""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "total_prompts": self.total_prompts,
            "metrics": {
                "accuracy": self.accuracy,
                "precision": self.precision,
                "recall": self.recall,
                "f1_score": self.f1_score,
            },
            "confusion_matrix": {
                "true_positives": self.true_positives,
                "true_negatives": self.true_negatives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
            },
            "errors": self.errors,
            "avg_response_time_ms": self.avg_response_time_ms,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "results": [r.to_dict() for r in self.results],
        }
    
    def save(self, path: Path) -> None:
        """Save report to JSON file."""
        path.write_text(json.dumps(self.to_dict(), indent=2))


class TestHarness:
    """Harness for running security tests against datasets."""
    
    def __init__(
        self,
        detector,  # ThreatDetector or compatible
        registry: Optional[DatasetRegistry] = None,
        reports_dir: Optional[Path] = None,
    ):
        self.detector = detector
        self.registry = registry or DatasetRegistry()
        self.reports_dir = reports_dir or Path(__file__).parent.parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    async def test_prompt(self, prompt: TestPrompt, verbose: bool = False) -> TestResult:
        """Test a single prompt against the detector."""
        start_time = time.time()
        
        try:
            analysis = await self.detector.analyze(prompt.prompt)
            response_time = (time.time() - start_time) * 1000
            
            detected = analysis.is_threat
            
            if prompt.is_malicious:
                correct = detected
            else:
                correct = not detected
            
            if verbose:
                status = "✓" if correct else "✗"
                print(f"\n{status} Prompt: {prompt.prompt[:80]}...")
                print(f"  Expected: {'malicious' if prompt.is_malicious else 'benign'}")
                print(f"  Detected: {'threat' if detected else 'safe'} (risk: {analysis.risk_score})")
                if analysis.attack_types:
                    print(f"  Attack types: {', '.join(analysis.attack_types)}")
            
            return TestResult(
                prompt=prompt,
                detected_as_threat=detected,
                risk_score=analysis.risk_score,
                attack_types_detected=analysis.attack_types,
                response_time_ms=response_time,
                correct=correct,
                raw_response=analysis.details,
            )
        except Exception as e:
            if verbose:
                print(f"\n! Error testing prompt: {prompt.prompt[:80]}...")
                print(f"  Error: {e}")
            return TestResult(
                prompt=prompt,
                detected_as_threat=False,
                risk_score="unknown",
                attack_types_detected=[],
                response_time_ms=(time.time() - start_time) * 1000,
                correct=False,
                error=str(e),
            )
    
    async def run_dataset(
        self,
        dataset: Dataset,
        concurrency: int = 5,
        progress_callback: Optional[Callable] = None,
        verbose: bool = False,
    ) -> TestReport:
        """Run tests on an entire dataset."""
        report = TestReport(
            dataset_name=dataset.name,
            total_prompts=len(dataset),
            started_at=datetime.now().isoformat(),
        )
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def test_with_limit(prompt: TestPrompt, idx: int) -> TestResult:
            async with semaphore:
                result = await self.test_prompt(prompt, verbose=verbose)
                if progress_callback and not verbose:
                    progress_callback(idx + 1, len(dataset), result)
                return result
        
        tasks = [test_with_limit(p, i) for i, p in enumerate(dataset.prompts)]
        results = await asyncio.gather(*tasks)
        
        total_time = 0.0
        for result in results:
            report.results.append(result)
            total_time += result.response_time_ms
            
            if result.error:
                report.errors += 1
            elif result.prompt.is_malicious:
                if result.detected_as_threat:
                    report.true_positives += 1
                else:
                    report.false_negatives += 1
            else:
                if result.detected_as_threat:
                    report.false_positives += 1
                else:
                    report.true_negatives += 1
        
        report.avg_response_time_ms = total_time / len(results) if results else 0
        report.completed_at = datetime.now().isoformat()
        
        return report
    
    async def run_by_name(self, dataset_name: str, **kwargs) -> TestReport:
        """Run tests on a dataset by name."""
        dataset = self.registry.get(dataset_name)
        if not dataset:
            raise ValueError(f"Dataset not found: {dataset_name}")
        return await self.run_dataset(dataset, **kwargs)
    
    async def run_all(self, **kwargs) -> Dict[str, TestReport]:
        """Run tests on all registered datasets."""
        reports = {}
        for name in self.registry.list_datasets():
            print(f"Testing dataset: {name}")
            reports[name] = await self.run_by_name(name, **kwargs)
        return reports
    
    def save_report(self, report: TestReport, suffix: str = "") -> Path:
        """Save a report to the reports directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report.dataset_name}_{timestamp}{suffix}.json"
        path = self.reports_dir / filename
        report.save(path)
        return path


def print_progress(current: int, total: int, result: TestResult):
    """Default progress callback."""
    status = "✓" if result.correct else "✗"
    if result.error:
        status = "!"
    print(f"  [{current}/{total}] {status} {result.risk_score}", end="\r")
