"""Dataset management for security agent testing.

Supports loading, processing, and iterating over prompt injection and jailbreak datasets
from various sources including HuggingFace, local files, and custom collections.
"""

import json
import csv
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Iterator, Optional
from enum import Enum


class AttackType(Enum):
    """Categories of prompt attacks."""
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    ROLE_HIJACKING = "role_hijacking"
    OBFUSCATION = "obfuscation"
    MULTI_TURN = "multi_turn"
    INDIRECT = "indirect"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestPrompt:
    """A single test prompt with metadata."""
    prompt: str
    attack_type: AttackType = AttackType.UNKNOWN
    severity: Severity = Severity.MEDIUM
    is_malicious: bool = True
    source: str = ""
    description: str = ""
    expected_blocked: bool = True
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "prompt": self.prompt,
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "is_malicious": self.is_malicious,
            "source": self.source,
            "description": self.description,
            "expected_blocked": self.expected_blocked,
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "TestPrompt":
        """Create from dictionary."""
        return cls(
            prompt=data["prompt"],
            attack_type=AttackType(data.get("attack_type", "unknown")),
            severity=Severity(data.get("severity", "medium")),
            is_malicious=data.get("is_malicious", True),
            source=data.get("source", ""),
            description=data.get("description", ""),
            expected_blocked=data.get("expected_blocked", True),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Dataset:
    """A collection of test prompts."""
    name: str
    description: str
    prompts: list[TestPrompt] = field(default_factory=list)
    version: str = "1.0"
    source_url: str = ""
    
    def __len__(self) -> int:
        return len(self.prompts)
    
    def __iter__(self) -> Iterator[TestPrompt]:
        return iter(self.prompts)
    
    def filter_by_type(self, attack_type: AttackType) -> list[TestPrompt]:
        """Filter prompts by attack type."""
        return [p for p in self.prompts if p.attack_type == attack_type]
    
    def filter_by_severity(self, severity: Severity) -> list[TestPrompt]:
        """Filter prompts by severity."""
        return [p for p in self.prompts if p.severity == severity]
    
    def filter_malicious(self, malicious: bool = True) -> list[TestPrompt]:
        """Filter by malicious/benign."""
        return [p for p in self.prompts if p.is_malicious == malicious]
    
    def sample(self, n: int) -> list[TestPrompt]:
        """Get a random sample of prompts."""
        import random
        return random.sample(self.prompts, min(n, len(self.prompts)))
    
    def save(self, path: Path) -> None:
        """Save dataset to JSON file."""
        data = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "source_url": self.source_url,
            "prompts": [p.to_dict() for p in self.prompts],
        }
        path.write_text(json.dumps(data, indent=2))
    
    @classmethod
    def load(cls, path: Path) -> "Dataset":
        """Load dataset from JSON file."""
        data = json.loads(path.read_text())
        return cls(
            name=data["name"],
            description=data["description"],
            version=data.get("version", "1.0"),
            source_url=data.get("source_url", ""),
            prompts=[TestPrompt.from_dict(p) for p in data["prompts"]],
        )


class DatasetRegistry:
    """Registry for managing multiple datasets."""
    
    def __init__(self, datasets_dir: Path = None):
        self.datasets_dir = datasets_dir or Path(__file__).parent / "datasets"
        self.datasets_dir.mkdir(exist_ok=True)
        self._datasets: dict[str, Dataset] = {}
    
    def register(self, dataset: Dataset) -> None:
        """Register a dataset."""
        self._datasets[dataset.name] = dataset
    
    def get(self, name: str) -> Optional[Dataset]:
        """Get a dataset by name."""
        if name in self._datasets:
            return self._datasets[name]
        # Try loading from file
        path = self.datasets_dir / f"{name}.json"
        if path.exists():
            dataset = Dataset.load(path)
            self._datasets[name] = dataset
            return dataset
        return None
    
    def list_datasets(self) -> list[str]:
        """List all available datasets."""
        # Combine registered and file-based datasets
        file_datasets = {p.stem for p in self.datasets_dir.glob("*.json")}
        return sorted(set(self._datasets.keys()) | file_datasets)
    
    def save_dataset(self, dataset: Dataset) -> None:
        """Save a dataset to the datasets directory."""
        path = self.datasets_dir / f"{dataset.name}.json"
        dataset.save(path)
        self._datasets[dataset.name] = dataset
    
    def load_all(self) -> None:
        """Load all datasets from the datasets directory."""
        for path in self.datasets_dir.glob("*.json"):
            if path.stem not in self._datasets:
                self._datasets[path.stem] = Dataset.load(path)
    
    def get_combined(self, names: list[str] = None) -> Dataset:
        """Combine multiple datasets into one."""
        if names is None:
            names = self.list_datasets()
        
        combined_prompts = []
        for name in names:
            dataset = self.get(name)
            if dataset:
                combined_prompts.extend(dataset.prompts)
        
        return Dataset(
            name="combined",
            description=f"Combined dataset from: {', '.join(names)}",
            prompts=combined_prompts,
        )


def load_from_csv(path: Path, prompt_col: str = "prompt", label_col: str = "label") -> Dataset:
    """Load a dataset from a CSV file."""
    prompts = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            is_malicious = row.get(label_col, "1") in ("1", "true", "malicious", "attack")
            prompts.append(TestPrompt(
                prompt=row[prompt_col],
                is_malicious=is_malicious,
                attack_type=AttackType.BENIGN if not is_malicious else AttackType.UNKNOWN,
                source=str(path),
            ))
    
    return Dataset(
        name=path.stem,
        description=f"Loaded from {path}",
        prompts=prompts,
    )


def load_from_huggingface(dataset_name: str, split: str = "train", prompt_field: str = "prompt", label_field: str = "label") -> Dataset:
    """Load a dataset from HuggingFace."""
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError("Install 'datasets' package: pip install datasets")
    
    hf_dataset = load_dataset(dataset_name, split=split)
    prompts = []
    
    for item in hf_dataset:
        prompt_text = item.get(prompt_field) or item.get("text") or item.get("content", "")
        label = item.get(label_field)
        
        # Determine if malicious based on label
        is_malicious = True
        if label is not None:
            if isinstance(label, (int, float)):
                is_malicious = label == 1
            elif isinstance(label, str):
                is_malicious = label.lower() in ("1", "malicious", "attack", "injection", "jailbreak")
        
        prompts.append(TestPrompt(
            prompt=prompt_text,
            is_malicious=is_malicious,
            attack_type=AttackType.BENIGN if not is_malicious else AttackType.UNKNOWN,
            source=f"huggingface:{dataset_name}",
            metadata=dict(item),
        ))
    
    return Dataset(
        name=dataset_name.replace("/", "_"),
        description=f"HuggingFace dataset: {dataset_name}",
        source_url=f"https://huggingface.co/datasets/{dataset_name}",
        prompts=prompts,
    )
