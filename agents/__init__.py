"""AI agents for rule generation, forensics, and orchestration."""

from .rule_generator import RuleGenerationAgent, generate_simple_rules
from .forensics import ForensicsAgent, ForensicsReport, AttackTechnique
from .learning import LearningPipeline, LearningResult, ProductionLog
from .orchestrator import (
    # Base classes
    BaseAgent,
    FunctionAgent,
    AgentResult,
    OrchestrationResult,
    # Agent wrappers
    DetectorAgent,
    AdaptiveDetectorAgent,
    ForensicsAgentWrapper,
    LLMDetectorAgent,
    LearningAgentWrapper,
    # Orchestration patterns
    Pipeline,
    ParallelExecutor,
    ConditionalRouter,
    Orchestrator,
    # Pre-built patterns
    create_detection_pipeline,
    create_full_learning_pipeline,
    create_ensemble_detector,
    create_tiered_router,
    # Enums
    ExecutionMode,
    AggregationStrategy,
)

__all__ = [
    # Rule generation
    "RuleGenerationAgent", 
    "generate_simple_rules",
    # Forensics
    "ForensicsAgent",
    "ForensicsReport",
    "AttackTechnique",
    # Learning
    "LearningPipeline",
    "LearningResult",
    "ProductionLog",
    # Orchestration base
    "BaseAgent",
    "FunctionAgent",
    "AgentResult",
    "OrchestrationResult",
    # Agent wrappers
    "DetectorAgent",
    "AdaptiveDetectorAgent",
    "ForensicsAgentWrapper",
    "LLMDetectorAgent",
    "LearningAgentWrapper",
    # Orchestration patterns
    "Pipeline",
    "ParallelExecutor",
    "ConditionalRouter",
    "Orchestrator",
    # Pre-built
    "create_detection_pipeline",
    "create_full_learning_pipeline",
    "create_ensemble_detector",
    "create_tiered_router",
    # Enums
    "ExecutionMode",
    "AggregationStrategy",
]
