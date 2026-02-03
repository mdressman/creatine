"""
Multi-Agent Meta-Evaluation Framework for Creatine.

Implements LLM-as-judge evaluation with:
- Multi-agent debate patterns (MoA, CourtEval, DEBATE, Consensus)
- Mixture-of-Experts architecture with specialized judge personas
- Consistency checking (IPI, TOV metrics)
- Reinforcement learning from panel consensus
- Bayesian optimization for hyperparameter tuning

Based on research from "Are We on the Right Way to Assessing LLM-as-a-Judge?"
https://arxiv.org/html/2508.02990

Quick Start:
    from meta_eval import AgentManager, DebateEngine, ConsistencyChecker
    from meta_eval.schemas import EvaluationRequest, CandidateOutput
    
    # Initialize
    manager = AgentManager()
    engine = DebateEngine(manager)
    
    # Evaluate
    request = EvaluationRequest(
        prompt="Original prompt",
        candidate_outputs=[CandidateOutput(content="Model response")],
    )
    result = await engine.evaluate(request)
    print(f"Verdict: {result.verdict}, Score: {result.score}")
"""

from .schemas import (
    AgentConfig, AgentPersona, AgentRole,
    EvaluationRequest, EvaluationResult, CandidateOutput,
    DebateProtocol, AggregationMethod, DebateConfig,
    ConsistencyMetrics, AgentVote, DebateRound,
    EvaluationRubric,
    # Domain experts
    SAMPLE_AGENTS, DOMAIN_EXPERT_AGENTS,
    SECURITY_RESEARCHER_AGENT, CYBER_SECURITY_RUBRIC,
)
from .agents.manager import AgentManager
from .debate.debate_engine import DebateEngine
from .consistency.checker import ConsistencyChecker, ConsistencyReport
from .training.rl_trainer import RLTrainer, TrainingConfig
from .training.bayesian_optimizer import BayesianOptimizer, OptimizationConfig
from .api.server import MetaEvalAPI, create_api

__version__ = "1.0.0"

__all__ = [
    # Schemas
    'AgentConfig',
    'AgentPersona', 
    'AgentRole',
    'EvaluationRequest',
    'EvaluationResult',
    'CandidateOutput',
    'DebateProtocol',
    'AggregationMethod',
    'DebateConfig',
    'ConsistencyMetrics',
    'AgentVote',
    'DebateRound',
    'EvaluationRubric',
    
    # Pre-built agents
    'SAMPLE_AGENTS',
    'DOMAIN_EXPERT_AGENTS',
    'SECURITY_RESEARCHER_AGENT',
    'CYBER_SECURITY_RUBRIC',
    
    # Core components
    'AgentManager',
    'DebateEngine',
    'ConsistencyChecker',
    'ConsistencyReport',
    
    # Training
    'RLTrainer',
    'TrainingConfig',
    'BayesianOptimizer',
    'OptimizationConfig',
    
    # API
    'MetaEvalAPI',
    'create_api',
]
