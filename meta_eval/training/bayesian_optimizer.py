"""
BayesianOptimizer - Hyperparameter tuning for the evaluation framework.

Uses Bayesian optimization to tune:
- Agent weights in consensus aggregation
- Debate protocol parameters (rounds, thresholds)
- Consistency thresholds

Objective: Maximize evaluation accuracy while minimizing IPI/TOV.
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from pathlib import Path
import json
import random
import math

from ..schemas import (
    AgentConfig, EvaluationRequest, EvaluationResult,
    DebateProtocol, DebateConfig, ConsistencyMetrics
)
from ..agents.manager import AgentManager
from ..debate.debate_engine import DebateEngine
from ..consistency.checker import ConsistencyChecker


@dataclass
class HyperparameterSpace:
    """Defines the search space for hyperparameters."""
    
    # Agent weights
    min_agent_weight: float = 0.1
    max_agent_weight: float = 3.0
    
    # Debate parameters
    max_debate_rounds_range: Tuple[int, int] = (1, 5)
    consensus_threshold_range: Tuple[float, float] = (0.5, 0.95)
    
    # Consistency thresholds
    ipi_threshold_range: Tuple[float, float] = (0.05, 0.3)
    tov_threshold_range: Tuple[float, float] = (0.05, 0.2)
    
    # Temperature
    temperature_range: Tuple[float, float] = (0.1, 1.0)


@dataclass
class TrialResult:
    """Result of a single optimization trial."""
    trial_id: int
    parameters: Dict[str, Any]
    objective_value: float
    accuracy: float
    ipi: float
    tov: float
    latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizationConfig:
    """Configuration for Bayesian optimization."""
    n_trials: int = 50
    n_initial_random: int = 10
    
    # Objective weights
    accuracy_weight: float = 1.0
    ipi_penalty_weight: float = 0.5
    tov_penalty_weight: float = 0.3
    latency_penalty_weight: float = 0.1
    
    # Acquisition function
    exploration_weight: float = 0.1  # For UCB acquisition
    
    # Early stopping
    patience: int = 10
    min_improvement: float = 0.01


class BayesianOptimizer:
    """
    Bayesian optimization for meta-evaluation hyperparameters.
    
    Uses Gaussian Process surrogate model with UCB acquisition.
    Optimizes:
    - Agent weights
    - Debate parameters
    - Consistency thresholds
    
    Objective: accuracy - penalty * (IPI + TOV) - latency_penalty
    """
    
    def __init__(
        self,
        agent_manager: AgentManager,
        debate_engine: DebateEngine,
        consistency_checker: ConsistencyChecker,
        space: Optional[HyperparameterSpace] = None,
        config: Optional[OptimizationConfig] = None,
        verbose: bool = False,
    ):
        self.agent_manager = agent_manager
        self.debate_engine = debate_engine
        self.consistency_checker = consistency_checker
        self.space = space or HyperparameterSpace()
        self.config = config or OptimizationConfig()
        self.verbose = verbose
        
        # Trial history
        self._trials: List[TrialResult] = []
        self._best_trial: Optional[TrialResult] = None
        
        # Simple surrogate model (mean and variance estimates)
        # In production, use sklearn GP or Optuna
        self._param_means: Dict[str, float] = {}
        self._param_vars: Dict[str, float] = {}
    
    async def optimize(
        self,
        validation_samples: List[Dict[str, Any]],
        ground_truth: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Run Bayesian optimization on validation samples.
        
        Args:
            validation_samples: List of {prompt, outputs} for evaluation
            ground_truth: Optional mapping of sample_id -> correct verdict
        
        Returns:
            Best hyperparameters found
        """
        if self.verbose:
            print(f"Starting Bayesian optimization with {self.config.n_trials} trials")
        
        no_improvement_count = 0
        
        for trial_id in range(self.config.n_trials):
            # Sample hyperparameters
            if trial_id < self.config.n_initial_random:
                params = self._sample_random()
            else:
                params = self._sample_acquisition()
            
            if self.verbose:
                print(f"\nTrial {trial_id + 1}/{self.config.n_trials}")
                print(f"  Parameters: {params}")
            
            # Apply parameters
            self._apply_parameters(params)
            
            # Evaluate
            result = await self._evaluate_parameters(
                params, validation_samples, ground_truth, trial_id
            )
            
            self._trials.append(result)
            
            # Update best
            if self._best_trial is None or result.objective_value > self._best_trial.objective_value:
                self._best_trial = result
                no_improvement_count = 0
                if self.verbose:
                    print(f"  New best! Objective: {result.objective_value:.4f}")
            else:
                no_improvement_count += 1
            
            # Update surrogate model
            self._update_surrogate(params, result.objective_value)
            
            # Early stopping
            if no_improvement_count >= self.config.patience:
                if self.verbose:
                    print(f"\nEarly stopping after {trial_id + 1} trials (no improvement)")
                break
        
        # Apply best parameters
        if self._best_trial:
            self._apply_parameters(self._best_trial.parameters)
        
        return self._get_optimization_summary()
    
    def _sample_random(self) -> Dict[str, Any]:
        """Sample random hyperparameters."""
        agents = self.agent_manager.list_agents()
        
        params = {
            "agent_weights": {
                a.id: random.uniform(self.space.min_agent_weight, self.space.max_agent_weight)
                for a in agents
            },
            "max_debate_rounds": random.randint(*self.space.max_debate_rounds_range),
            "consensus_threshold": random.uniform(*self.space.consensus_threshold_range),
            "temperature": random.uniform(*self.space.temperature_range),
        }
        
        return params
    
    def _sample_acquisition(self) -> Dict[str, Any]:
        """Sample using UCB acquisition function."""
        # Simple UCB: mean + exploration_weight * sqrt(variance)
        # With limited history, add more exploration
        
        params = {}
        agents = self.agent_manager.list_agents()
        
        # Agent weights - UCB for each
        agent_weights = {}
        for agent in agents:
            key = f"weight_{agent.id}"
            mean = self._param_means.get(key, (self.space.min_agent_weight + self.space.max_agent_weight) / 2)
            var = self._param_vars.get(key, 1.0)
            
            # UCB value
            ucb = mean + self.config.exploration_weight * math.sqrt(var)
            # Add noise for exploration
            ucb += random.gauss(0, 0.1)
            
            agent_weights[agent.id] = max(self.space.min_agent_weight, min(self.space.max_agent_weight, ucb))
        
        params["agent_weights"] = agent_weights
        
        # Other parameters - similar UCB approach
        params["max_debate_rounds"] = self._ucb_sample_int(
            "max_debate_rounds", *self.space.max_debate_rounds_range
        )
        params["consensus_threshold"] = self._ucb_sample_float(
            "consensus_threshold", *self.space.consensus_threshold_range
        )
        params["temperature"] = self._ucb_sample_float(
            "temperature", *self.space.temperature_range
        )
        
        return params
    
    def _ucb_sample_float(self, key: str, min_val: float, max_val: float) -> float:
        """UCB sampling for continuous parameter."""
        mean = self._param_means.get(key, (min_val + max_val) / 2)
        var = self._param_vars.get(key, 1.0)
        ucb = mean + self.config.exploration_weight * math.sqrt(var) + random.gauss(0, 0.05)
        return max(min_val, min(max_val, ucb))
    
    def _ucb_sample_int(self, key: str, min_val: int, max_val: int) -> int:
        """UCB sampling for integer parameter."""
        val = self._ucb_sample_float(key, float(min_val), float(max_val))
        return round(val)
    
    def _apply_parameters(self, params: Dict[str, Any]):
        """Apply hyperparameters to the system."""
        # Agent weights
        for agent_id, weight in params.get("agent_weights", {}).items():
            self.agent_manager.update_agent(agent_id, {"weight": weight})
        
        # Temperature
        temp = params.get("temperature", 0.3)
        for agent in self.agent_manager.list_agents():
            self.agent_manager.update_agent(agent.id, {"temperature": temp})
        
        # Debate config is applied per-evaluation
    
    async def _evaluate_parameters(
        self,
        params: Dict[str, Any],
        validation_samples: List[Dict[str, Any]],
        ground_truth: Optional[Dict[str, str]],
        trial_id: int,
    ) -> TrialResult:
        """Evaluate a set of hyperparameters."""
        
        debate_config = DebateConfig(
            max_rounds=params.get("max_debate_rounds", 3),
            consensus_threshold=params.get("consensus_threshold", 0.8),
        )
        
        correct = 0
        total = 0
        total_latency = 0.0
        
        for sample in validation_samples:
            # Run evaluation
            from ..schemas import CandidateOutput
            request = EvaluationRequest(
                prompt=sample["prompt"],
                candidate_outputs=[CandidateOutput(content=o) for o in sample["outputs"]],
            )
            
            result = await self.debate_engine.evaluate(request, debate_config)
            total_latency += result.total_latency_ms
            
            # Check accuracy
            if ground_truth:
                sample_id = sample.get("id", str(hash(sample["prompt"])))
                if sample_id in ground_truth:
                    if result.verdict == ground_truth[sample_id]:
                        correct += 1
                    total += 1
        
        accuracy = correct / max(total, 1)
        
        # Run consistency check
        consistency_report = await self.consistency_checker.run_consistency_check(
            validation_samples[:10]  # Limit for speed
        )
        
        ipi = consistency_report.metrics.ipi
        tov = consistency_report.metrics.tov
        avg_latency = total_latency / max(len(validation_samples), 1)
        
        # Calculate objective
        objective = (
            self.config.accuracy_weight * accuracy
            - self.config.ipi_penalty_weight * ipi
            - self.config.tov_penalty_weight * tov
            - self.config.latency_penalty_weight * (avg_latency / 10000)  # Normalize
        )
        
        if self.verbose:
            print(f"  Accuracy: {accuracy:.2%}, IPI: {ipi:.3f}, TOV: {tov:.3f}")
            print(f"  Objective: {objective:.4f}")
        
        return TrialResult(
            trial_id=trial_id,
            parameters=params,
            objective_value=objective,
            accuracy=accuracy,
            ipi=ipi,
            tov=tov,
            latency_ms=avg_latency,
        )
    
    def _update_surrogate(self, params: Dict[str, Any], objective: float):
        """Update surrogate model with new observation."""
        # Simple exponential moving average for mean/variance
        alpha = 0.1
        
        # Update agent weight estimates
        for agent_id, weight in params.get("agent_weights", {}).items():
            key = f"weight_{agent_id}"
            old_mean = self._param_means.get(key, weight)
            self._param_means[key] = alpha * weight + (1 - alpha) * old_mean
            
            old_var = self._param_vars.get(key, 1.0)
            self._param_vars[key] = alpha * (weight - self._param_means[key])**2 + (1 - alpha) * old_var
        
        # Update other parameters
        for key in ["max_debate_rounds", "consensus_threshold", "temperature"]:
            if key in params:
                value = float(params[key])
                old_mean = self._param_means.get(key, value)
                self._param_means[key] = alpha * value + (1 - alpha) * old_mean
                
                old_var = self._param_vars.get(key, 1.0)
                self._param_vars[key] = alpha * (value - self._param_means[key])**2 + (1 - alpha) * old_var
    
    def _get_optimization_summary(self) -> Dict[str, Any]:
        """Get summary of optimization results."""
        return {
            "best_parameters": self._best_trial.parameters if self._best_trial else {},
            "best_objective": self._best_trial.objective_value if self._best_trial else 0,
            "best_accuracy": self._best_trial.accuracy if self._best_trial else 0,
            "best_ipi": self._best_trial.ipi if self._best_trial else 0,
            "best_tov": self._best_trial.tov if self._best_trial else 0,
            "total_trials": len(self._trials),
            "trial_history": [
                {
                    "trial_id": t.trial_id,
                    "objective": t.objective_value,
                    "accuracy": t.accuracy,
                }
                for t in self._trials
            ],
        }
    
    def save_results(self, path: Path):
        """Save optimization results to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            json.dump(self._get_optimization_summary(), f, indent=2)
    
    def load_results(self, path: Path):
        """Load previous optimization results."""
        if not path.exists():
            return
        
        with open(path) as f:
            data = json.load(f)
        
        if data.get("best_parameters"):
            self._apply_parameters(data["best_parameters"])
