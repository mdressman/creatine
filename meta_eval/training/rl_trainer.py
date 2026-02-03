"""
RLTrainer - Reinforcement Learning for adaptive agent tuning.

Uses panel consensus as reward signal to train agents:
- Agents that agree with consensus get positive reward
- Agents that disagree get negative reward
- Weights are adjusted based on cumulative reward

Supports:
- Online learning (continuous updates)
- Offline learning (batch updates from logs)
- Multiple reward shaping strategies
"""

import asyncio
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable
import random
import math

from ..schemas import (
    AgentConfig, AgentVote, EvaluationResult,
    ConsistencyMetrics
)
from ..agents.manager import AgentManager


@dataclass
class Experience:
    """Single training experience for an agent."""
    agent_id: str
    verdict: str
    score: float
    confidence: float
    consensus_verdict: str
    consensus_score: float
    reward: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TrainingConfig:
    """Configuration for RL training."""
    learning_rate: float = 0.01
    discount_factor: float = 0.95
    exploration_rate: float = 0.1  # Epsilon for epsilon-greedy
    min_exploration: float = 0.01
    exploration_decay: float = 0.995
    
    # Reward shaping
    agreement_reward: float = 1.0
    disagreement_penalty: float = -0.5
    confidence_bonus_weight: float = 0.2
    consistency_bonus_weight: float = 0.1
    
    # Training schedule
    batch_size: int = 32
    update_frequency: int = 10  # Update weights every N evaluations
    warmup_evaluations: int = 50
    
    # Constraints
    min_weight: float = 0.1
    max_weight: float = 3.0


class RLTrainer:
    """
    Reinforcement Learning trainer for agent weight optimization.
    
    Uses consensus-based reward signal:
    - Reward = agreement with panel consensus
    - Penalty = disagreement with consensus
    - Bonus = high confidence on correct verdicts
    
    Updates agent weights to favor reliable agents.
    """
    
    def __init__(
        self,
        agent_manager: AgentManager,
        config: Optional[TrainingConfig] = None,
        experience_path: Optional[Path] = None,
        verbose: bool = False,
    ):
        self.agent_manager = agent_manager
        self.config = config or TrainingConfig()
        self.experience_path = experience_path
        self.verbose = verbose
        
        # Experience replay buffer
        self._experience_buffer: List[Experience] = []
        self._agent_rewards: Dict[str, List[float]] = defaultdict(list)
        
        # Training state
        self._evaluation_count = 0
        self._training_step = 0
        self._exploration_rate = self.config.exploration_rate
        
        # Load existing experiences
        if experience_path and experience_path.exists():
            self._load_experiences(experience_path)
    
    # ==================== Experience Collection ====================
    
    def record_experience(
        self,
        result: EvaluationResult,
    ):
        """
        Record experiences from an evaluation result.
        
        Calculates rewards based on agreement with consensus.
        """
        consensus_verdict = result.verdict
        consensus_score = result.score
        
        for vote in result.agent_votes:
            # Calculate reward
            reward = self._calculate_reward(vote, consensus_verdict, consensus_score)
            
            experience = Experience(
                agent_id=vote.agent_id,
                verdict=vote.verdict,
                score=vote.score,
                confidence=vote.confidence,
                consensus_verdict=consensus_verdict,
                consensus_score=consensus_score,
                reward=reward,
            )
            
            self._experience_buffer.append(experience)
            self._agent_rewards[vote.agent_id].append(reward)
        
        self._evaluation_count += 1
        
        # Periodic weight updates
        if self._evaluation_count >= self.config.warmup_evaluations:
            if self._evaluation_count % self.config.update_frequency == 0:
                self._update_weights()
    
    def _calculate_reward(
        self,
        vote: AgentVote,
        consensus_verdict: str,
        consensus_score: float,
    ) -> float:
        """Calculate reward for an agent's vote."""
        reward = 0.0
        
        # Base reward/penalty for agreement
        if vote.verdict == consensus_verdict:
            reward += self.config.agreement_reward
            
            # Bonus for high confidence on correct verdict
            reward += self.config.confidence_bonus_weight * vote.confidence
            
            # Bonus for score close to consensus
            score_diff = abs(vote.score - consensus_score)
            reward += self.config.confidence_bonus_weight * (1.0 - score_diff)
        else:
            reward += self.config.disagreement_penalty
            
            # Extra penalty for high confidence on wrong verdict
            reward -= self.config.confidence_bonus_weight * vote.confidence
        
        return reward
    
    # ==================== Weight Updates ====================
    
    def _update_weights(self):
        """Update agent weights based on accumulated rewards."""
        self._training_step += 1
        
        if self.verbose:
            print(f"RL Training step {self._training_step}")
        
        for agent_id, rewards in self._agent_rewards.items():
            if not rewards:
                continue
            
            agent = self.agent_manager.get_agent(agent_id)
            if not agent:
                continue
            
            # Calculate average reward over recent experiences
            recent_rewards = rewards[-self.config.batch_size:]
            avg_reward = sum(recent_rewards) / len(recent_rewards)
            
            # Update weight using gradient-like update
            old_weight = agent.weight
            delta = self.config.learning_rate * avg_reward
            new_weight = old_weight + delta
            
            # Clamp to bounds
            new_weight = max(self.config.min_weight, min(self.config.max_weight, new_weight))
            
            agent.weight = new_weight
            
            if self.verbose:
                print(f"  {agent.name}: weight {old_weight:.3f} -> {new_weight:.3f} (avg_reward={avg_reward:.3f})")
        
        # Decay exploration rate
        self._exploration_rate = max(
            self.config.min_exploration,
            self._exploration_rate * self.config.exploration_decay
        )
    
    # ==================== Online Learning ====================
    
    async def online_update(
        self,
        result: EvaluationResult,
        human_label: Optional[str] = None,
    ):
        """
        Perform online learning update from a single evaluation.
        
        If human_label provided, uses that as ground truth instead of consensus.
        """
        if human_label:
            # Override consensus with human judgment
            for vote in result.agent_votes:
                reward = self.config.agreement_reward if vote.verdict == human_label else self.config.disagreement_penalty
                self._agent_rewards[vote.agent_id].append(reward)
        else:
            self.record_experience(result)
    
    # ==================== Offline Learning ====================
    
    def offline_train(
        self,
        experiences: List[Experience],
        epochs: int = 10,
    ):
        """
        Train on a batch of historical experiences.
        
        Args:
            experiences: List of recorded experiences
            epochs: Number of training epochs
        """
        if self.verbose:
            print(f"Offline training on {len(experiences)} experiences for {epochs} epochs")
        
        for epoch in range(epochs):
            # Shuffle experiences
            random.shuffle(experiences)
            
            # Process in batches
            for i in range(0, len(experiences), self.config.batch_size):
                batch = experiences[i:i + self.config.batch_size]
                
                # Accumulate rewards per agent
                batch_rewards = defaultdict(list)
                for exp in batch:
                    batch_rewards[exp.agent_id].append(exp.reward)
                
                # Update weights
                for agent_id, rewards in batch_rewards.items():
                    agent = self.agent_manager.get_agent(agent_id)
                    if not agent:
                        continue
                    
                    avg_reward = sum(rewards) / len(rewards)
                    delta = self.config.learning_rate * avg_reward
                    agent.weight = max(
                        self.config.min_weight,
                        min(self.config.max_weight, agent.weight + delta)
                    )
            
            if self.verbose:
                print(f"  Epoch {epoch + 1}/{epochs} complete")
    
    # ==================== Exploration ====================
    
    def should_explore(self) -> bool:
        """Determine if exploration should happen (epsilon-greedy)."""
        return random.random() < self._exploration_rate
    
    def get_exploration_weights(self) -> Dict[str, float]:
        """Get weights with exploration noise added."""
        weights = {}
        for agent in self.agent_manager.list_agents():
            if self.should_explore():
                # Add noise for exploration
                noise = random.gauss(0, 0.2)
                weights[agent.id] = max(self.config.min_weight, agent.weight + noise)
            else:
                weights[agent.id] = agent.weight
        return weights
    
    # ==================== Persistence ====================
    
    def save_experiences(self, path: Optional[Path] = None):
        """Save experience buffer to file."""
        path = path or self.experience_path
        if not path:
            return
        
        path.parent.mkdir(parents=True, exist_ok=True)
        
        experiences_data = [
            {
                "agent_id": e.agent_id,
                "verdict": e.verdict,
                "score": e.score,
                "confidence": e.confidence,
                "consensus_verdict": e.consensus_verdict,
                "consensus_score": e.consensus_score,
                "reward": e.reward,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in self._experience_buffer
        ]
        
        with open(path, 'w') as f:
            json.dump(experiences_data, f, indent=2)
    
    def _load_experiences(self, path: Path):
        """Load experiences from file."""
        with open(path) as f:
            data = json.load(f)
        
        for item in data:
            exp = Experience(
                agent_id=item["agent_id"],
                verdict=item["verdict"],
                score=item["score"],
                confidence=item["confidence"],
                consensus_verdict=item["consensus_verdict"],
                consensus_score=item["consensus_score"],
                reward=item["reward"],
                timestamp=datetime.fromisoformat(item["timestamp"]),
            )
            self._experience_buffer.append(exp)
            self._agent_rewards[exp.agent_id].append(exp.reward)
    
    # ==================== Statistics ====================
    
    def get_training_stats(self) -> Dict[str, Any]:
        """Get training statistics."""
        agent_stats = {}
        for agent_id, rewards in self._agent_rewards.items():
            agent = self.agent_manager.get_agent(agent_id)
            if agent:
                agent_stats[agent.name] = {
                    "total_experiences": len(rewards),
                    "avg_reward": sum(rewards) / len(rewards) if rewards else 0,
                    "current_weight": agent.weight,
                }
        
        return {
            "training_steps": self._training_step,
            "total_evaluations": self._evaluation_count,
            "exploration_rate": self._exploration_rate,
            "experience_buffer_size": len(self._experience_buffer),
            "agent_stats": agent_stats,
        }
