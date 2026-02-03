"""
AgentManager - Lifecycle management for expert judge agents.

Manages LLM/SLM agents in the MoE architecture including:
- Loading, updating, and removing agents
- Fine-tuning support
- Performance tracking and adaptive weighting
- Agent registry and discovery
"""

import asyncio
import json
import os
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI
from dotenv import load_dotenv

from ..schemas import (
    AgentConfig, AgentPersona, AgentRole, AgentVote,
    EvaluationRubric, CandidateOutput, SAMPLE_AGENTS
)

load_dotenv()


class AgentManager:
    """
    Manages lifecycle of expert judge agents in the MoE architecture.
    
    Responsibilities:
    - Agent registry (add, remove, update, list)
    - Agent invocation with proper prompting
    - Performance tracking and adaptive weight adjustment
    - Fine-tuning metadata management
    - Persistence and loading of agent configurations
    """
    
    def __init__(
        self,
        config_path: Optional[Path] = None,
        auto_load_samples: bool = True,
        verbose: bool = False,
    ):
        self.agents: Dict[str, AgentConfig] = {}
        self.config_path = config_path
        self.verbose = verbose
        
        # Performance tracking
        self._call_history: Dict[str, List[Dict]] = defaultdict(list)
        self._accuracy_history: Dict[str, List[float]] = defaultdict(list)
        
        # LLM client (lazy init)
        self._llm_client: Optional[AzureOpenAI] = None
        
        # Load persisted configs
        if config_path and config_path.exists():
            self.load_configs(config_path)
        elif auto_load_samples:
            self._load_sample_agents()
    
    def _load_sample_agents(self):
        """Load default sample agents for bootstrapping."""
        for agent in SAMPLE_AGENTS:
            self.register_agent(agent)
    
    def _get_llm_client(self) -> AzureOpenAI:
        """Lazy initialization of Azure OpenAI client."""
        if self._llm_client is None:
            credential = DefaultAzureCredential()
            token_provider = get_bearer_token_provider(
                credential,
                "https://cognitiveservices.azure.com/.default"
            )
            self._llm_client = AzureOpenAI(
                api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
                azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
                azure_ad_token_provider=token_provider,
            )
        return self._llm_client
    
    # ==================== Agent Registry ====================
    
    def register_agent(self, agent: AgentConfig) -> str:
        """Register a new agent or update existing one."""
        self.agents[agent.id] = agent
        if self.verbose:
            print(f"Registered agent: {agent.name} ({agent.persona.value})")
        return agent.id
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        if agent_id in self.agents:
            del self.agents[agent_id]
            return True
        return False
    
    def get_agent(self, agent_id: str) -> Optional[AgentConfig]:
        """Get agent by ID."""
        return self.agents.get(agent_id)
    
    def get_agents_by_persona(self, persona: AgentPersona) -> List[AgentConfig]:
        """Get all agents with a specific persona."""
        return [a for a in self.agents.values() if a.persona == persona and a.enabled]
    
    def get_agents_by_role(self, role: AgentRole) -> List[AgentConfig]:
        """Get all agents capable of a specific role."""
        return [a for a in self.agents.values() if role in a.roles and a.enabled]
    
    def list_agents(self, enabled_only: bool = True) -> List[AgentConfig]:
        """List all registered agents."""
        agents = list(self.agents.values())
        if enabled_only:
            agents = [a for a in agents if a.enabled]
        return agents
    
    def update_agent(self, agent_id: str, updates: Dict[str, Any]) -> bool:
        """Update agent configuration."""
        if agent_id not in self.agents:
            return False
        agent = self.agents[agent_id]
        for key, value in updates.items():
            if hasattr(agent, key):
                setattr(agent, key, value)
        return True
    
    # ==================== Agent Invocation ====================
    
    async def invoke_agent(
        self,
        agent: AgentConfig,
        prompt: str,
        candidate: CandidateOutput,
        role: AgentRole = AgentRole.SCORER,
        context: Optional[str] = None,
        critique_target: Optional[AgentVote] = None,
    ) -> AgentVote:
        """
        Invoke an agent to evaluate a candidate output.
        
        Args:
            agent: Agent configuration
            prompt: Original prompt/input
            candidate: Output to evaluate
            role: Role the agent is playing
            context: Additional context
            critique_target: Previous vote to critique (for critic role)
        
        Returns:
            AgentVote with evaluation results
        """
        start_time = time.perf_counter()
        
        # Build evaluation prompt
        eval_prompt = self._build_evaluation_prompt(
            agent, prompt, candidate, role, context, critique_target
        )
        
        # Call LLM
        client = self._get_llm_client()
        
        try:
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
                messages=[
                    {"role": "system", "content": agent.system_prompt},
                    {"role": "user", "content": eval_prompt},
                ],
                temperature=agent.temperature,
                max_tokens=agent.max_tokens,
                response_format={"type": "json_object"},
            )
            
            result = json.loads(response.choices[0].message.content)
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            # Parse response into AgentVote
            vote = self._parse_agent_response(agent, role, result, latency_ms)
            vote.tokens_used = response.usage.total_tokens
            
            # Track performance
            self._track_invocation(agent.id, latency_ms, vote)
            
            return vote
            
        except Exception as e:
            if self.verbose:
                print(f"Agent {agent.name} failed: {e}")
            # Return uncertain vote on failure
            return AgentVote(
                agent_id=agent.id,
                agent_name=agent.name,
                persona=agent.persona,
                role=role,
                verdict="uncertain",
                score=0.5,
                confidence=0.0,
                rationale=f"Agent invocation failed: {str(e)}",
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
    
    def _build_evaluation_prompt(
        self,
        agent: AgentConfig,
        prompt: str,
        candidate: CandidateOutput,
        role: AgentRole,
        context: Optional[str],
        critique_target: Optional[AgentVote],
    ) -> str:
        """Build the evaluation prompt for an agent."""
        
        # Base prompt with rubric
        rubric_text = "\n".join([
            f"- {name}: {desc}" 
            for name, desc in agent.rubric.criteria.items()
        ])
        
        base = f"""Evaluate the following output based on these criteria:

{rubric_text}

**Original Prompt:**
{prompt}

**Output to Evaluate:**
{candidate.content}
"""
        
        if context:
            base += f"\n**Additional Context:**\n{context}\n"
        
        # Role-specific instructions
        if role == AgentRole.SCORER:
            base += """
**Instructions:**
Score each criterion from 1-5. Provide an overall verdict (pass/fail/uncertain).
Return JSON with: verdict, score (0-1), confidence (0-1), criterion_scores, rationale
"""
        elif role == AgentRole.CRITIC:
            base += f"""
**Instructions:**
You are acting as a CRITIC. A previous evaluator gave this assessment:

Previous verdict: {critique_target.verdict}
Previous score: {critique_target.score}
Previous rationale: {critique_target.rationale}

Challenge this assessment. Find weaknesses in the reasoning. Identify what was missed.
Return JSON with: verdict, score, confidence, rationale, critique (your challenges)
"""
        elif role == AgentRole.DEFENDER:
            base += f"""
**Instructions:**
You are acting as a DEFENDER. Defend this output against criticism.
Previous critique: {critique_target.critique if critique_target else 'N/A'}

Make the strongest case for the output. Address the criticisms.
Return JSON with: verdict, score, confidence, rationale, defense (your counter-arguments)
"""
        elif role == AgentRole.COMMANDER:
            base += """
**Instructions:**
You are the COMMANDER. Synthesize all evaluations and make a final decision.
Consider all perspectives and resolve any disagreements.
Return JSON with: verdict, score, confidence, rationale
"""
        
        return base
    
    def _parse_agent_response(
        self,
        agent: AgentConfig,
        role: AgentRole,
        result: Dict,
        latency_ms: float,
    ) -> AgentVote:
        """Parse LLM response into AgentVote."""
        return AgentVote(
            agent_id=agent.id,
            agent_name=agent.name,
            persona=agent.persona,
            role=role,
            verdict=result.get("verdict", "uncertain"),
            score=float(result.get("score", 0.5)),
            confidence=float(result.get("confidence", 0.5)),
            criterion_scores=result.get("criterion_scores", {}),
            rationale=result.get("rationale", ""),
            critique=result.get("critique"),
            defense=result.get("defense"),
            latency_ms=latency_ms,
        )
    
    def _track_invocation(self, agent_id: str, latency_ms: float, vote: AgentVote):
        """Track agent invocation for performance monitoring."""
        self._call_history[agent_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "latency_ms": latency_ms,
            "verdict": vote.verdict,
            "confidence": vote.confidence,
        })
        
        # Update rolling average latency
        if agent_id in self.agents:
            history = self._call_history[agent_id][-100:]  # Last 100 calls
            self.agents[agent_id].latency_ms = sum(h["latency_ms"] for h in history) / len(history)
    
    # ==================== Batch Operations ====================
    
    async def invoke_panel(
        self,
        agents: List[AgentConfig],
        prompt: str,
        candidate: CandidateOutput,
        role: AgentRole = AgentRole.SCORER,
        context: Optional[str] = None,
    ) -> List[AgentVote]:
        """Invoke multiple agents in parallel."""
        tasks = [
            self.invoke_agent(agent, prompt, candidate, role, context)
            for agent in agents
        ]
        return await asyncio.gather(*tasks)
    
    # ==================== Weight Adjustment ====================
    
    def adjust_weights_from_accuracy(self, accuracy_scores: Dict[str, float]):
        """
        Adjust agent weights based on accuracy against ground truth.
        
        Higher accuracy -> higher weight in ensemble.
        """
        for agent_id, accuracy in accuracy_scores.items():
            if agent_id in self.agents:
                self._accuracy_history[agent_id].append(accuracy)
                # Rolling average
                recent = self._accuracy_history[agent_id][-20:]
                avg_accuracy = sum(recent) / len(recent)
                
                # Weight = base_weight * (0.5 + accuracy)
                # This gives 0.5x-1.5x multiplier based on accuracy
                base_weight = 1.0
                self.agents[agent_id].weight = base_weight * (0.5 + avg_accuracy)
                self.agents[agent_id].accuracy = avg_accuracy
    
    def adjust_weights_from_consistency(self, consistency_scores: Dict[str, float]):
        """
        Adjust agent weights based on consistency (low IPI = more consistent).
        
        More consistent agents get higher weights.
        """
        for agent_id, consistency in consistency_scores.items():
            if agent_id in self.agents:
                self.agents[agent_id].consistency_score = consistency
                # Boost weight for consistent agents (consistency 0-1 where 1 = perfectly consistent)
                current = self.agents[agent_id].weight
                self.agents[agent_id].weight = current * (0.8 + 0.4 * consistency)
    
    # ==================== Persistence ====================
    
    def save_configs(self, path: Optional[Path] = None):
        """Save agent configurations to file."""
        path = path or self.config_path
        if path is None:
            return
        
        configs = []
        for agent in self.agents.values():
            config_dict = {
                "id": agent.id,
                "name": agent.name,
                "model": agent.model,
                "persona": agent.persona.value,
                "weight": agent.weight,
                "roles": [r.value for r in agent.roles],
                "temperature": agent.temperature,
                "max_tokens": agent.max_tokens,
                "system_prompt": agent.system_prompt,
                "enabled": agent.enabled,
                "fine_tuned": agent.fine_tuned,
                "accuracy": agent.accuracy,
                "consistency_score": agent.consistency_score,
                "latency_ms": agent.latency_ms,
            }
            configs.append(config_dict)
        
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(configs, f, indent=2)
    
    def load_configs(self, path: Path):
        """Load agent configurations from file."""
        if not path.exists():
            return
        
        with open(path) as f:
            configs = json.load(f)
        
        for config in configs:
            agent = AgentConfig(
                id=config["id"],
                name=config["name"],
                model=config.get("model", "gpt-4o"),
                persona=AgentPersona(config["persona"]),
                weight=config.get("weight", 1.0),
                roles=[AgentRole(r) for r in config.get("roles", ["scorer"])],
                temperature=config.get("temperature", 0.3),
                max_tokens=config.get("max_tokens", 1024),
                system_prompt=config.get("system_prompt", ""),
                enabled=config.get("enabled", True),
                fine_tuned=config.get("fine_tuned", False),
                accuracy=config.get("accuracy", 0.0),
                consistency_score=config.get("consistency_score", 0.0),
                latency_ms=config.get("latency_ms", 0.0),
            )
            self.register_agent(agent)
    
    # ==================== Statistics ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics about agent pool."""
        agents = self.list_agents()
        if not agents:
            return {"total_agents": 0}
        
        return {
            "total_agents": len(agents),
            "by_persona": {
                p.value: len(self.get_agents_by_persona(p))
                for p in AgentPersona
            },
            "by_role": {
                r.value: len(self.get_agents_by_role(r))
                for r in AgentRole
            },
            "avg_weight": sum(a.weight for a in agents) / len(agents),
            "avg_accuracy": sum(a.accuracy for a in agents) / len(agents),
            "avg_latency_ms": sum(a.latency_ms for a in agents) / len(agents),
            "fine_tuned_count": sum(1 for a in agents if a.fine_tuned),
        }
