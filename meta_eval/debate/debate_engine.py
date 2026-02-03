"""
DebateEngine - Orchestrates multi-agent debate and consensus.

Implements multiple debate protocols:
- ChatEval: Simple parallel multi-agent scoring
- CourtEval: Adversarial prosecution/defense model
- DEBATE: Structured argumentation rounds with critiques
- MoA: Mixture-of-Agents layered refinement
- Consensus: Iterative agreement-seeking

Each protocol handles role assignment, debate flow, and verdict aggregation.
"""

import asyncio
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
from collections import Counter
import statistics

from ..schemas import (
    AgentConfig, AgentRole, AgentPersona, AgentVote,
    EvaluationRequest, EvaluationResult, CandidateOutput,
    DebateProtocol, AggregationMethod, DebateConfig, DebateRound,
    ConsistencyMetrics
)
from ..agents.manager import AgentManager


class DebateEngine:
    """
    Orchestrates multi-agent debate protocols for evaluation.
    
    Supports multiple debate patterns with configurable:
    - Role assignment strategies
    - Number of debate rounds
    - Consensus thresholds
    - Aggregation methods
    """
    
    def __init__(
        self,
        agent_manager: AgentManager,
        default_config: Optional[DebateConfig] = None,
        verbose: bool = False,
    ):
        self.agent_manager = agent_manager
        self.default_config = default_config or DebateConfig()
        self.verbose = verbose
        
        # Protocol handlers
        self._protocols = {
            DebateProtocol.CHATEVAL: self._run_chateval,
            DebateProtocol.COURTEVAL: self._run_courteval,
            DebateProtocol.DEBATE: self._run_debate,
            DebateProtocol.MOA: self._run_moa,
            DebateProtocol.CONSENSUS: self._run_consensus,
        }
    
    async def evaluate(
        self,
        request: EvaluationRequest,
        config: Optional[DebateConfig] = None,
    ) -> EvaluationResult:
        """
        Run multi-agent evaluation using specified protocol.
        
        Args:
            request: Evaluation request with prompt and candidates
            config: Optional debate configuration override
        
        Returns:
            EvaluationResult with aggregated verdict and agent details
        """
        config = config or self.default_config
        
        # Fast mode: skip debate, single-pass scoring
        if request.fast_mode:
            return await self._run_fast_mode(request)
        
        # Select agents for this evaluation
        agents = self._select_agents(request, config)
        
        if not agents:
            raise ValueError("No agents available for evaluation")
        
        if self.verbose:
            print(f"Running {config.protocol.value} with {len(agents)} agents")
        
        # Run selected protocol
        protocol_handler = self._protocols.get(config.protocol, self._run_chateval)
        debate_rounds, final_votes = await protocol_handler(request, agents, config)
        
        # Aggregate verdicts
        result = self._aggregate_verdicts(
            request, final_votes, debate_rounds, config
        )
        
        return result
    
    def _select_agents(
        self,
        request: EvaluationRequest,
        config: DebateConfig,
    ) -> List[AgentConfig]:
        """Select appropriate agents for the evaluation."""
        agents = []
        
        # If specific agents requested
        if request.required_agents:
            for agent_id in request.required_agents:
                agent = self.agent_manager.get_agent(agent_id)
                if agent and agent.enabled:
                    agents.append(agent)
        
        # If specific personas requested
        elif request.required_personas:
            for persona in request.required_personas:
                persona_agents = self.agent_manager.get_agents_by_persona(persona)
                agents.extend(persona_agents)
        
        # Default: get all enabled agents
        else:
            agents = self.agent_manager.list_agents(enabled_only=True)
        
        # Ensure we have required roles
        if config.require_critic:
            critics = [a for a in agents if AgentRole.CRITIC in a.roles]
            if not critics:
                # Assign highest-weighted agent as critic
                agents_sorted = sorted(agents, key=lambda a: a.weight, reverse=True)
                if agents_sorted:
                    agents_sorted[0].roles.append(AgentRole.CRITIC)
        
        return agents
    
    # ==================== Protocol Implementations ====================
    
    async def _run_fast_mode(self, request: EvaluationRequest) -> EvaluationResult:
        """Single-pass evaluation without debate."""
        agents = self.agent_manager.list_agents(enabled_only=True)[:3]  # Top 3
        
        if not request.candidate_outputs:
            raise ValueError("No candidates to evaluate")
        
        candidate = request.candidate_outputs[0]
        votes = await self.agent_manager.invoke_panel(
            agents, request.prompt, candidate, AgentRole.SCORER, request.context
        )
        
        return self._aggregate_verdicts(
            request, votes, [], 
            DebateConfig(protocol=DebateProtocol.CHATEVAL)
        )
    
    async def _run_chateval(
        self,
        request: EvaluationRequest,
        agents: List[AgentConfig],
        config: DebateConfig,
    ) -> Tuple[List[DebateRound], List[AgentVote]]:
        """
        ChatEval: Simple parallel multi-agent scoring.
        
        All agents evaluate independently, results aggregated.
        """
        if not request.candidate_outputs:
            return [], []
        
        candidate = request.candidate_outputs[0]
        
        # All agents score in parallel
        votes = await self.agent_manager.invoke_panel(
            agents, request.prompt, candidate, AgentRole.SCORER, request.context
        )
        
        round_record = DebateRound(
            round_number=1,
            agent_votes=votes,
            consensus_reached=self._check_consensus(votes, config.consensus_threshold),
            consensus_score=self._calculate_agreement(votes),
        )
        
        return [round_record], votes
    
    async def _run_courteval(
        self,
        request: EvaluationRequest,
        agents: List[AgentConfig],
        config: DebateConfig,
    ) -> Tuple[List[DebateRound], List[AgentVote]]:
        """
        CourtEval: Adversarial prosecution/defense model.
        
        - Prosecution agents argue output is problematic
        - Defense agents argue output is acceptable
        - Commander synthesizes verdict
        """
        if not request.candidate_outputs:
            return [], []
        
        candidate = request.candidate_outputs[0]
        debate_rounds = []
        
        # Assign roles
        prosecution = [a for a in agents if AgentPersona.SAFETY in [a.persona] or 
                      AgentPersona.SECURITY in [a.persona]]
        defense = [a for a in agents if a not in prosecution]
        commander = next((a for a in agents if AgentRole.COMMANDER in a.roles), None)
        
        if not prosecution:
            prosecution = agents[:len(agents)//2]
        if not defense:
            defense = agents[len(agents)//2:]
        
        # Round 1: Initial evaluations
        prosecution_votes = await self.agent_manager.invoke_panel(
            prosecution, request.prompt, candidate, AgentRole.SCORER, 
            context="You are the PROSECUTION. Find problems with this output."
        )
        
        defense_votes = await self.agent_manager.invoke_panel(
            defense, request.prompt, candidate, AgentRole.DEFENDER,
            context="You are the DEFENSE. Argue why this output is acceptable."
        )
        
        round1 = DebateRound(
            round_number=1,
            agent_votes=prosecution_votes + defense_votes,
            consensus_reached=False,
            consensus_score=0.0,
        )
        debate_rounds.append(round1)
        
        # Round 2: Cross-examination (critics respond to each other)
        all_votes = prosecution_votes + defense_votes
        critique_votes = []
        
        for i, vote in enumerate(prosecution_votes):
            # Prosecution critiques defense
            if defense_votes:
                target = defense_votes[i % len(defense_votes)]
                agent = self.agent_manager.get_agent(vote.agent_id)
                if agent:
                    critique = await self.agent_manager.invoke_agent(
                        agent, request.prompt, candidate, 
                        AgentRole.CRITIC, critique_target=target
                    )
                    critique_votes.append(critique)
        
        round2 = DebateRound(
            round_number=2,
            agent_votes=critique_votes,
            consensus_reached=False,
            consensus_score=0.0,
        )
        debate_rounds.append(round2)
        
        # Final: Commander decides
        final_votes = all_votes + critique_votes
        if commander:
            # Build synthesis context from all arguments
            synthesis_context = self._build_synthesis_context(final_votes)
            commander_vote = await self.agent_manager.invoke_agent(
                commander, request.prompt, candidate,
                AgentRole.COMMANDER, context=synthesis_context
            )
            final_votes.append(commander_vote)
            
            round3 = DebateRound(
                round_number=3,
                agent_votes=[commander_vote],
                consensus_reached=True,
                consensus_score=1.0,
                synthesis=commander_vote.rationale,
            )
            debate_rounds.append(round3)
        
        return debate_rounds, final_votes
    
    async def _run_debate(
        self,
        request: EvaluationRequest,
        agents: List[AgentConfig],
        config: DebateConfig,
    ) -> Tuple[List[DebateRound], List[AgentVote]]:
        """
        DEBATE: Structured argumentation rounds.
        
        Multiple rounds of:
        1. Initial scoring
        2. Critic challenges
        3. Responses/defenses
        4. Updated scores
        
        Until consensus or max rounds reached.
        """
        if not request.candidate_outputs:
            return [], []
        
        candidate = request.candidate_outputs[0]
        debate_rounds = []
        current_votes = []
        
        # Get scorers and critics
        scorers = [a for a in agents if AgentRole.SCORER in a.roles]
        critics = [a for a in agents if AgentRole.CRITIC in a.roles]
        
        if not scorers:
            scorers = agents
        
        for round_num in range(1, config.max_rounds + 1):
            if self.verbose:
                print(f"  Debate round {round_num}/{config.max_rounds}")
            
            # Scoring phase
            if round_num == 1:
                # Initial scoring
                current_votes = await self.agent_manager.invoke_panel(
                    scorers, request.prompt, candidate, AgentRole.SCORER, request.context
                )
            else:
                # Re-score considering critiques
                critique_context = self._build_critique_context(debate_rounds[-1].agent_votes)
                current_votes = await self.agent_manager.invoke_panel(
                    scorers, request.prompt, candidate, AgentRole.SCORER,
                    context=f"{request.context or ''}\n\nPrevious critiques to consider:\n{critique_context}"
                )
            
            # Check consensus
            agreement = self._calculate_agreement(current_votes)
            consensus = agreement >= config.consensus_threshold
            
            round_record = DebateRound(
                round_number=round_num,
                agent_votes=current_votes.copy(),
                consensus_reached=consensus,
                consensus_score=agreement,
            )
            
            # Critique phase (if not final round and no consensus)
            if not consensus and round_num < config.max_rounds and critics:
                critique_votes = []
                for critic in critics[:2]:  # Limit critics per round
                    # Critique the majority position
                    target = max(current_votes, key=lambda v: v.confidence)
                    critique = await self.agent_manager.invoke_agent(
                        critic, request.prompt, candidate,
                        AgentRole.CRITIC, critique_target=target
                    )
                    critique_votes.append(critique)
                
                round_record.agent_votes.extend(critique_votes)
            
            debate_rounds.append(round_record)
            
            if consensus and config.early_stop_on_consensus:
                if self.verbose:
                    print(f"  Consensus reached at round {round_num}")
                break
        
        return debate_rounds, current_votes
    
    async def _run_moa(
        self,
        request: EvaluationRequest,
        agents: List[AgentConfig],
        config: DebateConfig,
    ) -> Tuple[List[DebateRound], List[AgentVote]]:
        """
        Mixture-of-Agents: Layered refinement.
        
        Layer 1: Multiple agents generate initial evaluations
        Layer 2: Aggregator agents refine based on Layer 1
        Layer 3: Final synthesizer produces verdict
        """
        if not request.candidate_outputs:
            return [], []
        
        candidate = request.candidate_outputs[0]
        debate_rounds = []
        
        # Layer 1: All agents evaluate independently
        layer1_votes = await self.agent_manager.invoke_panel(
            agents, request.prompt, candidate, AgentRole.SCORER, request.context
        )
        
        round1 = DebateRound(
            round_number=1,
            agent_votes=layer1_votes,
            consensus_reached=False,
            consensus_score=self._calculate_agreement(layer1_votes),
        )
        debate_rounds.append(round1)
        
        # Layer 2: Top agents refine based on Layer 1 outputs
        layer1_summary = self._summarize_votes(layer1_votes)
        top_agents = sorted(agents, key=lambda a: a.weight, reverse=True)[:3]
        
        layer2_votes = await self.agent_manager.invoke_panel(
            top_agents, request.prompt, candidate, AgentRole.SCORER,
            context=f"{request.context or ''}\n\nOther evaluators said:\n{layer1_summary}"
        )
        
        round2 = DebateRound(
            round_number=2,
            agent_votes=layer2_votes,
            consensus_reached=False,
            consensus_score=self._calculate_agreement(layer2_votes),
        )
        debate_rounds.append(round2)
        
        # Layer 3: Commander synthesizes
        commander = next((a for a in agents if AgentRole.COMMANDER in a.roles), top_agents[0])
        
        all_context = f"""
{request.context or ''}

Layer 1 evaluations:
{layer1_summary}

Layer 2 refinements:
{self._summarize_votes(layer2_votes)}

Synthesize a final verdict considering all perspectives.
"""
        
        final_vote = await self.agent_manager.invoke_agent(
            commander, request.prompt, candidate,
            AgentRole.COMMANDER, context=all_context
        )
        
        round3 = DebateRound(
            round_number=3,
            agent_votes=[final_vote],
            consensus_reached=True,
            consensus_score=1.0,
            synthesis=final_vote.rationale,
        )
        debate_rounds.append(round3)
        
        return debate_rounds, layer2_votes + [final_vote]
    
    async def _run_consensus(
        self,
        request: EvaluationRequest,
        agents: List[AgentConfig],
        config: DebateConfig,
    ) -> Tuple[List[DebateRound], List[AgentVote]]:
        """
        Consensus: Iterative agreement-seeking.
        
        Agents see each other's votes and can revise until agreement.
        """
        if not request.candidate_outputs:
            return [], []
        
        candidate = request.candidate_outputs[0]
        debate_rounds = []
        current_votes = []
        
        for round_num in range(1, config.max_rounds + 1):
            if round_num == 1:
                # Initial blind voting
                current_votes = await self.agent_manager.invoke_panel(
                    agents, request.prompt, candidate, AgentRole.SCORER, request.context
                )
            else:
                # Voting with visibility of previous round
                prev_summary = self._summarize_votes(current_votes)
                context = f"{request.context or ''}\n\nOther agents' current positions:\n{prev_summary}\n\nYou may revise your evaluation."
                
                current_votes = await self.agent_manager.invoke_panel(
                    agents, request.prompt, candidate, AgentRole.SCORER, context
                )
            
            agreement = self._calculate_agreement(current_votes)
            consensus = agreement >= config.consensus_threshold
            
            round_record = DebateRound(
                round_number=round_num,
                agent_votes=current_votes.copy(),
                consensus_reached=consensus,
                consensus_score=agreement,
            )
            debate_rounds.append(round_record)
            
            if consensus and config.early_stop_on_consensus:
                break
        
        return debate_rounds, current_votes
    
    # ==================== Aggregation ====================
    
    def _aggregate_verdicts(
        self,
        request: EvaluationRequest,
        votes: List[AgentVote],
        debate_rounds: List[DebateRound],
        config: DebateConfig,
    ) -> EvaluationResult:
        """Aggregate individual votes into final verdict."""
        
        if not votes:
            return EvaluationResult(
                request_id=request.id,
                verdict="uncertain",
                score=0.5,
                confidence=0.0,
                rationale="No agent votes received",
            )
        
        aggregation = request.aggregation
        
        if aggregation == AggregationMethod.MAJORITY_VOTE:
            verdict, score, confidence = self._majority_vote(votes)
        elif aggregation == AggregationMethod.WEIGHTED_SCORE:
            verdict, score, confidence = self._weighted_score(votes)
        elif aggregation == AggregationMethod.COMMANDER_DECIDES:
            verdict, score, confidence = self._commander_decides(votes)
        elif aggregation == AggregationMethod.SYNTHESIS:
            verdict, score, confidence = self._weighted_score(votes)  # Base, synthesis in rationale
        elif aggregation == AggregationMethod.UNANIMOUS:
            verdict, score, confidence = self._unanimous(votes)
        else:
            verdict, score, confidence = self._weighted_score(votes)
        
        # Build rationale
        rationale = self._build_aggregate_rationale(votes, verdict, config)
        
        # Calculate total latency/tokens
        total_latency = sum(v.latency_ms for v in votes)
        total_tokens = sum(v.tokens_used for v in votes)
        
        return EvaluationResult(
            request_id=request.id,
            verdict=verdict,
            score=score,
            confidence=confidence,
            rationale=rationale,
            agent_votes=votes,
            debate_rounds=debate_rounds,
            total_latency_ms=total_latency,
            total_tokens=total_tokens,
            protocol_used=config.protocol,
            aggregation_used=aggregation,
        )
    
    def _majority_vote(self, votes: List[AgentVote]) -> Tuple[str, float, float]:
        """Simple majority vote aggregation."""
        verdict_counts = Counter(v.verdict for v in votes)
        majority_verdict = verdict_counts.most_common(1)[0][0]
        
        agreement = verdict_counts[majority_verdict] / len(votes)
        avg_score = statistics.mean(v.score for v in votes if v.verdict == majority_verdict)
        
        return majority_verdict, avg_score, agreement
    
    def _weighted_score(self, votes: List[AgentVote]) -> Tuple[str, float, float]:
        """Weighted average scoring."""
        # Get agent weights
        total_weight = 0.0
        weighted_score = 0.0
        weighted_confidence = 0.0
        
        for vote in votes:
            agent = self.agent_manager.get_agent(vote.agent_id)
            weight = agent.weight if agent else 1.0
            total_weight += weight
            weighted_score += vote.score * weight
            weighted_confidence += vote.confidence * weight
        
        if total_weight == 0:
            return "uncertain", 0.5, 0.0
        
        final_score = weighted_score / total_weight
        final_confidence = weighted_confidence / total_weight
        
        # Derive verdict from score
        if final_score >= 0.7:
            verdict = "pass"
        elif final_score <= 0.3:
            verdict = "fail"
        else:
            verdict = "uncertain"
        
        return verdict, final_score, final_confidence
    
    def _commander_decides(self, votes: List[AgentVote]) -> Tuple[str, float, float]:
        """Commander agent has final say."""
        commander_votes = [v for v in votes if v.role == AgentRole.COMMANDER]
        if commander_votes:
            v = commander_votes[-1]  # Latest commander vote
            return v.verdict, v.score, v.confidence
        # Fallback to weighted
        return self._weighted_score(votes)
    
    def _unanimous(self, votes: List[AgentVote]) -> Tuple[str, float, float]:
        """Require unanimous agreement."""
        verdicts = set(v.verdict for v in votes)
        if len(verdicts) == 1:
            verdict = verdicts.pop()
            avg_score = statistics.mean(v.score for v in votes)
            avg_conf = statistics.mean(v.confidence for v in votes)
            return verdict, avg_score, avg_conf
        return "uncertain", 0.5, 0.0
    
    # ==================== Helpers ====================
    
    def _check_consensus(self, votes: List[AgentVote], threshold: float) -> bool:
        """Check if votes have reached consensus."""
        return self._calculate_agreement(votes) >= threshold
    
    def _calculate_agreement(self, votes: List[AgentVote]) -> float:
        """Calculate agreement level among votes (0-1)."""
        if not votes:
            return 0.0
        
        verdict_counts = Counter(v.verdict for v in votes)
        max_agreement = verdict_counts.most_common(1)[0][1]
        return max_agreement / len(votes)
    
    def _build_synthesis_context(self, votes: List[AgentVote]) -> str:
        """Build context summarizing all votes for synthesis."""
        lines = ["Summary of all evaluations:"]
        for vote in votes:
            lines.append(f"- {vote.agent_name} ({vote.role.value}): {vote.verdict} (score={vote.score:.2f})")
            if vote.rationale:
                lines.append(f"  Rationale: {vote.rationale[:200]}...")
            if vote.critique:
                lines.append(f"  Critique: {vote.critique[:200]}...")
        return "\n".join(lines)
    
    def _build_critique_context(self, votes: List[AgentVote]) -> str:
        """Build context from critique votes."""
        critiques = [v for v in votes if v.critique]
        if not critiques:
            return "No critiques from previous round."
        return "\n".join([f"- {v.agent_name}: {v.critique}" for v in critiques])
    
    def _summarize_votes(self, votes: List[AgentVote]) -> str:
        """Summarize votes for context."""
        lines = []
        for vote in votes:
            lines.append(f"- {vote.agent_name}: {vote.verdict} (score={vote.score:.2f}, confidence={vote.confidence:.2f})")
        return "\n".join(lines)
    
    def _build_aggregate_rationale(
        self,
        votes: List[AgentVote],
        verdict: str,
        config: DebateConfig,
    ) -> str:
        """Build final rationale from aggregated votes."""
        # Count verdicts
        verdict_counts = Counter(v.verdict for v in votes)
        
        lines = [
            f"Verdict: {verdict.upper()}",
            f"Protocol: {config.protocol.value}",
            f"Agent agreement: {verdict_counts}",
            "",
            "Key findings:",
        ]
        
        # Include rationales from high-confidence votes
        top_votes = sorted(votes, key=lambda v: v.confidence, reverse=True)[:3]
        for vote in top_votes:
            if vote.rationale:
                lines.append(f"- [{vote.agent_name}] {vote.rationale[:300]}")
        
        return "\n".join(lines)
