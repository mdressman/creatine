"""
ConsistencyChecker - Measures evaluation consistency and reliability.

Implements metrics from "Are We on the Right Way to Assessing LLM-as-a-Judge?":
- Intra-Pair Instability (IPI): Detects preference flips under A/B reordering
- Weak Total Order Violation (TOV): Detects transitivity violations

Also provides:
- Per-agent consistency tracking
- Human alignment measurement
- Calibration metrics
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any, Set
from itertools import combinations, permutations
import statistics

from ..schemas import (
    AgentConfig, AgentVote, EvaluationRequest, EvaluationResult,
    ConsistencyMetrics, CandidateOutput, DebateProtocol
)
from ..agents.manager import AgentManager
from ..debate.debate_engine import DebateEngine


@dataclass
class PairwiseComparison:
    """Record of a pairwise comparison for consistency analysis."""
    output_a_id: str
    output_b_id: str
    winner: str  # 'a', 'b', or 'tie'
    agent_id: str
    score_a: float
    score_b: float
    order: str  # 'ab' or 'ba' - presentation order


@dataclass
class ConsistencyReport:
    """Detailed report on evaluation consistency."""
    metrics: ConsistencyMetrics
    
    # IPI details
    ipi_violations: List[Dict[str, Any]] = field(default_factory=list)
    
    # TOV details  
    tov_violations: List[Tuple[str, str, str]] = field(default_factory=list)  # (A>B, B>C, but C>=A)
    
    # Per-agent breakdown
    agent_ipi: Dict[str, float] = field(default_factory=dict)
    agent_tov: Dict[str, float] = field(default_factory=dict)
    
    # Recommendations
    unreliable_agents: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ConsistencyChecker:
    """
    Measures and tracks evaluation consistency across the agent panel.
    
    Key metrics:
    - IPI (Intra-Pair Instability): Do agents flip preferences when A/B order swapped?
    - TOV (Total Order Violation): Are preferences transitive? (A>B, B>C => A>C?)
    
    Usage:
        checker = ConsistencyChecker(agent_manager, debate_engine)
        report = await checker.run_consistency_check(test_samples)
    """
    
    def __init__(
        self,
        agent_manager: AgentManager,
        debate_engine: Optional[DebateEngine] = None,
        verbose: bool = False,
    ):
        self.agent_manager = agent_manager
        self.debate_engine = debate_engine or DebateEngine(agent_manager)
        self.verbose = verbose
        
        # History for tracking
        self._comparison_history: List[PairwiseComparison] = []
        self._consistency_cache: Dict[str, ConsistencyMetrics] = {}
    
    # ==================== IPI (Intra-Pair Instability) ====================
    
    async def measure_ipi(
        self,
        prompt: str,
        output_a: str,
        output_b: str,
        agents: Optional[List[AgentConfig]] = None,
    ) -> Tuple[float, List[Dict]]:
        """
        Measure IPI by evaluating same pair in both orders.
        
        IPI = fraction of agents that flip their preference when order swapped.
        
        Args:
            prompt: The original prompt
            output_a: First candidate output
            output_b: Second candidate output
            agents: Agents to test (default: all enabled)
        
        Returns:
            (ipi_score, list of violations)
        """
        agents = agents or self.agent_manager.list_agents(enabled_only=True)
        violations = []
        flip_count = 0
        
        for agent in agents:
            # Evaluate A vs B (A first)
            result_ab = await self._evaluate_pair(
                agent, prompt, output_a, output_b, order='ab'
            )
            
            # Evaluate B vs A (B first)  
            result_ba = await self._evaluate_pair(
                agent, prompt, output_b, output_a, order='ba'
            )
            
            # Check for flip
            winner_ab = result_ab['winner']
            winner_ba = 'b' if result_ba['winner'] == 'a' else ('a' if result_ba['winner'] == 'b' else 'tie')
            
            if winner_ab != winner_ba:
                flip_count += 1
                violations.append({
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'order_ab': winner_ab,
                    'order_ba': winner_ba,
                    'score_diff_ab': result_ab['score_a'] - result_ab['score_b'],
                    'score_diff_ba': result_ba['score_a'] - result_ba['score_b'],
                })
                
                if self.verbose:
                    print(f"  IPI violation: {agent.name} flipped {winner_ab}->{winner_ba}")
            
            # Record comparisons
            self._comparison_history.append(PairwiseComparison(
                output_a_id=f"a_{hash(output_a)%10000}",
                output_b_id=f"b_{hash(output_b)%10000}",
                winner=winner_ab,
                agent_id=agent.id,
                score_a=result_ab['score_a'],
                score_b=result_ab['score_b'],
                order='ab',
            ))
        
        ipi = flip_count / len(agents) if agents else 0.0
        return ipi, violations
    
    async def _evaluate_pair(
        self,
        agent: AgentConfig,
        prompt: str,
        output_first: str,
        output_second: str,
        order: str,
    ) -> Dict[str, Any]:
        """Evaluate a pair of outputs with specified order."""
        
        # Create evaluation request for pairwise comparison
        comparison_prompt = f"""Compare these two outputs and determine which is better.

**Prompt:** {prompt}

**Output A:**
{output_first}

**Output B:**  
{output_second}

Score each output 0-1 and indicate the winner (a, b, or tie).
Return JSON: {{"score_a": float, "score_b": float, "winner": "a"|"b"|"tie", "rationale": string}}
"""
        
        candidate = CandidateOutput(content=comparison_prompt)
        vote = await self.agent_manager.invoke_agent(
            agent, prompt, candidate
        )
        
        # Parse scores from rationale or use overall score
        # In practice, we'd parse the JSON response
        score_a = vote.score
        score_b = 1.0 - vote.score  # Simplified
        
        if vote.verdict == "pass":
            winner = "a"
        elif vote.verdict == "fail":
            winner = "b"
        else:
            winner = "tie"
        
        return {
            'score_a': score_a,
            'score_b': score_b,
            'winner': winner,
            'rationale': vote.rationale,
        }
    
    # ==================== TOV (Total Order Violation) ====================
    
    async def measure_tov(
        self,
        prompt: str,
        outputs: List[str],
        agents: Optional[List[AgentConfig]] = None,
    ) -> Tuple[float, List[Tuple[str, str, str]]]:
        """
        Measure TOV by checking transitivity of preferences.
        
        For all triples (A, B, C), if A>B and B>C, then A>C should hold.
        TOV = fraction of triples that violate transitivity.
        
        Args:
            prompt: The original prompt
            outputs: List of candidate outputs (minimum 3)
            agents: Agents to test (default: all enabled)
        
        Returns:
            (tov_score, list of violations as (A, B, C) tuples)
        """
        if len(outputs) < 3:
            return 0.0, []
        
        agents = agents or self.agent_manager.list_agents(enabled_only=True)
        
        # Build preference graph for each agent
        all_violations = []
        agent_violation_counts = defaultdict(int)
        total_triples = 0
        
        for agent in agents:
            preferences = await self._build_preference_graph(agent, prompt, outputs)
            violations = self._find_transitivity_violations(preferences, outputs)
            
            all_violations.extend(violations)
            agent_violation_counts[agent.id] = len(violations)
            total_triples += len(list(combinations(range(len(outputs)), 3)))
            
            if self.verbose and violations:
                print(f"  TOV violations for {agent.name}: {len(violations)}")
        
        tov = len(all_violations) / total_triples if total_triples > 0 else 0.0
        return tov, all_violations
    
    async def _build_preference_graph(
        self,
        agent: AgentConfig,
        prompt: str,
        outputs: List[str],
    ) -> Dict[Tuple[int, int], str]:
        """Build pairwise preference graph for an agent."""
        preferences = {}
        
        for i, j in combinations(range(len(outputs)), 2):
            result = await self._evaluate_pair(
                agent, prompt, outputs[i], outputs[j], order='ab'
            )
            # Store as (i,j) -> winner
            preferences[(i, j)] = result['winner']
        
        return preferences
    
    def _find_transitivity_violations(
        self,
        preferences: Dict[Tuple[int, int], str],
        outputs: List[str],
    ) -> List[Tuple[str, str, str]]:
        """Find transitivity violations in preference graph."""
        violations = []
        n = len(outputs)
        
        for i, j, k in combinations(range(n), 3):
            # Get preferences for all pairs
            pref_ij = preferences.get((i, j)) or preferences.get((j, i), 'tie')
            pref_jk = preferences.get((j, k)) or preferences.get((k, j), 'tie')
            pref_ik = preferences.get((i, k)) or preferences.get((k, i), 'tie')
            
            # Normalize direction
            if (j, i) in preferences:
                pref_ij = 'b' if preferences[(j, i)] == 'a' else ('a' if preferences[(j, i)] == 'b' else 'tie')
            if (k, j) in preferences:
                pref_jk = 'b' if preferences[(k, j)] == 'a' else ('a' if preferences[(k, j)] == 'b' else 'tie')
            if (k, i) in preferences:
                pref_ik = 'b' if preferences[(k, i)] == 'a' else ('a' if preferences[(k, i)] == 'b' else 'tie')
            
            # Check transitivity: if i>j and j>k, then i>k
            # pref_ij == 'a' means i > j
            # pref_jk == 'a' means j > k
            # pref_ik should be 'a' (i > k)
            
            if pref_ij == 'a' and pref_jk == 'a' and pref_ik != 'a':
                violations.append((f"output_{i}", f"output_{j}", f"output_{k}"))
        
        return violations
    
    # ==================== Full Consistency Check ====================
    
    async def run_consistency_check(
        self,
        test_samples: List[Dict[str, Any]],
        agents: Optional[List[AgentConfig]] = None,
    ) -> ConsistencyReport:
        """
        Run comprehensive consistency check on test samples.
        
        Args:
            test_samples: List of {prompt, outputs: [str, str, ...]} dicts
            agents: Agents to test (default: all enabled)
        
        Returns:
            ConsistencyReport with detailed metrics
        """
        agents = agents or self.agent_manager.list_agents(enabled_only=True)
        
        all_ipi_violations = []
        all_tov_violations = []
        agent_ipi_scores = defaultdict(list)
        agent_tov_scores = defaultdict(list)
        
        total_ipi_samples = 0
        total_tov_samples = 0
        
        for sample in test_samples:
            prompt = sample['prompt']
            outputs = sample['outputs']
            
            if self.verbose:
                print(f"Checking consistency for: {prompt[:50]}...")
            
            # IPI check (if 2+ outputs)
            if len(outputs) >= 2:
                ipi, violations = await self.measure_ipi(
                    prompt, outputs[0], outputs[1], agents
                )
                all_ipi_violations.extend(violations)
                total_ipi_samples += 1
                
                for v in violations:
                    agent_ipi_scores[v['agent_id']].append(1.0)
                for agent in agents:
                    if agent.id not in [v['agent_id'] for v in violations]:
                        agent_ipi_scores[agent.id].append(0.0)
            
            # TOV check (if 3+ outputs)
            if len(outputs) >= 3:
                tov, violations = await self.measure_tov(prompt, outputs, agents)
                all_tov_violations.extend(violations)
                total_tov_samples += 1
        
        # Calculate aggregate metrics
        overall_ipi = len(all_ipi_violations) / (total_ipi_samples * len(agents)) if total_ipi_samples else 0.0
        overall_tov = len(all_tov_violations) / total_tov_samples if total_tov_samples else 0.0
        
        # Per-agent consistency
        agent_ipi = {
            aid: statistics.mean(scores) if scores else 0.0
            for aid, scores in agent_ipi_scores.items()
        }
        
        # Identify unreliable agents (high IPI)
        unreliable = [
            aid for aid, ipi in agent_ipi.items()
            if ipi > 0.3  # More than 30% flip rate
        ]
        
        # Generate recommendations
        recommendations = []
        if overall_ipi > 0.2:
            recommendations.append("High IPI detected. Consider adding position debiasing.")
        if overall_tov > 0.1:
            recommendations.append("Transitivity violations detected. Review agent prompts for consistency.")
        if unreliable:
            agent_names = [self.agent_manager.get_agent(a).name for a in unreliable if self.agent_manager.get_agent(a)]
            recommendations.append(f"Consider retraining or removing unreliable agents: {agent_names}")
        
        metrics = ConsistencyMetrics(
            ipi=overall_ipi,
            ipi_samples=total_ipi_samples,
            tov=overall_tov,
            tov_samples=total_tov_samples,
            transitivity_violations=all_tov_violations,
            agent_consistency={aid: 1.0 - ipi for aid, ipi in agent_ipi.items()},
        )
        
        return ConsistencyReport(
            metrics=metrics,
            ipi_violations=all_ipi_violations,
            tov_violations=all_tov_violations,
            agent_ipi=agent_ipi,
            agent_tov={},  # Would need per-agent TOV tracking
            unreliable_agents=unreliable,
            recommendations=recommendations,
        )
    
    # ==================== Human Alignment ====================
    
    def measure_human_alignment(
        self,
        agent_verdicts: List[Tuple[str, str]],  # (agent_verdict, human_label)
    ) -> float:
        """
        Measure agreement between agent verdicts and human labels.
        
        Args:
            agent_verdicts: List of (agent_verdict, human_label) pairs
        
        Returns:
            Agreement rate (0-1)
        """
        if not agent_verdicts:
            return 0.0
        
        agreements = sum(1 for av, hl in agent_verdicts if av == hl)
        return agreements / len(agent_verdicts)
    
    # ==================== Confidence Calibration ====================
    
    def measure_calibration(
        self,
        predictions: List[Tuple[float, bool]],  # (confidence, was_correct)
        num_bins: int = 10,
    ) -> float:
        """
        Measure calibration of confidence scores.
        
        Well-calibrated: 70% confidence predictions should be correct 70% of time.
        
        Returns:
            Expected Calibration Error (ECE) - lower is better
        """
        if not predictions:
            return 0.0
        
        bins = defaultdict(list)
        for conf, correct in predictions:
            bin_idx = min(int(conf * num_bins), num_bins - 1)
            bins[bin_idx].append((conf, correct))
        
        ece = 0.0
        total = len(predictions)
        
        for bin_idx, bin_preds in bins.items():
            if not bin_preds:
                continue
            
            avg_conf = statistics.mean(p[0] for p in bin_preds)
            accuracy = statistics.mean(1 if p[1] else 0 for p in bin_preds)
            
            ece += (len(bin_preds) / total) * abs(avg_conf - accuracy)
        
        return ece
    
    # ==================== Statistics ====================
    
    def get_agent_reliability_scores(self) -> Dict[str, float]:
        """
        Get reliability scores for all agents based on historical consistency.
        
        Reliability = 1 - IPI (lower flip rate = more reliable)
        """
        agent_flips = defaultdict(lambda: {'flips': 0, 'total': 0})
        
        # Analyze comparison history for each agent
        comparisons_by_pair = defaultdict(list)
        for comp in self._comparison_history:
            key = (comp.output_a_id, comp.output_b_id, comp.agent_id)
            comparisons_by_pair[key].append(comp)
        
        # Count flips for repeated comparisons
        for key, comps in comparisons_by_pair.items():
            if len(comps) >= 2:
                agent_id = key[2]
                winners = [c.winner for c in comps]
                if len(set(winners)) > 1:  # Flip detected
                    agent_flips[agent_id]['flips'] += 1
                agent_flips[agent_id]['total'] += 1
        
        reliability = {}
        for agent_id, data in agent_flips.items():
            if data['total'] > 0:
                flip_rate = data['flips'] / data['total']
                reliability[agent_id] = 1.0 - flip_rate
            else:
                reliability[agent_id] = 1.0  # No data, assume reliable
        
        return reliability
    
    def reset_history(self):
        """Clear comparison history."""
        self._comparison_history = []
        self._consistency_cache = {}
