"""Tests for ConsistencyChecker IPI and TOV metrics."""
import pytest
import asyncio
from unittest.mock import Mock, patch

from meta_eval.schemas import (
    AgentConfig, AgentPersona, AgentVote, CandidateOutput
)
from meta_eval.agents.manager import AgentManager
from meta_eval.consistency.checker import ConsistencyChecker, PairwiseComparison


class TestIPIMetric:
    """Tests for Intra-Pair Instability (IPI) measurement."""
    
    @pytest.fixture
    def manager(self):
        manager = AgentManager(auto_load_samples=False)
        for i in range(3):
            manager.register_agent(AgentConfig(
                id=f"agent_{i}",
                name=f"Agent_{i}",
                persona=AgentPersona.SAFETY,
            ))
        return manager
    
    @pytest.fixture
    def checker(self, manager):
        return ConsistencyChecker(manager, verbose=False)
    
    def test_ipi_zero_when_consistent(self, checker, manager):
        """IPI should be 0 when agents are perfectly consistent."""
        # Mock consistent evaluations (same winner regardless of order)
        async def mock_evaluate_pair(agent, prompt, a, b, order):
            return {"winner": "a", "score_a": 0.8, "score_b": 0.4, "rationale": "A is better"}
        
        with patch.object(checker, '_evaluate_pair', side_effect=mock_evaluate_pair):
            ipi, violations = asyncio.get_event_loop().run_until_complete(
                checker.measure_ipi("prompt", "output_a", "output_b")
            )
            
            assert ipi == 0.0
            assert len(violations) == 0
    
    def test_ipi_nonzero_when_inconsistent(self, checker, manager):
        """IPI should be > 0 when agents flip preferences."""
        call_count = [0]
        
        async def mock_evaluate_pair(agent, prompt, a, b, order):
            call_count[0] += 1
            # Flip winner based on order for some agents
            if agent.id == "agent_0":
                return {"winner": "a" if order == "ab" else "b", "score_a": 0.6, "score_b": 0.5}
            return {"winner": "a", "score_a": 0.8, "score_b": 0.4}
        
        with patch.object(checker, '_evaluate_pair', side_effect=mock_evaluate_pair):
            ipi, violations = asyncio.get_event_loop().run_until_complete(
                checker.measure_ipi("prompt", "output_a", "output_b")
            )
            
            assert ipi > 0  # At least agent_0 flipped
            assert any(v["agent_id"] == "agent_0" for v in violations)
    
    def test_ipi_all_flip(self, checker, manager):
        """IPI should be 1.0 when all agents flip."""
        async def mock_evaluate_pair(agent, prompt, a, b, order):
            # All agents flip
            return {"winner": "a" if order == "ab" else "b", "score_a": 0.6, "score_b": 0.5}
        
        with patch.object(checker, '_evaluate_pair', side_effect=mock_evaluate_pair):
            ipi, violations = asyncio.get_event_loop().run_until_complete(
                checker.measure_ipi("prompt", "output_a", "output_b")
            )
            
            assert ipi == 1.0
            assert len(violations) == 3


class TestTOVMetric:
    """Tests for Total Order Violation (TOV) measurement."""
    
    def test_tov_zero_when_transitive(self):
        """TOV should be 0 when preferences are transitive."""
        manager = AgentManager(auto_load_samples=False)
        manager.register_agent(AgentConfig(id="agent_0", name="Agent", persona=AgentPersona.SAFETY))
        checker = ConsistencyChecker(manager)
        
        # Transitive: A > B, B > C, A > C
        preferences = {
            (0, 1): "a",  # A > B
            (1, 2): "a",  # B > C
            (0, 2): "a",  # A > C (transitive)
        }
        
        violations = checker._find_transitivity_violations(preferences, ["a", "b", "c"])
        
        assert len(violations) == 0
    
    def test_tov_detects_violation(self):
        """TOV should detect transitivity violations."""
        manager = AgentManager(auto_load_samples=False)
        manager.register_agent(AgentConfig(id="agent_0", name="Agent", persona=AgentPersona.SAFETY))
        checker = ConsistencyChecker(manager)
        
        # Non-transitive: A > B, B > C, but C > A (cycle!)
        preferences = {
            (0, 1): "a",  # A > B
            (1, 2): "a",  # B > C  
            (0, 2): "b",  # C > A (violation!)
        }
        
        violations = checker._find_transitivity_violations(preferences, ["a", "b", "c"])
        
        assert len(violations) == 1


class TestHumanAlignment:
    """Tests for human alignment measurement."""
    
    def test_perfect_alignment(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        verdicts = [
            ("pass", "pass"),
            ("fail", "fail"),
            ("pass", "pass"),
        ]
        
        agreement = checker.measure_human_alignment(verdicts)
        
        assert agreement == 1.0
    
    def test_no_alignment(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        verdicts = [
            ("pass", "fail"),
            ("fail", "pass"),
            ("pass", "fail"),
        ]
        
        agreement = checker.measure_human_alignment(verdicts)
        
        assert agreement == 0.0
    
    def test_partial_alignment(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        verdicts = [
            ("pass", "pass"),
            ("fail", "pass"),
            ("pass", "pass"),
        ]
        
        agreement = checker.measure_human_alignment(verdicts)
        
        assert agreement == pytest.approx(2/3, rel=0.01)


class TestCalibration:
    """Tests for confidence calibration measurement."""
    
    def test_perfect_calibration(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        # Perfect calibration: 80% confidence, 80% correct
        predictions = [(0.8, True)] * 8 + [(0.8, False)] * 2
        
        ece = checker.measure_calibration(predictions, num_bins=10)
        
        # ECE should be very low for well-calibrated predictions
        assert ece < 0.1
    
    def test_overconfident(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        # Overconfident: 90% confidence but only 50% correct
        predictions = [(0.9, True)] * 5 + [(0.9, False)] * 5
        
        ece = checker.measure_calibration(predictions, num_bins=10)
        
        # ECE should be high (0.4 difference between confidence and accuracy)
        assert ece > 0.3


class TestConsistencyReport:
    """Tests for full consistency check reports."""
    
    @pytest.fixture
    def manager(self):
        manager = AgentManager(auto_load_samples=False)
        manager.register_agent(AgentConfig(
            id="test_agent", name="Test", persona=AgentPersona.SAFETY
        ))
        return manager
    
    @pytest.mark.asyncio
    async def test_consistency_report_structure(self, manager):
        """Test consistency report has all required fields."""
        checker = ConsistencyChecker(manager)
        
        async def mock_ipi(*args, **kwargs):
            return 0.1, []
        
        async def mock_tov(*args, **kwargs):
            return 0.05, []
        
        with patch.object(checker, 'measure_ipi', side_effect=mock_ipi):
            with patch.object(checker, 'measure_tov', side_effect=mock_tov):
                samples = [
                    {"prompt": "Test", "outputs": ["A", "B"]},
                ]
                
                report = await checker.run_consistency_check(samples)
                
                assert hasattr(report, 'metrics')
                assert hasattr(report.metrics, 'ipi')
                assert hasattr(report.metrics, 'tov')
                assert hasattr(report, 'recommendations')


class TestAgentReliability:
    """Tests for per-agent reliability scoring."""
    
    def test_reliability_scores_from_history(self):
        manager = AgentManager(auto_load_samples=False)
        checker = ConsistencyChecker(manager)
        
        # Add some comparison history
        checker._comparison_history = [
            PairwiseComparison("a", "b", "a", "agent_1", 0.8, 0.4, "ab"),
            PairwiseComparison("a", "b", "a", "agent_1", 0.8, 0.4, "ba"),  # Same winner = consistent
            PairwiseComparison("a", "b", "a", "agent_2", 0.8, 0.4, "ab"),
            PairwiseComparison("a", "b", "b", "agent_2", 0.4, 0.8, "ba"),  # Different = flip
        ]
        
        reliability = checker.get_agent_reliability_scores()
        
        assert "agent_1" in reliability
        assert "agent_2" in reliability
        assert reliability["agent_1"] > reliability["agent_2"]  # agent_1 more reliable


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
