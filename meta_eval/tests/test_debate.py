"""Tests for DebateEngine protocols."""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from meta_eval.schemas import (
    AgentConfig, AgentPersona, AgentRole, AgentVote, 
    EvaluationRequest, CandidateOutput, DebateProtocol,
    AggregationMethod, DebateConfig
)
from meta_eval.agents.manager import AgentManager
from meta_eval.debate.debate_engine import DebateEngine


def create_mock_vote(agent_id: str, verdict: str, score: float, confidence: float = 0.8) -> AgentVote:
    """Helper to create mock AgentVote."""
    return AgentVote(
        agent_id=agent_id,
        agent_name=f"Agent_{agent_id}",
        persona=AgentPersona.SAFETY,
        role=AgentRole.SCORER,
        verdict=verdict,
        score=score,
        confidence=confidence,
        rationale="Test rationale",
    )


class TestDebateEngine:
    """Tests for DebateEngine protocol implementations."""
    
    @pytest.fixture
    def manager(self):
        """Create agent manager with test agents."""
        manager = AgentManager(auto_load_samples=False)
        
        for i in range(3):
            agent = AgentConfig(
                id=f"agent_{i}",
                name=f"TestAgent_{i}",
                persona=AgentPersona.SAFETY,
                roles=[AgentRole.SCORER, AgentRole.CRITIC],
                weight=1.0,
            )
            manager.register_agent(agent)
        
        return manager
    
    @pytest.fixture
    def engine(self, manager):
        """Create debate engine."""
        return DebateEngine(manager, verbose=False)
    
    def test_select_agents_default(self, engine, manager):
        """Test default agent selection."""
        request = EvaluationRequest(prompt="Test")
        config = DebateConfig()
        
        agents = engine._select_agents(request, config)
        
        assert len(agents) == 3
    
    def test_select_agents_by_id(self, engine, manager):
        """Test agent selection by specific IDs."""
        request = EvaluationRequest(
            prompt="Test",
            required_agents=["agent_0", "agent_1"],
        )
        config = DebateConfig()
        
        agents = engine._select_agents(request, config)
        
        assert len(agents) == 2
        assert all(a.id in ["agent_0", "agent_1"] for a in agents)
    
    def test_select_agents_by_persona(self, engine, manager):
        """Test agent selection by persona."""
        # Add agent with different persona
        manager.register_agent(AgentConfig(
            id="factuality_agent",
            name="Factuality",
            persona=AgentPersona.FACTUALITY,
        ))
        
        request = EvaluationRequest(
            prompt="Test",
            required_personas=[AgentPersona.FACTUALITY],
        )
        config = DebateConfig()
        
        agents = engine._select_agents(request, config)
        
        assert len(agents) == 1
        assert agents[0].persona == AgentPersona.FACTUALITY
    
    def test_calculate_agreement_unanimous(self, engine):
        """Test agreement calculation with unanimous votes."""
        votes = [
            create_mock_vote("a", "pass", 0.8),
            create_mock_vote("b", "pass", 0.85),
            create_mock_vote("c", "pass", 0.9),
        ]
        
        agreement = engine._calculate_agreement(votes)
        
        assert agreement == 1.0
    
    def test_calculate_agreement_split(self, engine):
        """Test agreement calculation with split votes."""
        votes = [
            create_mock_vote("a", "pass", 0.8),
            create_mock_vote("b", "pass", 0.85),
            create_mock_vote("c", "fail", 0.9),
        ]
        
        agreement = engine._calculate_agreement(votes)
        
        assert agreement == pytest.approx(2/3, rel=0.01)
    
    def test_check_consensus_reached(self, engine):
        """Test consensus detection."""
        votes = [
            create_mock_vote("a", "pass", 0.8),
            create_mock_vote("b", "pass", 0.85),
            create_mock_vote("c", "pass", 0.9),
        ]
        
        assert engine._check_consensus(votes, threshold=0.8) is True
        assert engine._check_consensus(votes, threshold=1.0) is True
    
    def test_check_consensus_not_reached(self, engine):
        """Test when consensus not reached."""
        votes = [
            create_mock_vote("a", "pass", 0.8),
            create_mock_vote("b", "fail", 0.85),
            create_mock_vote("c", "uncertain", 0.9),
        ]
        
        assert engine._check_consensus(votes, threshold=0.8) is False


class TestAggregationMethods:
    """Tests for verdict aggregation methods."""
    
    @pytest.fixture
    def engine(self):
        manager = AgentManager(auto_load_samples=False)
        for i, weight in enumerate([1.0, 2.0, 0.5]):
            manager.register_agent(AgentConfig(
                id=f"agent_{i}",
                name=f"Agent_{i}",
                persona=AgentPersona.SAFETY,
                weight=weight,
            ))
        return DebateEngine(manager)
    
    def test_majority_vote(self, engine):
        """Test majority vote aggregation."""
        votes = [
            create_mock_vote("agent_0", "pass", 0.8),
            create_mock_vote("agent_1", "pass", 0.9),
            create_mock_vote("agent_2", "fail", 0.7),
        ]
        
        verdict, score, confidence = engine._majority_vote(votes)
        
        assert verdict == "pass"
        assert confidence == pytest.approx(2/3, rel=0.01)
    
    def test_weighted_score_pass(self, engine):
        """Test weighted score aggregation resulting in pass."""
        votes = [
            create_mock_vote("agent_0", "pass", 0.8),  # weight 1.0
            create_mock_vote("agent_1", "pass", 0.9),  # weight 2.0
            create_mock_vote("agent_2", "fail", 0.3),  # weight 0.5
        ]
        
        verdict, score, confidence = engine._weighted_score(votes)
        
        # Weighted score: (0.8*1.0 + 0.9*2.0 + 0.3*0.5) / 3.5 = 2.75/3.5 ≈ 0.786
        assert verdict == "pass"
        assert score > 0.7
    
    def test_weighted_score_fail(self, engine):
        """Test weighted score aggregation resulting in fail."""
        votes = [
            create_mock_vote("agent_0", "fail", 0.2),
            create_mock_vote("agent_1", "fail", 0.1),
            create_mock_vote("agent_2", "fail", 0.3),
        ]
        
        verdict, score, confidence = engine._weighted_score(votes)
        
        assert verdict == "fail"
        assert score < 0.3
    
    def test_unanimous_pass(self, engine):
        """Test unanimous aggregation when all agree."""
        votes = [
            create_mock_vote("agent_0", "pass", 0.8),
            create_mock_vote("agent_1", "pass", 0.9),
            create_mock_vote("agent_2", "pass", 0.85),
        ]
        
        verdict, score, confidence = engine._unanimous(votes)
        
        assert verdict == "pass"
    
    def test_unanimous_uncertain(self, engine):
        """Test unanimous aggregation when not all agree."""
        votes = [
            create_mock_vote("agent_0", "pass", 0.8),
            create_mock_vote("agent_1", "pass", 0.9),
            create_mock_vote("agent_2", "fail", 0.7),
        ]
        
        verdict, score, confidence = engine._unanimous(votes)
        
        assert verdict == "uncertain"
        assert confidence == 0.0


class TestDebateProtocols:
    """Integration tests for debate protocols."""
    
    @pytest.fixture
    def manager(self):
        manager = AgentManager(auto_load_samples=False)
        
        # Add various agents
        manager.register_agent(AgentConfig(
            id="scorer_1", name="Scorer1", persona=AgentPersona.SAFETY,
            roles=[AgentRole.SCORER]
        ))
        manager.register_agent(AgentConfig(
            id="scorer_2", name="Scorer2", persona=AgentPersona.SECURITY,
            roles=[AgentRole.SCORER]
        ))
        manager.register_agent(AgentConfig(
            id="critic", name="Critic", persona=AgentPersona.SAFETY,
            roles=[AgentRole.CRITIC]
        ))
        manager.register_agent(AgentConfig(
            id="commander", name="Commander", persona=AgentPersona.SAFETY,
            roles=[AgentRole.COMMANDER]
        ))
        
        return manager
    
    @pytest.mark.asyncio
    async def test_chateval_protocol(self, manager):
        """Test ChatEval protocol runs successfully."""
        engine = DebateEngine(manager)
        
        # Mock agent invocations
        async def mock_invoke(*args, **kwargs):
            return create_mock_vote("test", "pass", 0.8)
        
        with patch.object(manager, 'invoke_agent', side_effect=mock_invoke):
            request = EvaluationRequest(
                prompt="Test prompt",
                candidate_outputs=[CandidateOutput(content="Test output")],
                protocol=DebateProtocol.CHATEVAL,
            )
            
            result = await engine.evaluate(request)
            
            assert result.verdict in ["pass", "fail", "uncertain"]
            assert len(result.debate_rounds) == 1
            assert result.protocol_used == DebateProtocol.CHATEVAL
    
    @pytest.mark.asyncio
    async def test_fast_mode(self, manager):
        """Test fast mode skips debate."""
        engine = DebateEngine(manager)
        
        async def mock_invoke(*args, **kwargs):
            return create_mock_vote("test", "pass", 0.85)
        
        with patch.object(manager, 'invoke_agent', side_effect=mock_invoke):
            request = EvaluationRequest(
                prompt="Test",
                candidate_outputs=[CandidateOutput(content="Test")],
                fast_mode=True,
            )
            
            result = await engine.evaluate(request)
            
            assert result.verdict == "pass"
            # Fast mode should have minimal rounds
            assert len(result.debate_rounds) <= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
