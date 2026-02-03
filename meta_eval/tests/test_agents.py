"""Tests for AgentManager."""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from meta_eval.schemas import (
    AgentConfig, AgentPersona, AgentRole, AgentVote, CandidateOutput
)
from meta_eval.agents.manager import AgentManager


class TestAgentManager:
    """Tests for AgentManager lifecycle and invocation."""
    
    def test_register_agent(self):
        """Test agent registration."""
        manager = AgentManager(auto_load_samples=False)
        
        agent = AgentConfig(
            name="TestAgent",
            persona=AgentPersona.SAFETY,
            weight=1.5,
        )
        
        agent_id = manager.register_agent(agent)
        
        assert agent_id == agent.id
        assert manager.get_agent(agent_id) is agent
        assert len(manager.list_agents()) == 1
    
    def test_unregister_agent(self):
        """Test agent removal."""
        manager = AgentManager(auto_load_samples=False)
        
        agent = AgentConfig(name="TestAgent", persona=AgentPersona.SAFETY)
        agent_id = manager.register_agent(agent)
        
        assert manager.unregister_agent(agent_id) is True
        assert manager.get_agent(agent_id) is None
        assert manager.unregister_agent(agent_id) is False  # Already removed
    
    def test_get_agents_by_persona(self):
        """Test filtering agents by persona."""
        manager = AgentManager(auto_load_samples=False)
        
        safety_agent = AgentConfig(name="Safety", persona=AgentPersona.SAFETY)
        factuality_agent = AgentConfig(name="Factuality", persona=AgentPersona.FACTUALITY)
        
        manager.register_agent(safety_agent)
        manager.register_agent(factuality_agent)
        
        safety_agents = manager.get_agents_by_persona(AgentPersona.SAFETY)
        assert len(safety_agents) == 1
        assert safety_agents[0].name == "Safety"
    
    def test_get_agents_by_role(self):
        """Test filtering agents by role."""
        manager = AgentManager(auto_load_samples=False)
        
        scorer = AgentConfig(name="Scorer", persona=AgentPersona.SAFETY, roles=[AgentRole.SCORER])
        critic = AgentConfig(name="Critic", persona=AgentPersona.SAFETY, roles=[AgentRole.CRITIC])
        both = AgentConfig(name="Both", persona=AgentPersona.SAFETY, roles=[AgentRole.SCORER, AgentRole.CRITIC])
        
        manager.register_agent(scorer)
        manager.register_agent(critic)
        manager.register_agent(both)
        
        scorers = manager.get_agents_by_role(AgentRole.SCORER)
        assert len(scorers) == 2
        
        critics = manager.get_agents_by_role(AgentRole.CRITIC)
        assert len(critics) == 2
    
    def test_update_agent(self):
        """Test agent configuration updates."""
        manager = AgentManager(auto_load_samples=False)
        
        agent = AgentConfig(name="Test", persona=AgentPersona.SAFETY, weight=1.0)
        agent_id = manager.register_agent(agent)
        
        assert manager.update_agent(agent_id, {"weight": 2.0}) is True
        assert manager.get_agent(agent_id).weight == 2.0
        
        assert manager.update_agent("nonexistent", {"weight": 1.0}) is False
    
    def test_sample_agents_loaded(self):
        """Test default sample agents are loaded."""
        manager = AgentManager(auto_load_samples=True)
        
        agents = manager.list_agents()
        assert len(agents) >= 3  # At least SafetyGuard, SecurityAnalyst, FactChecker
        
        # Check specific agents exist
        names = [a.name for a in agents]
        assert "SafetyGuard" in names
        assert "SecurityAnalyst" in names
    
    def test_adjust_weights_from_accuracy(self):
        """Test weight adjustment based on accuracy."""
        manager = AgentManager(auto_load_samples=False)
        
        agent = AgentConfig(name="Test", persona=AgentPersona.SAFETY, weight=1.0)
        agent_id = manager.register_agent(agent)
        
        # High accuracy should increase weight
        manager.adjust_weights_from_accuracy({agent_id: 0.9})
        assert manager.get_agent(agent_id).weight > 1.0
        
    def test_disabled_agents_filtered(self):
        """Test that disabled agents are filtered by default."""
        manager = AgentManager(auto_load_samples=False)
        
        enabled = AgentConfig(name="Enabled", persona=AgentPersona.SAFETY, enabled=True)
        disabled = AgentConfig(name="Disabled", persona=AgentPersona.SAFETY, enabled=False)
        
        manager.register_agent(enabled)
        manager.register_agent(disabled)
        
        assert len(manager.list_agents(enabled_only=True)) == 1
        assert len(manager.list_agents(enabled_only=False)) == 2
    
    def test_get_stats(self):
        """Test statistics aggregation."""
        manager = AgentManager(auto_load_samples=True)
        
        stats = manager.get_stats()
        
        assert "total_agents" in stats
        assert "by_persona" in stats
        assert "by_role" in stats
        assert stats["total_agents"] > 0


class TestAgentInvocation:
    """Tests for agent invocation (requires mocking LLM)."""
    
    @pytest.mark.asyncio
    async def test_invoke_agent_success(self):
        """Test successful agent invocation."""
        manager = AgentManager(auto_load_samples=False)
        agent = AgentConfig(name="Test", persona=AgentPersona.SAFETY)
        manager.register_agent(agent)
        
        # Mock LLM client
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '{"verdict": "pass", "score": 0.8, "confidence": 0.9, "rationale": "Looks safe"}'
        mock_response.usage.total_tokens = 100
        
        with patch.object(manager, '_get_llm_client') as mock_client:
            mock_client.return_value.chat.completions.create = Mock(return_value=mock_response)
            
            candidate = CandidateOutput(content="Test output")
            vote = await manager.invoke_agent(agent, "Test prompt", candidate)
            
            assert vote.verdict == "pass"
            assert vote.score == 0.8
            assert vote.confidence == 0.9
            assert vote.agent_id == agent.id
    
    @pytest.mark.asyncio
    async def test_invoke_agent_failure(self):
        """Test agent invocation handles failures gracefully."""
        manager = AgentManager(auto_load_samples=False)
        agent = AgentConfig(name="Test", persona=AgentPersona.SAFETY)
        manager.register_agent(agent)
        
        with patch.object(manager, '_get_llm_client') as mock_client:
            mock_client.return_value.chat.completions.create = Mock(side_effect=Exception("API Error"))
            
            candidate = CandidateOutput(content="Test output")
            vote = await manager.invoke_agent(agent, "Test prompt", candidate)
            
            assert vote.verdict == "uncertain"
            assert vote.confidence == 0.0
            assert "failed" in vote.rationale.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
