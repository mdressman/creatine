"""Tests for EvaluationAPI endpoints."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock

from meta_eval.api.server import MetaEvalAPI, create_api
from meta_eval.schemas import AgentPersona, EvaluationResult, AgentVote, AgentRole


class TestHealthEndpoint:
    """Tests for /health endpoint."""
    
    def test_health_check(self):
        """Test health endpoint returns healthy status."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "agents_loaded" in data


class TestAgentsEndpoints:
    """Tests for /agents endpoints."""
    
    def test_list_agents(self):
        """Test listing agents."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        response = client.get("/agents")
        
        assert response.status_code == 200
        data = response.json()
        assert "agents" in data
        assert "total" in data
        assert "enabled" in data
        # Should have sample agents loaded
        assert data["total"] >= 3
    
    def test_add_agent(self):
        """Test adding a new agent."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        agent_config = {
            "name": "NewTestAgent",
            "persona": "safety",
            "weight": 1.5,
            "roles": ["scorer", "critic"],
            "temperature": 0.5,
        }
        
        response = client.post("/agents", json=agent_config)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "agent_id" in data
        
        # Verify agent was added
        list_response = client.get("/agents")
        agents = list_response.json()["agents"]
        assert any(a["name"] == "NewTestAgent" for a in agents)
    
    def test_add_agent_invalid_persona(self):
        """Test adding agent with invalid persona fails."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        agent_config = {
            "name": "BadAgent",
            "persona": "invalid_persona",
        }
        
        response = client.post("/agents", json=agent_config)
        
        assert response.status_code == 400
    
    def test_delete_agent(self):
        """Test removing an agent."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        # First add an agent
        agent_config = {"name": "ToDelete", "persona": "safety"}
        add_response = client.post("/agents", json=agent_config)
        agent_id = add_response.json()["agent_id"]
        
        # Delete it
        response = client.delete(f"/agents/{agent_id}")
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Verify it's gone
        list_response = client.get("/agents")
        agents = list_response.json()["agents"]
        assert not any(a["id"] == agent_id for a in agents)
    
    def test_delete_nonexistent_agent(self):
        """Test deleting nonexistent agent returns 404."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        response = client.delete("/agents/nonexistent_id")
        
        assert response.status_code == 404


class TestMetricsEndpoint:
    """Tests for /metrics endpoint."""
    
    def test_get_metrics(self):
        """Test metrics endpoint returns expected structure."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        response = client.get("/metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "ipi" in data
        assert "tov" in data
        assert "human_agreement" in data
        assert "agent_stats" in data
        assert "total_evaluations" in data
        assert "avg_latency_ms" in data
        assert "timestamp" in data


class TestEvaluateEndpoint:
    """Tests for /evaluate endpoint."""
    
    def test_evaluate_request_validation(self):
        """Test evaluation request validation."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        # Missing required field
        response = client.post("/evaluate", json={
            "candidate_outputs": [{"content": "test"}]
        })
        
        assert response.status_code == 422  # Validation error
    
    def test_evaluate_minimal_request(self):
        """Test evaluation with minimal valid request."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        # Mock the debate engine to avoid actual LLM calls
        mock_result = EvaluationResult(
            request_id="test",
            verdict="pass",
            score=0.85,
            confidence=0.9,
            rationale="Test rationale",
            agent_votes=[
                AgentVote(
                    agent_id="test",
                    agent_name="Test",
                    persona=AgentPersona.SAFETY,
                    role=AgentRole.SCORER,
                    verdict="pass",
                    score=0.85,
                    confidence=0.9,
                )
            ],
        )
        
        with patch.object(api.debate_engine, 'evaluate', new_callable=AsyncMock) as mock_eval:
            mock_eval.return_value = mock_result
            
            response = client.post("/evaluate", json={
                "prompt": "Test prompt",
                "candidate_outputs": [{"content": "Test output"}],
            })
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["verdict"] == "pass"
            assert data["score"] == 0.85
            assert "agent_votes" in data
    
    def test_evaluate_with_protocol(self):
        """Test evaluation with specific protocol."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        mock_result = EvaluationResult(
            request_id="test",
            verdict="fail",
            score=0.3,
            confidence=0.8,
        )
        
        with patch.object(api.debate_engine, 'evaluate', new_callable=AsyncMock) as mock_eval:
            mock_eval.return_value = mock_result
            
            response = client.post("/evaluate", json={
                "prompt": "Test",
                "candidate_outputs": [{"content": "Test"}],
                "protocol": "courteval",
                "aggregation": "majority_vote",
                "max_debate_rounds": 5,
            })
            
            assert response.status_code == 200


class TestConsistencyEndpoint:
    """Tests for /consistency endpoint."""
    
    def test_consistency_check(self):
        """Test consistency check endpoint."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        # Mock consistency checker
        mock_report = Mock()
        mock_report.metrics = Mock(
            ipi=0.1,
            tov=0.05,
            ipi_samples=10,
            tov_samples=5,
            agent_consistency={"agent_1": 0.9},
        )
        mock_report.ipi_violations = []
        mock_report.tov_violations = []
        mock_report.unreliable_agents = []
        mock_report.recommendations = ["Consider adding more agents"]
        
        with patch.object(api.consistency_checker, 'run_consistency_check', new_callable=AsyncMock) as mock_check:
            mock_check.return_value = mock_report
            
            response = client.post("/consistency", json={
                "test_samples": [
                    {"prompt": "Test", "outputs": ["A", "B"]},
                ],
            })
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["ipi"] == 0.1
            assert data["tov"] == 0.05
            assert "recommendations" in data


class TestFeedbackEndpoint:
    """Tests for /feedback endpoint."""
    
    def test_submit_feedback(self):
        """Test submitting human feedback."""
        api = MetaEvalAPI(verbose=False)
        client = TestClient(api.app)
        
        response = client.post("/feedback", params={
            "verdict": "pass",
            "human_label": "pass",
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "recorded"
        assert data["total_feedback"] == 1
        
        # Submit more feedback
        client.post("/feedback", params={"verdict": "fail", "human_label": "fail"})
        client.post("/feedback", params={"verdict": "pass", "human_label": "fail"})
        
        # Check metrics updated
        metrics = client.get("/metrics").json()
        assert metrics["human_agreement"] > 0  # Some agreement recorded


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
