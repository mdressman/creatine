"""
EvaluationAPI - REST API for the Multi-Agent Meta-Evaluation Framework.

Endpoints:
- POST /evaluate: Submit evaluation request, returns verdict + rationale
- GET /metrics: Returns current IPI, TOV, human alignment KPIs
- POST /agents: Add/update agent configurations
- GET /agents: List current agents and their roles
- POST /consistency: Run consistency check on test samples
- GET /health: Health check endpoint

Uses FastAPI for async support and automatic OpenAPI documentation.
"""

import asyncio
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from ..schemas import (
    AgentConfig, AgentPersona, AgentRole, EvaluationRequest,
    EvaluationResult, CandidateOutput, DebateProtocol,
    AggregationMethod, ConsistencyMetrics, DebateConfig
)
from ..agents.manager import AgentManager
from ..debate.debate_engine import DebateEngine
from ..consistency.checker import ConsistencyChecker


# ==================== Pydantic Models for API ====================

class CandidateOutputModel(BaseModel):
    """API model for candidate output."""
    id: Optional[str] = None
    content: str
    model: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvaluationRequestModel(BaseModel):
    """API model for evaluation request."""
    prompt: str
    candidate_outputs: List[CandidateOutputModel]
    reference_output: Optional[str] = None
    context: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    protocol: str = "chateval"
    aggregation: str = "weighted_score"
    required_agents: Optional[List[str]] = None
    required_personas: Optional[List[str]] = None
    max_debate_rounds: int = 3
    consensus_threshold: float = 0.8
    fast_mode: bool = False


class AgentConfigModel(BaseModel):
    """API model for agent configuration."""
    id: Optional[str] = None
    name: str
    model: str = "gpt-4o"
    persona: str = "safety"
    weight: float = 1.0
    roles: List[str] = Field(default_factory=lambda: ["scorer"])
    temperature: float = 0.3
    max_tokens: int = 1024
    system_prompt: Optional[str] = None
    enabled: bool = True


class ConsistencyCheckRequest(BaseModel):
    """API model for consistency check request."""
    test_samples: List[Dict[str, Any]]
    agent_ids: Optional[List[str]] = None


class MetricsResponse(BaseModel):
    """API model for metrics response."""
    ipi: float
    tov: float
    human_agreement: float
    agent_stats: Dict[str, Any]
    total_evaluations: int
    avg_latency_ms: float
    timestamp: str


# ==================== API Application ====================

class MetaEvalAPI:
    """
    FastAPI application for the Meta-Evaluation Framework.
    
    Manages lifecycle of components and provides REST endpoints.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.agent_manager: Optional[AgentManager] = None
        self.debate_engine: Optional[DebateEngine] = None
        self.consistency_checker: Optional[ConsistencyChecker] = None
        
        # Metrics tracking
        self._evaluation_count = 0
        self._total_latency_ms = 0.0
        self._latest_consistency: Optional[ConsistencyMetrics] = None
        self._human_verdicts: List[tuple] = []
        
        # Create FastAPI app
        self.app = self._create_app()
    
    def _create_app(self) -> FastAPI:
        """Create and configure FastAPI application."""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # Startup
            self.agent_manager = AgentManager(verbose=self.verbose)
            self.debate_engine = DebateEngine(self.agent_manager, verbose=self.verbose)
            self.consistency_checker = ConsistencyChecker(
                self.agent_manager, self.debate_engine, verbose=self.verbose
            )
            if self.verbose:
                print("Meta-Eval API initialized")
            yield
            # Shutdown
            if self.verbose:
                print("Meta-Eval API shutting down")
        
        app = FastAPI(
            title="Creatine Meta-Evaluation API",
            description="Multi-Agent LLM-as-Judge Evaluation Framework",
            version="1.0.0",
            lifespan=lifespan,
        )
        
        # CORS
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Register routes
        self._register_routes(app)
        
        return app
    
    def _register_routes(self, app: FastAPI):
        """Register API routes."""
        
        @app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "agents_loaded": len(self.agent_manager.list_agents()) if self.agent_manager else 0,
            }
        
        @app.post("/evaluate", response_model=Dict[str, Any])
        async def evaluate(request: EvaluationRequestModel):
            """
            Evaluate candidate outputs using multi-agent debate.
            
            Returns verdict, confidence, rationale, and agent-level details.
            """
            start_time = time.perf_counter()
            
            try:
                # Convert API model to internal schema
                eval_request = EvaluationRequest(
                    prompt=request.prompt,
                    candidate_outputs=[
                        CandidateOutput(
                            id=c.id or f"candidate_{i}",
                            content=c.content,
                            model=c.model,
                            metadata=c.metadata,
                        )
                        for i, c in enumerate(request.candidate_outputs)
                    ],
                    reference_output=request.reference_output,
                    context=request.context,
                    metadata=request.metadata,
                    protocol=DebateProtocol(request.protocol),
                    aggregation=AggregationMethod(request.aggregation),
                    required_agents=request.required_agents,
                    required_personas=[AgentPersona(p) for p in request.required_personas] if request.required_personas else None,
                    max_debate_rounds=request.max_debate_rounds,
                    consensus_threshold=request.consensus_threshold,
                    fast_mode=request.fast_mode,
                )
                
                # Run evaluation
                result = await self.debate_engine.evaluate(eval_request)
                
                # Track metrics
                latency_ms = (time.perf_counter() - start_time) * 1000
                self._evaluation_count += 1
                self._total_latency_ms += latency_ms
                
                return self._result_to_dict(result)
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/metrics", response_model=MetricsResponse)
        async def get_metrics():
            """
            Get current evaluation metrics and KPIs.
            
            Returns IPI, TOV, human alignment, and agent statistics.
            """
            agent_stats = self.agent_manager.get_stats() if self.agent_manager else {}
            
            return MetricsResponse(
                ipi=self._latest_consistency.ipi if self._latest_consistency else 0.0,
                tov=self._latest_consistency.tov if self._latest_consistency else 0.0,
                human_agreement=self._calculate_human_agreement(),
                agent_stats=agent_stats,
                total_evaluations=self._evaluation_count,
                avg_latency_ms=self._total_latency_ms / max(self._evaluation_count, 1),
                timestamp=datetime.utcnow().isoformat(),
            )
        
        @app.post("/agents")
        async def add_agent(config: AgentConfigModel):
            """
            Add or update an agent configuration.
            
            Returns the agent ID.
            """
            try:
                agent = AgentConfig(
                    id=config.id,
                    name=config.name,
                    model=config.model,
                    persona=AgentPersona(config.persona),
                    weight=config.weight,
                    roles=[AgentRole(r) for r in config.roles],
                    temperature=config.temperature,
                    max_tokens=config.max_tokens,
                    system_prompt=config.system_prompt or "",
                    enabled=config.enabled,
                )
                
                agent_id = self.agent_manager.register_agent(agent)
                
                return {"status": "success", "agent_id": agent_id}
                
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
        
        @app.get("/agents")
        async def list_agents():
            """
            List all registered agents and their roles.
            """
            agents = self.agent_manager.list_agents(enabled_only=False)
            
            return {
                "agents": [
                    {
                        "id": a.id,
                        "name": a.name,
                        "persona": a.persona.value,
                        "roles": [r.value for r in a.roles],
                        "weight": a.weight,
                        "enabled": a.enabled,
                        "accuracy": a.accuracy,
                        "consistency_score": a.consistency_score,
                        "latency_ms": a.latency_ms,
                    }
                    for a in agents
                ],
                "total": len(agents),
                "enabled": len([a for a in agents if a.enabled]),
            }
        
        @app.delete("/agents/{agent_id}")
        async def remove_agent(agent_id: str):
            """Remove an agent from the registry."""
            if self.agent_manager.unregister_agent(agent_id):
                return {"status": "success", "removed": agent_id}
            raise HTTPException(status_code=404, detail="Agent not found")
        
        @app.post("/consistency")
        async def run_consistency_check(request: ConsistencyCheckRequest, background_tasks: BackgroundTasks):
            """
            Run consistency check on test samples.
            
            Returns IPI, TOV metrics and per-agent breakdown.
            """
            try:
                agents = None
                if request.agent_ids:
                    agents = [
                        self.agent_manager.get_agent(aid)
                        for aid in request.agent_ids
                        if self.agent_manager.get_agent(aid)
                    ]
                
                report = await self.consistency_checker.run_consistency_check(
                    request.test_samples, agents
                )
                
                # Update cached metrics
                self._latest_consistency = report.metrics
                
                return {
                    "ipi": report.metrics.ipi,
                    "tov": report.metrics.tov,
                    "ipi_samples": report.metrics.ipi_samples,
                    "tov_samples": report.metrics.tov_samples,
                    "ipi_violations": report.ipi_violations,
                    "tov_violations": report.tov_violations,
                    "agent_consistency": report.metrics.agent_consistency,
                    "unreliable_agents": report.unreliable_agents,
                    "recommendations": report.recommendations,
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/feedback")
        async def submit_human_feedback(verdict: str, human_label: str):
            """
            Submit human feedback for alignment tracking.
            
            Used to calculate human agreement metric.
            """
            self._human_verdicts.append((verdict, human_label))
            return {"status": "recorded", "total_feedback": len(self._human_verdicts)}
    
    def _result_to_dict(self, result: EvaluationResult) -> Dict[str, Any]:
        """Convert EvaluationResult to API response dict."""
        return {
            "request_id": result.request_id,
            "verdict": result.verdict,
            "score": result.score,
            "confidence": result.confidence,
            "rationale": result.rationale,
            "agent_votes": [
                {
                    "agent_id": v.agent_id,
                    "agent_name": v.agent_name,
                    "persona": v.persona.value,
                    "role": v.role.value,
                    "verdict": v.verdict,
                    "score": v.score,
                    "confidence": v.confidence,
                    "rationale": v.rationale,
                    "latency_ms": v.latency_ms,
                }
                for v in result.agent_votes
            ],
            "debate_rounds": len(result.debate_rounds),
            "protocol": result.protocol_used.value,
            "aggregation": result.aggregation_used.value,
            "total_latency_ms": result.total_latency_ms,
            "total_tokens": result.total_tokens,
            "timestamp": result.timestamp.isoformat(),
        }
    
    def _calculate_human_agreement(self) -> float:
        """Calculate human agreement from feedback."""
        if not self._human_verdicts:
            return 0.0
        agreements = sum(1 for v, h in self._human_verdicts if v == h)
        return agreements / len(self._human_verdicts)
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the API server."""
        uvicorn.run(self.app, host=host, port=port)


# ==================== Standalone runner ====================

def create_api(verbose: bool = False) -> FastAPI:
    """Create API instance for external use."""
    api = MetaEvalAPI(verbose=verbose)
    return api.app


if __name__ == "__main__":
    api = MetaEvalAPI(verbose=True)
    api.run()
