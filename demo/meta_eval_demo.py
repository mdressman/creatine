#!/usr/bin/env python3
"""
Meta-Evaluation Demo - Multi-Agent LLM-as-Judge Framework

Demonstrates:
1. Agent management and personas
2. Debate protocols (ChatEval, CourtEval, DEBATE)
3. Consistency metrics (IPI, TOV)
4. API usage

Run with: python demo/meta_eval_demo.py [--quick]
"""

import asyncio
import sys
import os
import time
import logging

# Suppress noisy Azure identity logs
logging.getLogger('azure.identity').setLevel(logging.ERROR)
logging.getLogger('azure.core').setLevel(logging.ERROR)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meta_eval import (
    AgentManager, DebateEngine, ConsistencyChecker,
    AgentConfig, AgentPersona, AgentRole,
    EvaluationRequest, CandidateOutput, DebateProtocol, AggregationMethod
)


def print_header(title: str):
    """Print section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_agent(agent: AgentConfig):
    """Print agent details."""
    roles = ", ".join(r.value for r in agent.roles)
    print(f"  • {agent.name}")
    print(f"    Persona: {agent.persona.value}")
    print(f"    Roles: {roles}")
    print(f"    Weight: {agent.weight}")


async def demo_agent_management():
    """Demonstrate agent management."""
    print_header("1. Agent Management")
    
    print("Creating AgentManager with default expert agents...")
    manager = AgentManager(auto_load_samples=True)
    
    print(f"\n📋 Registered Agents ({len(manager.list_agents())}):\n")
    for agent in manager.list_agents():
        print_agent(agent)
        print()
    
    # Add custom agent
    print("Adding custom 'StrictSafety' agent...")
    custom = AgentConfig(
        name="StrictSafety",
        persona=AgentPersona.SAFETY,
        roles=[AgentRole.SCORER, AgentRole.CRITIC],
        weight=2.0,
        temperature=0.1,
    )
    manager.register_agent(custom)
    print(f"✓ Added {custom.name} with weight {custom.weight}")
    
    # Get stats
    stats = manager.get_stats()
    print(f"\n📊 Agent Pool Stats:")
    print(f"  Total agents: {stats['total_agents']}")
    print(f"  Avg weight: {stats['avg_weight']:.2f}")
    print(f"  By persona: {stats['by_persona']}")
    
    return manager


async def demo_debate_protocols(manager: AgentManager):
    """Demonstrate different debate protocols."""
    print_header("2. Debate Protocols")
    
    engine = DebateEngine(manager, verbose=True)
    
    # Sample evaluation request
    prompt = "What is the capital of France?"
    outputs = [
        CandidateOutput(content="The capital of France is Paris, a beautiful city known for the Eiffel Tower."),
    ]
    
    protocols = [
        (DebateProtocol.CHATEVAL, "ChatEval (Simple parallel scoring)"),
        (DebateProtocol.CONSENSUS, "Consensus (Iterative agreement)"),
    ]
    
    for protocol, description in protocols:
        print(f"\n🎭 {description}")
        print("-" * 50)
        
        request = EvaluationRequest(
            prompt=prompt,
            candidate_outputs=outputs,
            protocol=protocol,
            fast_mode=(protocol == DebateProtocol.CHATEVAL),  # Fast for demo
        )
        
        start = time.perf_counter()
        try:
            result = await engine.evaluate(request)
            elapsed = (time.perf_counter() - start) * 1000
            
            print(f"\n  Verdict: {result.verdict.upper()}")
            print(f"  Score: {result.score:.2f}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Debate rounds: {len(result.debate_rounds)}")
            print(f"  Agents voted: {len(result.agent_votes)}")
            print(f"  Time: {elapsed:.0f}ms")
        except Exception as e:
            print(f"  ⚠️ Demo mode - LLM calls disabled: {e}")
    
    return engine


async def demo_consistency_metrics(manager: AgentManager):
    """Demonstrate consistency checking."""
    print_header("3. Consistency Metrics (IPI/TOV)")
    
    checker = ConsistencyChecker(manager, verbose=True)
    
    print("📐 Consistency metrics measure evaluation reliability:\n")
    print("  • IPI (Intra-Pair Instability): Do agents flip preferences")
    print("    when A/B presentation order is swapped?")
    print("    (0% = perfectly stable, 100% = always flips)\n")
    print("  • TOV (Total Order Violation): Are preferences transitive?")
    print("    If A>B and B>C, is A>C?")
    print("    (0% = fully transitive, higher = more violations)\n")
    
    # Demo with synthetic data
    print("🔬 Running consistency check on sample data...\n")
    
    test_samples = [
        {
            "prompt": "Which response is better?",
            "outputs": [
                "Paris is the capital of France.",
                "The capital city of France is Paris.",
            ]
        },
        {
            "prompt": "Evaluate this explanation",
            "outputs": [
                "2+2=4 because addition combines quantities.",
                "Two plus two equals four.",
                "The sum of 2 and 2 is 4.",
            ]
        },
    ]
    
    print(f"  Test samples: {len(test_samples)}")
    print("  (In production, this would run actual LLM evaluations)\n")
    
    # Show human alignment example
    print("📊 Human Alignment Tracking:")
    verdicts = [
        ("pass", "pass"),
        ("pass", "pass"),
        ("fail", "fail"),
        ("pass", "fail"),  # Disagreement
    ]
    alignment = checker.measure_human_alignment(verdicts)
    print(f"  Agent-Human agreement: {alignment:.0%}")
    
    return checker


async def demo_aggregation_methods():
    """Demonstrate different aggregation methods."""
    print_header("4. Verdict Aggregation Methods")
    
    print("Available aggregation methods:\n")
    methods = [
        ("majority_vote", "Simple majority - most common verdict wins"),
        ("weighted_score", "Weighted average - agents contribute by weight"),
        ("unanimous", "Unanimous - all must agree or 'uncertain'"),
        ("commander", "Commander decides - designated agent has final say"),
        ("synthesis", "Synthesis - LLM combines all perspectives"),
    ]
    
    for method, description in methods:
        print(f"  • {method}: {description}")
    
    print("\n📊 Example with 3 agents:")
    print("  Agent A (weight=1.5): pass, score=0.8")
    print("  Agent B (weight=1.0): pass, score=0.7")
    print("  Agent C (weight=0.5): fail, score=0.3")
    print()
    print("  → majority_vote: PASS (2/3 agents)")
    print("  → weighted_score: PASS (weighted avg = 0.68)")
    print("  → unanimous: UNCERTAIN (not all agree)")


async def demo_api_usage():
    """Demonstrate API usage."""
    print_header("5. REST API")
    
    print("Start the API server:\n")
    print("  python -m meta_eval.api.server")
    print()
    print("Available endpoints:\n")
    
    endpoints = [
        ("POST", "/evaluate", "Submit evaluation request"),
        ("GET", "/metrics", "Get IPI, TOV, human alignment KPIs"),
        ("POST", "/agents", "Add/update agent configuration"),
        ("GET", "/agents", "List all registered agents"),
        ("DELETE", "/agents/{id}", "Remove an agent"),
        ("POST", "/consistency", "Run consistency check"),
        ("POST", "/feedback", "Submit human feedback for alignment"),
        ("GET", "/health", "Health check"),
    ]
    
    for method, path, description in endpoints:
        print(f"  {method:6} {path:20} - {description}")
    
    print("\n📝 Example API call:\n")
    print("""  curl -X POST http://localhost:8000/evaluate \\
    -H "Content-Type: application/json" \\
    -d '{
      "prompt": "What is 2+2?",
      "candidate_outputs": [{"content": "4"}],
      "protocol": "chateval",
      "aggregation": "weighted_score"
    }'""")


async def demo_quick():
    """Quick demo without LLM calls."""
    print("\n" + "="*60)
    print("  META-EVALUATION FRAMEWORK - Quick Demo")
    print("="*60)
    
    manager = await demo_agent_management()
    await demo_aggregation_methods()
    await demo_consistency_metrics(manager)
    await demo_api_usage()
    
    print_header("Demo Complete!")
    print("For full functionality with LLM calls, configure:")
    print("  AZURE_OPENAI_ENDPOINT")
    print("  AZURE_OPENAI_DEPLOYMENT")
    print("\nSee meta_eval/README.md for complete documentation.")


async def demo_full():
    """Full demo with LLM calls (requires Azure OpenAI)."""
    print("\n" + "="*60)
    print("  META-EVALUATION FRAMEWORK - Full Demo")
    print("="*60)
    
    manager = await demo_agent_management()
    engine = await demo_debate_protocols(manager)
    await demo_consistency_metrics(manager)
    await demo_aggregation_methods()
    await demo_api_usage()
    
    print_header("Demo Complete!")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Meta-Evaluation Demo")
    parser.add_argument("--quick", action="store_true", help="Quick demo without LLM calls")
    parser.add_argument("--full", action="store_true", help="Full demo with LLM calls")
    args = parser.parse_args()
    
    if args.full:
        asyncio.run(demo_full())
    else:
        asyncio.run(demo_quick())


if __name__ == "__main__":
    main()
