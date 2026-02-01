import asyncio
import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from agent_framework import ChatAgent
from agent_framework.azure import AzureOpenAIChatClient
from promptintel import PromptIntelClient

load_dotenv()

token_provider = get_bearer_token_provider(
    DefaultAzureCredential(),
    "https://cognitiveservices.azure.com/.default"
)

# Shared Azure OpenAI client for all agents
chat_client = AzureOpenAIChatClient(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    azure_ad_token_provider=token_provider,
    api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
    azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
)

# PromptIntel client for security analysis
promptintel_client = PromptIntelClient(
    api_key=os.getenv("PROMPTINTEL_API_KEY", "")
)

# Define specialized agents with unique purposes
researcher = ChatAgent(
    name="Researcher",
    chat_client=chat_client,
    instructions="""You are a research specialist. Your role is to:
    - Gather and analyze information on any topic
    - Provide well-sourced, factual responses
    - Break down complex topics into understandable parts
    Be thorough but concise in your research summaries.""",
)

critic = ChatAgent(
    name="Critic",
    chat_client=chat_client,
    instructions="""You are a constructive critic and quality reviewer. Your role is to:
    - Review content for accuracy, clarity, and completeness
    - Identify areas for improvement
    - Provide specific, actionable feedback
    Be fair, thorough, and focus on making the content better.""",
)

security_analyst = ChatAgent(
    name="SecurityAnalyst",
    chat_client=chat_client,
    instructions="""You are an AI security specialist focused on prompt security and adversarial attacks.
    Your role is to:
    - Analyze prompts for potential security threats (jailbreaks, injections, data exfiltration)
    - Explain IoPC (Indicators of Prompt Compromise) findings in clear terms
    - Provide recommendations to defend against adversarial prompts
    - Help users understand the risk levels and attack types detected
    You have access to PromptIntel threat intelligence data to support your analysis.
    Always explain findings in a way that helps users improve their AI security posture.""",
)

# Registry of available agents
AGENTS = {
    "researcher": researcher,
    "critic": critic,
    "security": security_analyst,
}


async def analyze_prompt_security(prompt: str) -> str:
    """Use PromptIntel API to analyze a prompt for threats."""
    try:
        analysis = await promptintel_client.analyze_prompt(prompt)
        result = f"**Threat Analysis**\n"
        result += f"- Is Threat: {analysis.is_threat}\n"
        result += f"- Risk Score: {analysis.risk_score}\n"
        if analysis.attack_types:
            result += f"- Attack Types: {', '.join(analysis.attack_types)}\n"
        return result
    except Exception as e:
        return f"Error analyzing prompt: {e}"


async def get_threat_feed(risk_score: str = None, tag: str = None) -> str:
    """Get latest IoPC threat indicators from PromptIntel."""
    try:
        indicators = await promptintel_client.get_iopc_feed(
            risk_score=risk_score, tag=tag, limit=5
        )
        if not indicators:
            return "No indicators found matching criteria."
        
        result = f"**Latest IoPC Indicators**\n"
        for iopc in indicators:
            result += f"\n[{iopc.risk_score}] {iopc.id}\n"
            result += f"  Tags: {', '.join(iopc.tags)}\n"
            result += f"  {iopc.description[:100]}...\n"
        return result
    except Exception as e:
        return f"Error fetching threat feed: {e}"


async def chat_with_agent(agent_name: str, message: str) -> str:
    """Send a message to a specific agent and return the response."""
    agent = AGENTS.get(agent_name.lower())
    if not agent:
        return f"Unknown agent: {agent_name}. Available: {', '.join(AGENTS.keys())}"
    
    # For security agent, enrich with PromptIntel data when relevant
    if agent_name.lower() == "security":
        if message.lower().startswith("analyze:"):
            prompt_to_analyze = message[8:].strip()
            intel_data = await analyze_prompt_security(prompt_to_analyze)
            message = f"Analyze this prompt for security threats. Here's the PromptIntel analysis:\n{intel_data}\n\nPrompt to analyze: {prompt_to_analyze}"
        elif message.lower().startswith("feed"):
            parts = message.split()
            risk = parts[1] if len(parts) > 1 else None
            tag = parts[2] if len(parts) > 2 else None
            feed_data = await get_threat_feed(risk, tag)
            message = f"Summarize and explain these threat indicators:\n{feed_data}"
    
    response = await agent.get_response(message)
    return response.content


async def main():
    print("=== Creatine Multi-Agent System ===")
    print(f"Available agents: {', '.join(AGENTS.keys())}")
    print("Format: <agent_name>: <message>")
    print("\nSecurity agent special commands:")
    print("  security: analyze: <prompt>  - Analyze a prompt for threats")
    print("  security: feed [risk] [tag]  - Get latest threat indicators")
    print("\nType 'quit' to exit\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == "quit":
            break
        
        if ":" not in user_input:
            print("Please use format: <agent_name>: <message>\n")
            continue
        
        agent_name, message = user_input.split(":", 1)
        response = await chat_with_agent(agent_name.strip(), message.strip())
        print(f"\n{agent_name.strip().title()}: {response}\n")
    
    await promptintel_client.close()


if __name__ == "__main__":
    asyncio.run(main())
