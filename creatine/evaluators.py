"""LLM and Semantic evaluators for Nova rule evaluation."""

import os
import json
import requests
from typing import Tuple, Dict, Any, Optional

from nova.evaluators.llm import LLMEvaluator
from nova.evaluators.semantics import DefaultSemanticEvaluator


class AzureEntraLLMEvaluator(LLMEvaluator):
    """
    LLM evaluator using Azure OpenAI with Entra (AAD) authentication.
    
    Uses DefaultAzureCredential for authentication instead of API keys,
    making it compatible with managed identities and Azure AD authentication.
    """
    
    def __init__(
        self,
        endpoint: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
    ):
        """
        Initialize the Azure Entra OpenAI evaluator.
        
        Args:
            endpoint: Azure OpenAI endpoint (defaults to AZURE_OPENAI_ENDPOINT env var)
            deployment_name: Azure deployment name (defaults to AZURE_OPENAI_DEPLOYMENT_NAME env var)
            api_version: Azure OpenAI API version
        """
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        
        self.endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT")
        self.deployment_name = deployment_name or os.environ.get("AZURE_OPENAI_DEPLOYMENT_NAME")
        self.api_version = api_version
        
        if not self.endpoint:
            raise ValueError("Azure OpenAI endpoint required. Set AZURE_OPENAI_ENDPOINT env var.")
        if not self.deployment_name:
            raise ValueError("Azure OpenAI deployment name required. Set AZURE_OPENAI_DEPLOYMENT_NAME env var.")
        
        # Set up Entra authentication
        self._credential = DefaultAzureCredential()
        self._token_provider = get_bearer_token_provider(
            self._credential,
            "https://cognitiveservices.azure.com/.default"
        )
        
        # Build base URL
        endpoint = self.endpoint.rstrip('/')
        self.base_url = f"{endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={api_version}"
        
        # Session for connection reuse
        self.session = requests.Session()
    
    def _get_token(self) -> str:
        """Get a fresh access token."""
        return self._token_provider()
    
    def evaluate(self, pattern: str, text: str) -> Tuple[bool, float]:
        """
        Evaluate text against a pattern.
        
        Args:
            pattern: The LLM prompt pattern
            text: The text to evaluate
            
        Returns:
            Tuple of (matched, confidence)
        """
        matched, confidence, _ = self.evaluate_prompt(pattern, text)
        return matched, confidence
    
    def evaluate_prompt(
        self, 
        prompt_template: str, 
        text: str, 
        temperature: float = 0.1
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Evaluate text using the provided prompt template with Azure OpenAI.
        
        Args:
            prompt_template: The prompt to send to the LLM
            text: The text to evaluate
            temperature: Temperature setting for the model
            
        Returns:
            Tuple of (matched, confidence, details)
        """
        try:
            # Format the complete prompt
            full_prompt = (
                f"{prompt_template}\n\n"
                f"Text to evaluate: {text}\n\n"
                f"Respond with a JSON object with keys: matched (boolean), confidence (float 0-1), reason (string)"
            )
            
            # Get fresh token
            token = self._get_token()
            
            # Call Azure OpenAI API
            response = self.session.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                json={
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security analyst evaluating text for potential threats. "
                                      "Respond with a JSON object containing 'matched' (boolean), 'confidence' (float 0-1), "
                                      "and 'reason' (string)."
                        },
                        {"role": "user", "content": full_prompt}
                    ],
                    "temperature": temperature,
                    "response_format": {"type": "json_object"}
                },
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                
                try:
                    evaluation = json.loads(content)
                    matched = bool(evaluation.get("matched", False))
                    confidence = float(evaluation.get("confidence", 0.0))
                    
                    evaluation["model"] = self.deployment_name
                    evaluation["evaluator_type"] = "azure_entra"
                    
                    return matched, confidence, evaluation
                except json.JSONDecodeError:
                    return False, 0.0, {"error": "Invalid JSON response", "raw": content}
            else:
                return False, 0.0, {"error": f"API error: {response.status_code}", "text": response.text}
                
        except Exception as e:
            return False, 0.0, {"error": str(e)}


def create_semantic_evaluator() -> DefaultSemanticEvaluator:
    """Create a semantic similarity evaluator with suppressed noisy output."""
    import sys
    import io
    import logging
    import os
    import warnings
    
    # Suppress transformers/sentence-transformers logging
    logging.getLogger("transformers").setLevel(logging.ERROR)
    logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
    logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
    
    # Suppress HF Hub warnings
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    warnings.filterwarnings("ignore", message=".*unauthenticated.*")
    warnings.filterwarnings("ignore", message=".*HF Hub.*")
    
    # Suppress stdout/stderr during model loading (BERT load report, HF warnings)
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        evaluator = DefaultSemanticEvaluator()
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    
    return evaluator


def create_llm_evaluator(
    endpoint: Optional[str] = None,
    deployment_name: Optional[str] = None,
) -> AzureEntraLLMEvaluator:
    """Create an LLM evaluator with Azure Entra auth."""
    return AzureEntraLLMEvaluator(endpoint, deployment_name)
