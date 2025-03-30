from abc import ABC, abstractmethod
from typing import List, Dict


# Base interface for any LLM implementation.
class BaseLLM(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> Dict:
        """
        Generate a response based on the given prompt.
        Returns a dictionary containing:
            - "llm_name": Name of the LLM.
            - "response": The generated text response.
        """
        pass


# Concrete LLM implementations.
class ApiLLM(BaseLLM):
    def __init__(self, name: str, api_key: str, endpoint: str):
        self.name = name
        self.api_key = api_key
        self.endpoint = endpoint

    def generate(self, prompt: str) -> Dict:
        # Simulate an API call; replace with a real API call in production.
        response_text = f"API response for prompt '{prompt}' from {self.name}"
        return {"llm_name": self.name, "response": response_text}


class InMemoryLLM(BaseLLM):
    def __init__(self, name: str, model):
        self.name = name
        self.model = model  # Could be a loaded model in a real scenario.

    def generate(self, prompt: str) -> Dict:
        # Simulate in-memory generation; replace with a real call in production.
        response_text = f"In-memory response for prompt '{prompt}' from {self.name}"
        return {"llm_name": self.name, "response": response_text}


# Strategy interface for generating responses from a collection of LLMs.
class LLMStrategy(ABC):
    @abstractmethod
    def register(self, llm: BaseLLM):
        """Register an LLM with this strategy."""
        pass

    @abstractmethod
    def generate(self, prompt: str) -> List[Dict]:
        """Generate responses from all registered LLMs based on the prompt."""
        pass


# Concrete strategy for API-based LLMs.
class ApiLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[ApiLLM] = []

    def register(self, llm: ApiLLM):
        self.llms.append(llm)

    def generate(self, prompt: str) -> List[Dict]:
        responses = []
        for llm in self.llms:
            responses.append(llm.generate(prompt))
        return responses


# Concrete strategy for in-memory LLMs.
class InMemoryLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[InMemoryLLM] = []

    def register(self, llm: InMemoryLLM):
        self.llms.append(llm)

    def generate(self, prompt: str) -> List[Dict]:
        responses = []
        for llm in self.llms:
            responses.append(llm.generate(prompt))
        return responses


# Facade client that uses a strategy to dispatch the prompt.
class LLMClient:
    def __init__(self):
        # Mapping of strategy names to strategy instances.
        self.strategies: Dict[str, LLMStrategy] = {}
        self.active_strategy: LLMStrategy = None

    def register_strategy(self, name: str, strategy: LLMStrategy):
        """
        Register a strategy instance with a given name.
        """
        self.strategies[name] = strategy

    def set_strategy(self, name: str):
        """
        Set the active strategy to be used for generating responses.
        """
        if name in self.strategies:
            self.active_strategy = self.strategies[name]
        else:
            raise ValueError(f"Strategy '{name}' is not registered.")

    def generate(self, prompt: str) -> List[Dict]:
        """
        Dispatch the prompt to the active strategy and return the structured responses.
        """
        if not self.active_strategy:
            raise Exception(
                "No active strategy set. Please set a strategy using set_strategy()."
            )
        return self.active_strategy.generate(prompt)


# Example usage:
if __name__ == "__main__":
    client = LLMClient()

    # Create strategy instances.
    api_strategy = ApiLLMStrategy()
    in_memory_strategy = InMemoryLLMStrategy()

    # Register LLMs with their respective strategies.
    api_strategy.register(
        ApiLLM(name="OpenAI", api_key="dummy_key", endpoint="https://api.openai.com/v1")
    )
    in_memory_strategy.register(InMemoryLLM(name="LocalModel", model="dummy_model"))

    # Register strategies with the client.
    client.register_strategy("api", api_strategy)
    client.register_strategy("in_memory", in_memory_strategy)

    # Set active strategy at runtime.
    client.set_strategy("api")  # Change to "in_memory" to use the in-memory strategy.
    prompt = "What is the capital of France?"
    responses = client.generate(prompt)
    for response in responses:
        print(f"LLM: {response['llm_name']}\nResponse: {response['response']}\n")
