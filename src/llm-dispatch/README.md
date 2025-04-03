# LLM-Dispatch 

BaseLLM: An abstract base class defining the interface for any LLM implementation.

ApiLLM & InMemoryLLM: Two concrete classes simulating an API-based LLM and an in-memory LLM respectively. In a real-world scenario, these would encapsulate the logic for calling an external API or processing locally.

LLMClient: Acts as a facade that registers multiple LLMs and dispatches a prompt to all of them. The generate method collects responses and returns them as a list of dictionaries, each with metadata indicating which LLM produced the response.

This structure makes it easy to extend the system by adding new classes that implement BaseLLM without changing the client code that uses LLMClient.


