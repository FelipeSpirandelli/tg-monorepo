import os
from typing import List

import requests
from langchain.agents import AgentExecutor, LLMSingleActionAgent, Tool
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain.prompts import StringPromptTemplate
from langchain.tools import BaseTool
from langchain_community.llms import OpenAI


# MVC API Client for communicating with the MVC API
class MVCAPIClient:
    def __init__(self, base_url):
        self.base_url = base_url

    def get_data(self, endpoint):
        """Get data from the MVC API"""
        response = requests.get(f"{self.base_url}/{endpoint}")
        return response.json()

    def post_data(self, endpoint, data):
        """Post data to the MVC API"""
        response = requests.post(f"{self.base_url}/{endpoint}", json=data)
        return response.json()

    def put_data(self, endpoint, data):
        """Update data in the MVC API"""
        response = requests.put(f"{self.base_url}/{endpoint}", json=data)
        return response.json()

    def delete_data(self, endpoint):
        """Delete data from the MVC API"""
        response = requests.delete(f"{self.base_url}/{endpoint}")
        return response.json()


# Tool for the agent to interact with MVC API
class MVCAPITool(BaseTool):
    name: str = "mvc_api_tool"
    description: str = "Tool for interacting with the MVC API"

    def __init__(self, client):
        super().__init__()
        self.client = client

    def _run(self, instruction: str) -> str:
        """Execute the tool based on the instruction"""
        # Parse the instruction to determine what API call to make
        instruction = instruction.lower()

        try:
            if instruction.startswith("get "):
                endpoint = instruction[4:].strip()
                result = self.client.get_data(endpoint)
                return str(result)
            elif instruction.startswith("create "):
                # Format expected: "create endpoint {json_data}"
                parts = instruction[7:].strip().split(" ", 1)
                if len(parts) != 2:
                    return "Invalid format for create command"
                endpoint, data_str = parts
                # Convert string representation of JSON to dict (simplified)
                import json

                try:
                    data = json.loads(data_str)
                    result = self.client.post_data(endpoint, data)
                    return str(result)
                except json.JSONDecodeError:
                    return "Invalid JSON data format"
            elif instruction.startswith("update "):
                # Similar parsing logic for update operations
                parts = instruction[7:].strip().split(" ", 1)
                if len(parts) != 2:
                    return "Invalid format for update command"
                endpoint, data_str = parts
                import json

                try:
                    data = json.loads(data_str)
                    result = self.client.put_data(endpoint, data)
                    return str(result)
                except json.JSONDecodeError:
                    return "Invalid JSON data format"
            elif instruction.startswith("delete "):
                endpoint = instruction[7:].strip()
                result = self.client.delete_data(endpoint)
                return str(result)
            else:
                return "Unknown command. Please use get, create, update, or delete."
        except Exception as e:
            return f"Error executing MVC API call: {str(e)}"

    def _arun(self, instruction: str) -> str:
        """Async implementation would go here"""
        # For simplicity, we'll just call the sync version
        return self._run(instruction)


# Custom prompt template for the agent
class MVCAgentPromptTemplate(StringPromptTemplate):
    template: str
    tools: List[Tool]

    def format(self, **kwargs) -> str:
        intermediate_steps = kwargs.pop("intermediate_steps")
        thoughts = ""
        for action, observation in intermediate_steps:
            thoughts += f"\nAction: {action}\nObservation: {observation}\n"

        kwargs["agent_scratchpad"] = thoughts
        kwargs["tools"] = "\n".join([f"{tool.name}: {tool.description}" for tool in self.tools])
        kwargs["tool_names"] = ", ".join([tool.name for tool in self.tools])

        return self.template.format(**kwargs)


def create_mvc_langchain_agent(mvc_api_url, openai_api_key=None):
    """Create and return a LangChain agent that can interact with the MVC API"""

    # Set OpenAI API key
    if openai_api_key:
        os.environ["OPENAI_API_KEY"] = openai_api_key

    # Initialize the MVC API client
    mvc_client = MVCAPIClient(mvc_api_url)

    # Create the tool
    tools = [MVCAPITool(mvc_client)]

    # Define the prompt template
    template = """
    You are an intelligent agent with access to an MVC API.

    Available tools:
    {tools}

    Use the following format:
    Question: the input question you must answer
    Thought: consider what you need to do
    Action: the action to take, should be one of [{tool_names}]
    Action Input: the input to the action
    Observation: the result of the action
    ... (this Thought/Action/Action Input/Observation can repeat N times)
    Thought: I now know the final answer
    Final Answer: the final answer to the original input question

    Begin!

    Question: {input}
    {agent_scratchpad}
    Thought:
    """

    prompt = MVCAgentPromptTemplate(
        template=template, tools=tools, input_variables=["input", "intermediate_steps"]
    )

    # Initialize the LLM
    llm = OpenAI(temperature=0)

    # Set up the agent with the LLM chain
    llm_chain = LLMChain(llm=llm, prompt=prompt)

    # Add memory to the agent
    memory = ConversationBufferMemory(memory_key="chat_history")

    # Create agent
    agent = LLMSingleActionAgent(
        llm_chain=llm_chain,
        output_parser=None,  # You could create a custom parser here
        stop=["\nObservation:"],
        allowed_tools=[tool.name for tool in tools],
    )

    # Create the agent executor
    agent_executor = AgentExecutor.from_agent_and_tools(agent=agent, tools=tools, verbose=True, memory=memory)

    return agent_executor
