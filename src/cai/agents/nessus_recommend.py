import os
from typing import Optional
import json

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.util import load_prompt_template, create_system_prompt_renderer

from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.nessus.nessus_tools import parse_nessus_report

load_dotenv()

nessus_recommend_prompt = load_prompt_template("prompts/system_nessus_recommend_agent.md")

def _make_openai_compatible_client() -> AsyncOpenAI:
    # Priority: Google key if available => point to Google's OpenAI-compatible endpoint
    google_key = (
        os.getenv("GOOGLE_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or os.getenv("GOOGLE_GENAI_API_KEY")
    )
    if google_key:
        return AsyncOpenAI(
            api_key=google_key,
            base_url="https://generativelanguage.googleapis.com/openai/v1",
        )
    # Fallback to standard OpenAI if no Google key
    return AsyncOpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )

model_name = os.getenv("CAI_MODEL", "gemini/gemini-2.5-flash")

nessus_recommend_agent = Agent(
    name="Nessus Recommend Agent",
    description="Agent that analyzes Nessus scan results and generates detailed testing recommendations.",
    instructions=create_system_prompt_renderer(nessus_recommend_prompt),
    tools=[
        parse_nessus_report,
        generic_linux_command,
    ],
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=_make_openai_compatible_client(),
    ),
)