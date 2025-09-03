import os
from typing import List, Optional, Any
import json

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel
from cai.sdk.agents.run import RunConfig
from cai.util import load_prompt_template, create_system_prompt_renderer

from cai.tools.reconnaissance.generic_linux_command import generic_linux_command  # noqa: E501
from cai.tools.reconnaissance.exec_code import execute_code  # noqa: E501

from cai.tools.nessus.nessus_tools import (
    parse_nessus_report,
    compile_nessus_report_with_verification_impl,
)

# Optional MCP support (pass mcp_servers to the Agent from callers)
# from cai.sdk.agents.mcp import MCPServer, MCPServerSse, MCPServerSseParams

load_dotenv()

nessus_verifier_prompt = load_prompt_template("prompts/system_nessus_verifier_agent.md")

def _make_openai_compatible_client() -> AsyncOpenAI:
    # Ưu tiên key của Google nếu có => trỏ về OpenAI-compatible endpoint của Google
    google_key = (
        os.getenv("GOOGLE_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or os.getenv("GOOGLE_GENAI_API_KEY")
    )
    if google_key:
        return AsyncOpenAI(
            api_key=google_key,
            base_url=os.getenv("https://generativelanguage.googleapis.com/openai/v1"),
        )
    # Fallback sang OpenAI chuẩn nếu không có key Google
    return AsyncOpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )

model_name = os.getenv("CAI_MODEL", "gemini/gemini-2.5-flash")

nessus_verifier_agent = Agent(
    name="Nessus Verifier",
    description="Agent that validates and re-scores Nessus scan results to reduce false positives.",
    instructions=create_system_prompt_renderer(nessus_verifier_prompt),
    tools=[
        parse_nessus_report,
        generic_linux_command,
        execute_code,
        # compile_nessus_report_with_verification is called by driver after agent outputs JSON
    ],
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=_make_openai_compatible_client(),
    ),
)

def _strip_code_fences(s: str) -> str:
    """Remove common markdown code fences like ```json ... ``` or ``` ... ```."""
    if not isinstance(s, str):
        return s
    text = s.strip()
    if text.startswith("```"):
        # remove opening fence with optional language label
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1 :]
        # remove trailing fence if present
        if text.endswith("```"):
            text = text[: -3]
    return text.strip()

def _extract_json_object(text: str) -> Any:
    """Try to parse a JSON object from an arbitrary string.

    Strategy:
    - Strip code fences if present
    - Try json.loads directly
    - Fallback: scan for the first balanced {...} block and parse it
    """
    if not isinstance(text, str):
        return text
    cleaned = _strip_code_fences(text)
    # First attempt: direct parse
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Fallback: find first balanced JSON object
    start = cleaned.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model output")
    depth = 0
    for i in range(start, len(cleaned)):
        ch = cleaned[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                candidate = cleaned[start : i + 1]
                try:
                    return json.loads(candidate)
                except Exception:
                    # continue searching in case there is another block
                    pass
    # If we get here, we couldn't parse
    raise ValueError("Failed to parse JSON decisions from model output")

async def verify_nessus_report(
    file_path: str,
    output_path: Optional[str] = None,
    mcp_servers: Optional[List] = None,
) -> str:
    """
    Orchestrates one-shot verification:
    - Run agent to produce decisions JSON
    - Compile the original XML + decisions into final verified XML
    - Writes to output_path if provided, returns the XML string
    """
    agent = nessus_verifier_agent
    if mcp_servers:
        agent = Agent(
            **{
                **nessus_verifier_agent.__dict__,
                "mcp_servers": mcp_servers,
            }
        )

    # Provide the file path as user message; agent must call parse_nessus_report(file_path)
    result = await Runner.run(
        starting_agent=agent,
        input=f"File path: {file_path}. Use parse_nessus_report to parse it and return the JSON decisions as per the required format.",
        run_config=RunConfig(tracing_disabled=True),
    )
    decisions_json = result.final_output

    # Normalize decisions into a JSON string
    try:
        if isinstance(decisions_json, (dict, list)):
            parsed_obj = decisions_json
        elif isinstance(decisions_json, str):
            parsed_obj = _extract_json_object(decisions_json)
        else:
            # Unsupported type -> stringify then try parse
            parsed_obj = _extract_json_object(str(decisions_json))
        decisions_json_str = json.dumps(parsed_obj, ensure_ascii=False)
    except Exception as e:
        # Provide a short preview to help debugging
        preview = str(decisions_json)[:200] if decisions_json is not None else "<None>"
        raise ValueError(f"Could not parse decisions JSON from model output: {e}. Preview: {preview}")

    # Compile XML
    final_xml = compile_nessus_report_with_verification_impl(
        original_report_path=file_path,
        decisions_json=decisions_json_str,
        output_path=output_path or "",
    )
    return final_xml