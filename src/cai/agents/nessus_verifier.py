import os
from typing import List, Optional, Any
import json

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel, handoff
from cai.sdk.agents.run import RunConfig
from cai.util import load_prompt_template, create_system_prompt_renderer

from cai.agents.nessus_recommend import nessus_recommend_agent
from cai.agents.nessus_verify import nessus_verify_agent

from cai.tools.nessus.nessus_tools import (
    compile_nessus_report_with_verification_impl,
)

# Optional MCP support (pass mcp_servers to the Agent from callers)
# from cai.sdk.agents.mcp import MCPServer, MCPServerSse, MCPServerSseParams

load_dotenv()

# Create orchestrator prompt for the main verifier agent
orchestrator_prompt = """# System context
You are part of a multi-agent system called the Agents SDK, designed to make agent coordination and execution easy. Agents uses two primary abstraction: **Agents** and **Handoffs**. An agent encompasses instructions and tools and can hand off a conversation to another agent when appropriate. Handoffs are achieved by calling a handoff function, generally named `transfer_to_<agent_name>`. Transfers between agents are handled seamlessly in the background; do not mention or draw attention to these transfers in your conversation with the user.

# Nessus Verification Orchestrator

You are a cybersecurity orchestrator agent that coordinates the complete Nessus verification process through a two-phase approach:

## Your Role
Manage the workflow between recommendation and verification agents to provide comprehensive Nessus scan validation.

## Process Flow
1. **Phase 1 - Recommendations**: Call `transfer_to_nessus_recommend_agent` to analyze findings and generate testing recommendations
2. **Phase 2 - Verification**: Call `transfer_to_nessus_verify_agent` with the recommendations to execute actual penetration tests and validate findings
3. **Integration**: Present the final comprehensive results from both phases

## Instructions
- Start by transferring to the Nessus Recommend Agent with the file path provided by the user
- After receiving detailed recommendations from the first agent, transfer to the Nessus Verify Agent with those recommendations
- The verify agent will execute actual penetration testing based on the recommendations
- Present the final consolidated results focusing on confirmed vulnerabilities and false positive eliminations

## Available Handoffs
- `transfer_to_nessus_recommend_agent` - for analysis and recommendation generation
- `transfer_to_nessus_verify_agent` - for actual verification testing

Always maintain context between phases and ensure comprehensive coverage of all findings. The goal is to provide definitive answers about vulnerability exploitability through this two-phase approach."""

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

# Create the orchestrator agent with handoffs to specialized agents
nessus_verifier_agent = Agent(
    name="Nessus Verifier",
    description="Orchestrator agent that coordinates recommendation and verification phases for comprehensive Nessus validation.",
    instructions=orchestrator_prompt,
    handoffs=[
        handoff(nessus_recommend_agent),
        handoff(nessus_verify_agent),
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
    raise ValueError("Failed to parse JSON from model output")

def _convert_verification_to_decisions(verification_results: dict) -> dict:
    """Convert the new verification report format to the legacy decisions format for XML compilation."""
    verification_data = verification_results.get("verification_results", [])
    decisions = []
    
    for result in verification_data:
        # Map verification status to legacy status
        status_mapping = {
            "CONFIRMED_VULNERABLE": "confirmed",
            "NOT_EXPLOITABLE": "rejected", 
            "FALSE_POSITIVE": "rejected",
            "ACCESS_LIMITED": "uncertain"
        }
        
        decision = {
            "host": result.get("host", ""),
            "plugin_id": result.get("plugin_id", ""),
            "port": result.get("port", "0"),
            "protocol": result.get("protocol", "tcp"),
            "status": status_mapping.get(result.get("verification_status", "uncertain"), "uncertain"),
            "confidence": result.get("confidence_level", 0.5),
            "score": result.get("verified_score", 50),
            "rationale": _build_rationale_from_verification(result),
            "recommended_tests": _extract_tests_from_verification(result)
        }
        decisions.append(decision)
    
    return {
        "decisions": decisions,
        "meta": {
            "scoring_profile": "verification_based",
            "notes": f"Results from comprehensive verification testing. {verification_results.get('executive_summary', {}).get('total_tested', 0)} findings tested."
        }
    }

def _build_rationale_from_verification(result: dict) -> str:
    """Build a rationale string from verification results."""
    status = result.get("verification_status", "UNCERTAIN")
    plugin_name = result.get("plugin_name", "Unknown")
    
    rationale_parts = [f"{plugin_name} - {status}"]
    
    if status == "CONFIRMED_VULNERABLE":
        impact = result.get("impact_assessment", {})
        if impact.get("business_risk"):
            rationale_parts.append(f"Business risk: {impact['business_risk']}")
        
        exploits = result.get("exploitation_evidence", {}).get("successful_exploits", [])
        if exploits:
            rationale_parts.append(f"Exploitation confirmed: {exploits[0].get('exploit_type', 'Unknown')}")
    
    elif status == "FALSE_POSITIVE":
        failed_exploits = result.get("exploitation_evidence", {}).get("failed_exploits", [])
        if failed_exploits:
            rationale_parts.append(f"Testing failed: {failed_exploits[0].get('reason_failed', 'Could not reproduce')}")
    
    return ". ".join(rationale_parts)

def _extract_tests_from_verification(result: dict) -> List[str]:
    """Extract test commands from verification results."""
    tests = []
    
    testing_data = result.get("testing_executed", {})
    
    # Add primary test commands
    primary = testing_data.get("primary_tests", {})
    if isinstance(primary, dict) and primary.get("command"):
        tests.append(f"Primary: {primary['command']}")
    
    # Add exploitation attempts
    exploitation = testing_data.get("exploitation_attempts", [])
    for attempt in exploitation[:2]:  # Limit to first 2
        if attempt.get("command"):
            tests.append(f"Exploit test: {attempt['command']}")
    
    # Add manual verification notes
    manual = testing_data.get("manual_verification", [])
    for procedure in manual[:1]:  # Limit to first 1
        if procedure.get("procedure"):
            tests.append(f"Manual: {procedure['procedure']}")
    
    return tests[:5]  # Limit total tests

async def verify_nessus_report(
    file_path: str,
    output_path: Optional[str] = None,
    mcp_servers: Optional[List] = None,
) -> str:
    """
    Orchestrates comprehensive Nessus verification using the two-agent workflow:
    1. Recommendation phase - analyzes findings and generates testing strategies
    2. Verification phase - executes actual penetration tests
    3. Compilation phase - combines results into final verified XML
    """
    agent = nessus_verifier_agent
    if mcp_servers:
        # Create new agent with MCP servers if provided
        agent = Agent(
            name=nessus_verifier_agent.name,
            description=nessus_verifier_agent.description,
            instructions=nessus_verifier_agent.instructions,
            handoffs=nessus_verifier_agent.handoffs,
            model=nessus_verifier_agent.model,
            mcp_servers=mcp_servers,
        )

    # Start the orchestrated workflow
    result = await Runner.run(
        starting_agent=agent,
        input=f"""Begin comprehensive Nessus verification for file: {file_path}

Please execute the two-phase verification process:
1. First, transfer to the Nessus Recommend Agent to analyze findings and generate testing recommendations
2. Then, transfer to the Nessus Verify Agent to execute actual penetration tests and validate findings
3. Provide the final consolidated verification results

File to analyze: {file_path}""",
        run_config=RunConfig(tracing_disabled=True),
    )
    
    final_output = result.final_output

    # Try to parse the final output as verification results
    try:
        if isinstance(final_output, (dict, list)):
            parsed_obj = final_output
        elif isinstance(final_output, str):
            parsed_obj = _extract_json_object(final_output)
        else:
            parsed_obj = _extract_json_object(str(final_output))
        
        # Check if this is the new verification format
        if isinstance(parsed_obj, dict) and "verification_results" in parsed_obj:
            # Convert to legacy decisions format for XML compilation
            decisions_data = _convert_verification_to_decisions(parsed_obj)
        elif isinstance(parsed_obj, dict) and "recommendations" in parsed_obj:
            # Handle case where we only got recommendations (verification phase didn't complete)
            decisions_data = _convert_recommendations_to_decisions(parsed_obj)
        elif isinstance(parsed_obj, dict) and "decisions" in parsed_obj:
            # Already in legacy format
            decisions_data = parsed_obj
        else:
            # Fallback: try to extract any structured data
            decisions_data = {"decisions": [], "meta": {"notes": "Could not parse verification results properly"}}
        
        decisions_json_str = json.dumps(decisions_data, ensure_ascii=False)
        
    except Exception as e:
        # Provide a short preview to help debugging
        preview = str(final_output)[:500] if final_output is not None else "<None>"
        raise ValueError(f"Could not parse verification results from model output: {e}. Preview: {preview}")

    # Compile XML with verification results
    final_xml = compile_nessus_report_with_verification_impl(
        original_report_path=file_path,
        decisions_json=decisions_json_str,
        output_path=output_path or "",
    )
    return final_xml

def _convert_recommendations_to_decisions(recommendations_data: dict) -> dict:
    """Convert recommendations format to legacy decisions format as fallback."""
    recommendations = recommendations_data.get("recommendations", [])
    decisions = []
    
    for rec in recommendations:
        risk = rec.get("risk_assessment", {})
        decision = {
            "host": rec.get("host", ""),
            "plugin_id": rec.get("plugin_id", ""),
            "port": rec.get("port", "0"),
            "protocol": rec.get("protocol", "tcp"),
            "status": risk.get("status", "needs_verification").replace("needs_verification", "uncertain").replace("likely_false_positive", "rejected").replace("confirmed_by_analysis", "confirmed"),
            "confidence": risk.get("confidence", 0.5),
            "score": risk.get("adjusted_score", risk.get("initial_score", 50)),
            "rationale": f"{rec.get('plugin_name', 'Unknown')} - {risk.get('status', 'uncertain')}. {rec.get('evidence_analysis', {}).get('plugin_output_summary', '')}",
            "recommended_tests": rec.get("testing_strategy", {}).get("primary_tests", [])[:3]
        }
        decisions.append(decision)
    
    return {
        "decisions": decisions,
        "meta": {
            "scoring_profile": "recommendation_based", 
            "notes": f"Based on recommendations analysis. {len(decisions)} findings analyzed. Verification phase incomplete."
        }
    }