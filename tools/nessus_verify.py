# Must be first: configure model before any agent imports
import os
import argparse
from dotenv import load_dotenv

load_dotenv()  # load .env

parser = argparse.ArgumentParser()
parser.add_argument(
    "--model",
    help="Override CAI_MODEL for this run (e.g. 'gemini/gemini-2.5-flash')"
)
# Allow unknown args to pass through if script already uses argparse elsewhere
args, _ = parser.parse_known_args()

# Priority: CLI --model > existing CAI_MODEL in env > default for this script
if args.model:
    os.environ["CAI_MODEL"] = args.model
elif not os.getenv("CAI_MODEL"):
    os.environ["CAI_MODEL"] = "gemini/gemini-2.5-flash"

# Now import the rest (agents, etc.) so they see the final CAI_MODEL
import asyncio
import sys
from pathlib import Path

from cai.agents.nessus_verifier import verify_nessus_report
# Optional: load an MCP SSE server
# from cai.sdk.agents.mcp import MCPServerSse, MCPServerSseParams


async def _amain():
    parser = argparse.ArgumentParser(description="Verify & re-score a Nessus XML report with CAI.")
    parser.add_argument("input", help="Path to Nessus XML (.nessus)")
    parser.add_argument("-o", "--output", help="Path to write verified XML", default="")
    # parser.add_argument("--mcp-sse-url", help="MCP SSE server URL", default="")
    # parser.add_argument("--mcp-name", help="MCP name", default="nessus_mcp")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    mcp_servers = []
    # if args.mcp_sse_url:
    #     mcp_servers = [MCPServerSse(MCPServerSseParams(url=args.mcp_sse_url, name=args.mcp_name))]

    xml_str = await verify_nessus_report(
        file_path=str(in_path),
        output_path=args.output or "",
        mcp_servers=mcp_servers or None,
    )

    if not args.output:
        # If no output path, print to stdout
        print(xml_str)


def main():
    asyncio.run(_amain())


if __name__ == "__main__":
    main()