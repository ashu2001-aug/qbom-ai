"""
mcp/server.py — Model Context Protocol server that exposes database functions
as standardised tools callable by any LangGraph agent.

The MCP server wraps PostgreSQL queries so agents can call them like any
other tool without knowing the underlying schema.
"""
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent, CallToolResult
from mcp.server.stdio import stdio_server
import json
import asyncio
from sqlalchemy import text
from models.db import AsyncSessionLocal


app = Server("qbom-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_scan_history",
            description="Retrieve past scan results for a target URL or repo",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or repo to look up"},
                    "limit": {"type": "integer", "default": 5}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="query_crypto_knowledge",
            description="Look up documentation and migration guidance for a cryptographic algorithm",
            inputSchema={
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string", "description": "Algorithm name e.g. RSA-2048"}
                },
                "required": ["algorithm"]
            }
        ),
        Tool(
            name="save_finding",
            description="Persist a new cryptographic finding to the database",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "algorithm": {"type": "string"},
                    "location": {"type": "string"},
                    "hndl_score": {"type": "number"},
                    "is_shadow_crypto": {"type": "boolean"}
                },
                "required": ["scan_id", "algorithm", "location"]
            }
        ),
        Tool(
            name="get_project_risk_summary",
            description="Return aggregated risk metrics across all scans for a project",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {"type": "string"}
                },
                "required": ["project_name"]
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
    async with AsyncSessionLocal() as db:
        if name == "get_scan_history":
            result = await db.execute(
                text("SELECT id, status, hndl_score, risk_level, created_at FROM scans WHERE target = :t ORDER BY created_at DESC LIMIT :l"),
                {"t": arguments["target"], "l": arguments.get("limit", 5)}
            )
            rows = [dict(r._mapping) for r in result]
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(rows, default=str))])

        elif name == "query_crypto_knowledge":
            result = await db.execute(
                text("SELECT algorithm, content, source FROM crypto_knowledge WHERE algorithm ILIKE :a LIMIT 3"),
                {"a": f"%{arguments['algorithm']}%"}
            )
            rows = [dict(r._mapping) for r in result]
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(rows))])

        elif name == "save_finding":
            from uuid import uuid4
            from models.db import ScanFinding
            quantum_vulnerable = arguments["algorithm"] in {
                "RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "3DES", "RC4", "MD5", "SHA-1", "AES-128"
            }
            finding = ScanFinding(
                id=str(uuid4()),
                scan_id=arguments["scan_id"],
                algorithm=arguments["algorithm"],
                location=arguments["location"],
                hndl_score=float(arguments.get("hndl_score", 0.0)),
                is_shadow_crypto=bool(arguments.get("is_shadow_crypto", False)),
                quantum_vulnerable=quantum_vulnerable
            )
            db.add(finding)
            await db.commit()
            return CallToolResult(content=[TextContent(type="text", text='{"saved": true}')])

        elif name == "get_project_risk_summary":
            result = await db.execute(
                text("""SELECT AVG(hndl_score) as avg_hndl, COUNT(*) as scan_count,
                               MAX(risk_level) as highest_risk
                        FROM scans WHERE target LIKE :p"""),
                {"p": f"%{arguments['project_name']}%"}
            )
            row = dict(result.fetchone()._mapping)
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(row, default=str))])

    return CallToolResult(content=[TextContent(type="text", text='{"error": "unknown tool"}')])


async def run_mcp_server():
    """Start the MCP server over stdio (for local use) or HTTP (for AKS deployment)."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="qbom-mcp",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=None,
                    experimental_capabilities={}
                )
            )
        )


if __name__ == "__main__":
    asyncio.run(run_mcp_server())
