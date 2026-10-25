# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Stdio MCP server (Apache 2.0 interface layer) — agent surface.

Exposes two tools to an *authorized agent*: ``mykey_list`` (metadata
only) and ``mykey_get`` (one credential the agent's scopes cover).
All authorization lives in the proprietary core (agents.py); this
module only speaks newline-delimited JSON-RPC 2.0 on stdio.

The agent token comes from the environment variable
``MYKEY_AGENT_KEY``; the vault path from ``MYKEY_VAULT`` (default
``vault.mykey``). The agent never receives a master password.
Diagnostics go to stderr only — stdout carries protocol messages.

FLEET NOTE: drafted by Claude (anthropic/claude-sonnet-5 via
OpenRouter) under the three-builder rule, then reviewed line-by-line
and integrated by Wright. Adopted from the draft: uniform auth-error
text (no reason leakage), strict argument validation, strict tool
schemas. Rejected from the draft: its lazily CACHED agent session —
revocation must apply on the next call, so this server
re-authenticates per call (see _session_or_error).
"""

import json
import os
import sys

import brand
from agents import AgentAuthError, AgentScopeError, open_agent_session

_PROTOCOL_VERSION = "2024-11-05"

_AUTH_ERROR_TEXT = (
    "Could not start an agent session. The agent token may be "
    "invalid, expired, revoked, or the vault may be unavailable."
)
_NOT_AVAILABLE = {"error": "not available for this agent"}

_TOOLS = [
    {
        "name": "mykey_list",
        "description": "List metadata (service, username, url, tags) for "
                       "vault entries visible to this agent. Never "
                       "returns passwords.",
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
    {
        "name": "mykey_get",
        "description": "Return one credential this agent is authorized "
                       "for. Denied entries and missing entries look "
                       "the same to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string"},
                "username": {"type": "string"},
            },
            "required": ["service"],
            "additionalProperties": False,
        },
    },
]


def _log(*args):
    print(*args, file=sys.stderr, flush=True)


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _tool_result(payload, is_error=False):
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "isError": is_error,
    }


class McpServer:
    def __init__(self, vault_path, token):
        self.vault_path = vault_path
        self.token = token

    def _session_or_error(self):
        # Authenticate PER CALL, never cache a session: revocation,
        # disable and scope changes must take effect on the very next
        # call even in this long-lived process. The cost is one
        # Argon2id derivation per call — the right trade for a
        # credential endpoint.
        if not self.token:
            raise AgentAuthError(
                "MYKEY_AGENT_KEY is not set — an agent token is required")
        return open_agent_session(self.vault_path, self.token)

    def call_tool(self, name, arguments):
        try:
            session = self._session_or_error()
            if name == "mykey_list":
                return _tool_result(session.list_metadata())
            if name == "mykey_get":
                service = (arguments or {}).get("service")
                if not isinstance(service, str) or not service.strip():
                    return _tool_result(
                        {"error": "a service name is required"}, is_error=True)
                username = (arguments or {}).get("username")
                if username is not None and not isinstance(username, str):
                    return _tool_result(
                        {"error": "username must be a string"}, is_error=True)
                entry = session.get(service, username)
                return _tool_result(entry)
            return _tool_result({"error": f"unknown tool: {name}"},
                                is_error=True)
        except AgentScopeError:
            return _tool_result(dict(_NOT_AVAILABLE), is_error=True)
        except AgentAuthError as exc:
            # Uniform text outward; the real reason goes to stderr for
            # the operator only (adopted from the fleet draft review).
            _log("agent auth failed:", exc)
            return _tool_result({"error": _AUTH_ERROR_TEXT}, is_error=True)
        except KeyError:
            # Missing and denied must look identical from outside.
            return _tool_result(dict(_NOT_AVAILABLE), is_error=True)
        except Exception as exc:  # never leak a traceback into the result
            _log("tool error:", exc)
            return _tool_result({"error": "internal error"}, is_error=True)

    def handle(self, msg):
        if not isinstance(msg, dict):
            return None
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "initialize":
            return _result(req_id, {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mykey", "version": "2.2.1"},
            })
        if method == "ping":
            return _result(req_id, {})
        if method == "tools/list":
            return _result(req_id, {"tools": _TOOLS})
        if method == "tools/call":
            params = msg.get("params")
            if not isinstance(params, dict):
                return _error(req_id, -32602, "invalid params: expected an object")
            if params.get("name") not in ("mykey_list", "mykey_get"):
                return _error(req_id, -32602, "invalid params: unknown tool")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return _error(req_id, -32602,
                              "invalid params: 'arguments' must be an object")
            return _result(req_id, self.call_tool(params.get("name"), arguments))
        if method and method.startswith("notifications/"):
            return None
        if req_id is not None:
            return _error(req_id, -32601, f"method not found: {method}")
        return None

    def serve(self, instream, outstream):
        for line in instream:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _log("skipping malformed line")
                continue
            try:
                resp = self.handle(msg)
            except Exception as exc:  # keep the loop alive
                _log("handler error:", exc)
                resp = _error(msg.get("id"), -32603, "internal error")
            if resp is not None:
                outstream.write(json.dumps(resp) + "\n")
                outstream.flush()
        return 0


def main():
    vault_path = os.environ.get("MYKEY_VAULT", "vault.mykey")
    token = os.environ.get("MYKEY_AGENT_KEY", "")
    _log(f"{brand.PRODUCT_NAME} MCP server (stdio) — vault: {vault_path}")
    return McpServer(vault_path, token).serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
