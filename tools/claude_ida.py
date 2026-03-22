"""
IDA MCP Server (Unified)
------------------------
Single MCP server that discovers and routes to ALL running IDA instances.

IDA instances register themselves via ida_server.py into ~/.ida-mcp/instances/.
This server discovers them automatically — no hardcoded ports needed.

Configure with environment variables:
    IDA_HTTP_TIMEOUT   Per-request timeout in seconds (default: 30.0)

Run:
    python claude_ida.py
"""

from __future__ import annotations

import ctypes
import glob
import json
import logging
import os
import time
from typing import Any, Literal, Optional

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

# ---------------------------------------------------------------------------
# Logging (stderr, as recommended for stdio MCP servers)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ida-mcp")

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("ida-tools")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IDA_TIMEOUT = float(os.getenv("IDA_HTTP_TIMEOUT", "30.0"))
REGISTRY_DIR = os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")

# ---------------------------------------------------------------------------
# Instance discovery
# ---------------------------------------------------------------------------

# Cache to avoid hitting the filesystem on every tool call
_discovery_cache: list[dict[str, Any]] = []
_discovery_cache_time: float = 0.0
_CACHE_TTL = 3.0  # seconds


def _pid_exists(pid: int) -> bool:
    """Check if a process with the given PID exists (Windows)."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    return False


def _discover_live_instances(force: bool = False) -> list[dict[str, Any]]:
    """
    Read all instance files from the registry directory, validate liveness,
    and return a list of live instance records.

    Stale entries (dead PIDs) are cleaned up automatically.
    Results are cached for a few seconds to avoid repeated filesystem hits.
    """
    global _discovery_cache, _discovery_cache_time

    now = time.monotonic()
    if not force and _discovery_cache and (now - _discovery_cache_time) < _CACHE_TTL:
        return _discovery_cache

    if not os.path.isdir(REGISTRY_DIR):
        _discovery_cache = []
        _discovery_cache_time = now
        return []

    instances = []
    for path in glob.glob(os.path.join(REGISTRY_DIR, "*.json")):
        try:
            with open(path, "r") as f:
                info = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Corrupted or unreadable — skip
            continue

        pid = info.get("pid")
        if pid is None:
            continue

        # Check if the process is still alive
        if not _pid_exists(pid):
            # Stale entry — clean up
            try:
                os.unlink(path)
                logger.info("Cleaned up stale instance file: %s", path)
            except OSError:
                pass
            continue

        instances.append(info)

    _discovery_cache = instances
    _discovery_cache_time = now
    return instances


def _instance_label(inst: dict[str, Any]) -> str:
    """Format an instance record for display in error messages."""
    return f"  - {inst['instance_id']} (port={inst.get('port')}, pid={inst.get('pid')})"


def _resolve_target(target: str) -> dict[str, Any]:
    """
    Resolve a target to a single instance record.

    target is REQUIRED and must be one of:
    - The exact full file path (instance_id) as shown by ida_list_instances
    - A port number (integer or "port=N")

    No substring matching is performed. Call ida_list_instances first to see
    available targets, then copy the exact instance_id or port.
    """
    instances = _discover_live_instances()

    if not instances:
        raise ToolError(
            "No IDA instances are running. Load ida_server.py in IDA first."
        )

    if not target or not target.strip():
        raise ToolError(
            "target is REQUIRED. You must provide either:\n"
            "  1. The exact full file path (instance_id) from ida_list_instances\n"
            "  2. The port number (e.g. 58013)\n"
            "Call ida_list_instances first to see available targets.\n"
            "Available instances:\n"
            + "\n".join(_instance_label(i) for i in instances)
        )

    target = target.strip()

    # Match by port number — accept bare integer or "port=N"
    port_str = target[5:] if target.startswith("port=") else target
    try:
        port_num = int(port_str)
        for inst in instances:
            if inst.get("port") == port_num:
                return inst
    except ValueError:
        pass

    # Exact match on instance_id (full path) — case-insensitive for Windows paths
    for inst in instances:
        if inst["instance_id"].lower() == target.lower():
            return inst

    raise ToolError(
        f'No IDA instance found for target "{target}".\n'
        "target must be the EXACT full file path (instance_id) or port number.\n"
        "Do NOT use substrings or partial paths. Call ida_list_instances to get the exact values.\n"
        "Available instances:\n"
        + "\n".join(_instance_label(i) for i in instances)
    )


# ---------------------------------------------------------------------------
# HTTP helpers (target-aware)
# ---------------------------------------------------------------------------


def _base_url(target: str) -> str:
    """Resolve target to a base URL like http://127.0.0.1:51234."""
    inst = _resolve_target(target)
    return f"http://{inst['host']}:{inst['port']}"


def _url(target: str, path: str) -> str:
    base = _base_url(target)
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _handle_response(resp: requests.Response, url: str) -> dict[str, Any]:
    """Check status, parse JSON, raise ToolError on problems."""
    if resp.status_code >= 400:
        text = resp.text.strip()[:500]
        logger.warning("IDA %s %s: %s", resp.status_code, url, text)
        raise ToolError(f"IDA HTTP {resp.status_code} for {url}: {text}")
    try:
        return resp.json()
    except ValueError as exc:
        logger.error("Non-JSON from %s: %s", url, resp.text[:200])
        raise ToolError(f"Non-JSON response from IDA at {url}") from exc


def _ida_get(
    target: str, path: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET JSON from a specific IDA HTTP server."""
    url = _url(target, path)
    logger.debug("GET %s %s", url, params)
    try:
        resp = requests.get(url, params=params or {}, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


def _ida_post(
    target: str, path: str, body: dict[str, Any]
) -> dict[str, Any]:
    """POST JSON to a specific IDA HTTP server."""
    url = _url(target, path)
    logger.debug("POST %s %s", url, body)
    try:
        resp = requests.post(url, json=body, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


def _normalize_ea(ea: str) -> str:
    """
    Normalize a hex address string.
    Accepts "0x401000", "401000", "0X401000".
    Returns lowercase hex with 0x prefix.
    """
    s = ea.strip().lower()
    if not s:
        raise ToolError("ea must be a non-empty hex string")
    if s.startswith("0x"):
        s = s[2:]
    try:
        value = int(s, 16)
    except ValueError as exc:
        raise ToolError(f"ea must be a hex address, got {ea!r}") from exc
    return f"0x{value:x}"


# ---------------------------------------------------------------------------
# Discovery tool
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_list_instances() -> dict[str, Any]:
    """
    List all running IDA instances available for analysis.
    IMPORTANT: Call this FIRST before any other ida_ tool. All other tools require
    the "target" parameter, which must be either:
      1. The exact "instance_id" value (full file path) from this response — copy it exactly
      2. The "port" number from this response

    Do NOT use substrings, partial paths, or DLL names as target. Always use the exact value.

    Returns:
        {"count": N, "instances": [{"instance_id", "port", "pid", "started_at"}, ...]}
    """
    instances = _discover_live_instances(force=True)
    # Strip host field from output (always 127.0.0.1), keep it clean
    cleaned = []
    for inst in instances:
        cleaned.append({
            "instance_id": inst.get("instance_id"),
            "port": inst.get("port"),
            "pid": inst.get("pid"),
            "started_at": inst.get("started_at"),
            "ida_version": inst.get("ida_version"),
        })
    return {"count": len(cleaned), "instances": cleaned}


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_ping(target: str) -> dict[str, Any]:
    """
    Health check. Returns IDA version, Hex-Rays availability, and readonly status.

    Args:
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.
    """
    return _ida_get(target, "/api/ping")


@mcp.tool()
def ida_info(target: str) -> dict[str, Any]:
    """
    Get metadata about the loaded IDB: file path, imagebase, architecture,
    pointer size, segment bounds, Hex-Rays availability, readonly mode.

    Args:
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.
    """
    return _ida_get(target, "/api/info")


@mcp.tool()
def ida_get_bytes(target: str, ea: str, size: int = 256) -> dict[str, Any]:
    """
    Read raw bytes at an address.

    Args:
        ea: Hex address string (e.g. "0x401000").
        size: Number of bytes to read (default 256).
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "size", "bytes_hex"} where bytes_hex is a lowercase hex string.
    """
    if size <= 0:
        raise ToolError("size must be positive")
    return _ida_get(target, "/api/bytes", {"ea": _normalize_ea(ea), "size": str(size)})


@mcp.tool()
def ida_get_disasm(target: str, ea: str, count: int = 50) -> dict[str, Any]:
    """
    Get disassembly lines starting at an address.

    Args:
        ea: Hex address string.
        count: Max number of instructions (default 50).
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"start_ea", "count", "disasm": [{"ea", "text"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get(target, "/api/disasm", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_decompile(ea: str, target: str) -> dict[str, Any]:
    """
    Decompile the function containing the given address using Hex-Rays.

    Args:
        ea: Hex address string.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "function": {"name", "start_ea", "end_ea"}, "pseudocode"}
    """
    return _ida_get(target, "/api/decompile", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_get_function_context(ea: str, target: str) -> dict[str, Any]:
    """
    Get rich context for the function containing an address: disassembly,
    pseudocode, callers, callees, xrefs, and comments.

    Args:
        ea: Hex address string.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {
            "ea", "in_function",
            "function": {"name", "start_ea", "end_ea"} | null,
            "bytes_at_ea", "disasm", "pseudocode",
            "xrefs_from", "xrefs_to", "callers", "callees",
            "function_comment", "function_repeatable_comment",
            "instr_comments"
        }
    """
    return _ida_get(target, "/api/function", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_list_functions(
    target: str,
    limit: int = 0,
    name_filter: Optional[str] = None,
    mode: Literal["fast", "full"] = "fast",
) -> dict[str, Any]:
    """
    List functions known to IDA.

    Args:
        limit: Max functions to return. 0 = no limit.
        name_filter: Case-insensitive substring filter on function names.
        mode: "fast" for basic info, "full" to also count xrefs_to and include type.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "functions": [{"start_ea", "end_ea", "name", "size", ...}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    if mode not in ("fast", "full"):
        raise ToolError("mode must be 'fast' or 'full'")
    params: dict[str, str] = {"limit": str(limit), "mode": mode}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/functions", params)


@mcp.tool()
def ida_get_xrefs(
    target: str,
    ea: str,
    direction: Literal["from", "to", "both"] = "both",
) -> dict[str, Any]:
    """
    Get cross-references for an address.

    Args:
        ea: Hex address string.
        direction: "from" (outgoing), "to" (incoming), or "both".
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "xrefs_from": [...], "xrefs_to": [...]}
        Each xref has {from, to, type, type_name}.
    """
    if direction not in ("from", "to", "both"):
        raise ToolError("direction must be 'from', 'to', or 'both'")
    return _ida_get(target, "/api/xrefs", {"ea": _normalize_ea(ea), "direction": direction})


@mcp.tool()
def ida_get_names(
    target: str,
    limit: int = 0,
    name_filter: Optional[str] = None,
) -> dict[str, Any]:
    """
    List named addresses in the IDB.

    Args:
        limit: Max entries. 0 = no limit.
        name_filter: Case-insensitive substring filter.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "names": [{"ea", "name"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    params: dict[str, str] = {"limit": str(limit)}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/names", params)


@mcp.tool()
def ida_get_strings(
    target: str,
    limit: int = 0,
    min_length: int = 4,
) -> dict[str, Any]:
    """
    List string literals found in the binary.

    Args:
        limit: Max strings to return. 0 = no limit.
        min_length: Minimum string length to include (default 4).
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "strings": [{"ea", "length", "type", "value"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    return _ida_get(target, "/api/strings", {"limit": str(limit), "min_length": str(min_length)})


@mcp.tool()
def ida_get_segments(target: str) -> dict[str, Any]:
    """
    List all segments (sections) in the binary.

    Args:
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "segments": [{"start_ea", "end_ea", "name", "class", "size", "perm", "bitness"}, ...]}
    """
    return _ida_get(target, "/api/segments")


@mcp.tool()
def ida_get_imports(target: str) -> dict[str, Any]:
    """
    List all imported modules and their functions.

    Args:
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "modules": {"dll_name": [{"ea", "name", "ordinal"}, ...], ...}}
    """
    return _ida_get(target, "/api/imports")


@mcp.tool()
def ida_get_exports(target: str) -> dict[str, Any]:
    """
    List all exported entry points.

    Args:
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "exports": [{"index", "ordinal", "ea", "name"}, ...]}
    """
    return _ida_get(target, "/api/exports")


@mcp.tool()
def ida_list_structs(target: str, name_filter: Optional[str] = None) -> dict[str, Any]:
    """
    List structure types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "structs": [{"index", "id", "name", "size", "is_union"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/structs", params)


@mcp.tool()
def ida_get_struct(name: str, target: str) -> dict[str, Any]:
    """
    Get full details of a struct by name, including all members.

    Args:
        name: Exact struct name.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"name", "id", "size", "is_union",
         "members": [{"offset", "name", "size", "type", "comment"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get(target, "/api/struct", {"name": name})


@mcp.tool()
def ida_list_enums(target: str, name_filter: Optional[str] = None) -> dict[str, Any]:
    """
    List enum types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"count", "enums": [{"id", "name", "is_bitfield", "member_count"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/enums", params)


@mcp.tool()
def ida_get_enum(name: str, target: str) -> dict[str, Any]:
    """
    Get full details of an enum by name, including all members.

    Args:
        name: Exact enum name.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"name", "id", "is_bitfield",
         "members": [{"name", "value", "value_hex"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get(target, "/api/enum", {"name": name})


@mcp.tool()
def ida_get_vtable(target: str, ea: str, count: int = 64) -> dict[str, Any]:
    """
    Read a vtable as an array of pointers at a given address.
    Each pointer is resolved to a function name where possible.
    Stops early if a pointer target looks invalid (null, out of bounds).

    Args:
        ea: Hex address of the vtable start.
        count: Max number of slots to read (default 64).
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "pointer_size", "count",
         "entries": [{"index", "slot_ea", "target", "name", "is_function"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get(target, "/api/vtable", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_get_address_info(ea: str, target: str) -> dict[str, Any]:
    """
    Get detailed information about a single address: name, type, segment,
    flags (code/data/head/tail), containing function, comments, raw bytes.

    Args:
        ea: Hex address string.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "name", "type", "segment", "is_code", "is_data", "is_head",
         "is_tail", "in_function", "function_name", "function_start",
         "comment", "repeatable_comment", "item_size", "bytes_hex"}
    """
    return _ida_get(target, "/api/address", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_search_bytes(
    target: str,
    pattern: str,
    start: Optional[str] = None,
    direction: Literal["down", "up"] = "down",
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Search for a byte pattern in the binary.

    Args:
        pattern: Hex byte pattern with optional '??' wildcards,
                 e.g. "48 8B ?? 10" or "E8 ?? ?? ?? FF".
        start: Hex address to start searching from. Defaults to min_ea (down) or max_ea (up).
        direction: "down" (forward) or "up" (backward). Default "down".
        max_results: Max matches to return (default 100).
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"pattern", "count", "results": [{"ea", "name"}, ...]}
    """
    if not pattern:
        raise ToolError("pattern is required")
    if direction not in ("down", "up"):
        raise ToolError("direction must be 'down' or 'up'")
    if max_results <= 0:
        raise ToolError("max_results must be positive")
    params: dict[str, str] = {
        "pattern": pattern,
        "direction": direction,
        "max_results": str(max_results),
    }
    if start:
        params["start"] = _normalize_ea(start)
    return _ida_get(target, "/api/search", params)


# ---------------------------------------------------------------------------
# Write tools (will return 403 if the IDA server is in readonly mode)
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_rename(ea: str, name: str, target: str) -> dict[str, Any]:
    """
    Rename an address (function, global, label, etc).

    Args:
        ea: Hex address to rename.
        name: New name. Use "" to clear an existing name.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "name", "success": true}

    Raises:
        ToolError with a 403 message if the IDA server is in readonly mode.
    """
    return _ida_post(target, "/api/rename", {"ea": _normalize_ea(ea), "name": name})


@mcp.tool()
def ida_set_comment(target: str, ea: str, comment: str, repeatable: bool = False) -> dict[str, Any]:
    """
    Set a comment at an address.

    Args:
        ea: Hex address.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post(target, "/api/comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_func_comment(target: str, ea: str, comment: str, repeatable: bool = False) -> dict[str, Any]:
    """
    Set a comment on the function containing an address.

    Args:
        ea: Hex address within the target function.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post(target, "/api/func_comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_type(ea: str, type_decl: str, target: str) -> dict[str, Any]:
    """
    Apply a C type declaration at an address.

    Args:
        ea: Hex address.
        type_decl: C type string, e.g. "int __fastcall(int a, int b)"
                   or "struct MyStruct *". The trailing semicolon is
                   added automatically if missing.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "type", "success": true}
    """
    if not type_decl:
        raise ToolError("type_decl is required")
    return _ida_post(target, "/api/set_type", {
        "ea": _normalize_ea(ea),
        "type": type_decl,
    })


@mcp.tool()
def ida_create_function(target: str, start_ea: str, end_ea: Optional[str] = None) -> dict[str, Any]:
    """
    Create a function at the given address range. If end_ea is omitted,
    IDA will try to determine the function boundaries automatically.

    Args:
        start_ea: Hex address of the function start.
        end_ea: Optional hex address of the function end.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"start_ea", "end_ea", "success": true}
    """
    body: dict[str, str] = {"start_ea": _normalize_ea(start_ea)}
    if end_ea:
        body["end_ea"] = _normalize_ea(end_ea)
    return _ida_post(target, "/api/create_function", body)


@mcp.tool()
def ida_delete_function(ea: str, target: str) -> dict[str, Any]:
    """
    Delete the function containing the given address.

    Args:
        ea: Hex address within the function to delete.
        target: REQUIRED. The exact full file path (instance_id) or port number from ida_list_instances. No substrings.

    Returns:
        {"ea", "success": true}
    """
    return _ida_post(target, "/api/delete_function", {"ea": _normalize_ea(ea)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Run the MCP server over stdio.

    Environment variables:
        IDA_HTTP_TIMEOUT  Request timeout in seconds (default 30.0)
    """
    logger.info(
        "Starting unified IDA MCP server, registry=%s, timeout=%.1fs",
        REGISTRY_DIR,
        IDA_TIMEOUT,
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
