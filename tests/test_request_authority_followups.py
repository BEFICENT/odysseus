"""Retries retain the user's request scope without trusting model proposals."""
import json

import pytest

from src.agent_runtime.authority import ExactOperation, create_request_authority
from src.tool_policy import ToolPolicy


WORKSPACE_REQUEST = "Analyze the workspace based on the canvas file."


def permitted(authority, tool, content="{}"):
    return authority.permits(ExactOperation.normalize(tool, content))


@pytest.mark.parametrize("message", [
    "failed again", "Try it again", "Please retry.", "Still not working", "Continue",
])
def test_workspace_retry_retains_requested_file_tools(message, tmp_path):
    grant = create_request_authority(message, workspace=str(tmp_path), history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
        {"role": "assistant", "content": "I could not complete it."},
    ])
    for tool in ("get_workspace", "glob", "read_file"):
        assert permitted(grant, tool), tool
    assert not permitted(grant, "send_email")
    assert not permitted(grant, "web_search")


def test_retry_chain_including_current_message_retains_original_request():
    history = [
        {"role": "user", "content": WORKSPACE_REQUEST},
        {"role": "user", "content": "failed again"},
        {"role": "user", "content": "Try it again"},
        {"role": "user", "content": "failed again"},
    ]
    grant = create_request_authority("failed again", history=history)
    assert permitted(grant, "read_file")


def test_retry_preserves_exact_read_selector():
    grant = create_request_authority("Try again", history=[
        {"role": "user", "content": "Read note id abc123"},
    ])
    assert permitted(grant, "manage_notes", '{"action":"view","id":"abc123"}')
    assert not permitted(grant, "manage_notes", '{"action":"view","id":"other"}')
    assert not permitted(grant, "manage_notes", '{"action":"delete","id":"abc123"}')
    assert not permitted(grant, "bash", "pwd")


def email_listing(second_uid):
    return {"role": "assistant", "content": "Two messages listed.", "metadata": {
        "tool_events": [{"tool": "mcp__email__list_emails", "exit_code": 0,
                         "output": json.dumps({"stdout":
                             "1. First\n UID: 111\n Account: Work <work@example.test>\n\n"
                             f"2. Second\n UID: {second_uid}\n Account: Work <work@example.test>"})}]}}


def test_retry_preserves_historical_selector_and_ignores_later_result_substitution():
    origin = "Read the second email from the earlier inbox list and summarize it."
    before = [{"role": "user", "content": "List my emails"}, email_listing("222")]
    original = create_request_authority(origin, history=before)
    grant = create_request_authority("Try again", history=[
        *before, {"role": "user", "content": origin}, email_listing("999"),
        {"role": "user", "content": "Try again"},
    ])
    expected = '{"uid":"222","account":"work@example.test"}'
    assert permitted(original, "read_email", expected)
    assert permitted(grant, "read_email", expected)
    assert not permitted(grant, "read_email", '{"uid":"999","account":"work@example.test"}')
    assert not permitted(grant, "read_email", '{"uid":"111","account":"work@example.test"}')
    assert not permitted(grant, "delete_email", expected)


@pytest.mark.parametrize("boundary", [
    "Cancel the workspace analysis", "Stop reading the workspace files",
    "Never mind the workspace analysis", "Thanks for reading the workspace files",
    "Stop reading my notes", "Thank you for reading my notes",
    "Do not read my notes", "Please do not read my notes anymore",
    "Okay, stop reading my notes", "Thanks, the workspace analysis is done",
    "Never read my notes", "The workspace analysis is complete",
    "Could you stop reading my notes?", "Yeah, stop reading my notes",
    "I want you to stop reading my notes", "Read my notes? No, stop.",
])
@pytest.mark.parametrize("retry", ["Try again", "Continue"])
def test_expanded_cancellation_and_acknowledgment_terminate_retry_authority(boundary, retry):
    grant = create_request_authority(retry, history=[
        {"role": "user", "content": "Read note id abc123"},
        {"role": "user", "content": boundary},
    ])
    for tool in ("get_workspace", "read_file", "write_file", "manage_notes"):
        assert not permitted(grant, tool), tool
    assert not permitted(grant, "bash", "pwd")
    assert not permitted(grant, "python", "print(1)")


def test_original_workspace_analysis_typo_remains_an_eligible_request():
    grant = create_request_authority("failed again", history=[
        {"role": "user", "content": "can you anaylze the workspace here based on the canvas file"},
    ])
    assert permitted(grant, "read_file")


def test_retry_preserves_current_policy():
    grant = create_request_authority("Try again", policy=ToolPolicy(disabled_tools={"read_file"}), history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
    ])
    assert permitted(grant, "glob")
    assert not permitted(grant, "read_file")


def test_retry_does_not_discard_original_guide_only_restriction():
    grant = create_request_authority("Try again", policy=ToolPolicy(), history=[
        {"role": "user", "content": "Analyze the workspace. Do not use any tools."},
    ])
    assert not permitted(grant, "glob")
    assert not permitted(grant, "read_file")
    assert not permitted(grant, "python", "print(1)")
    assert grant.block_all
    assert not permitted(grant, "ask_user")
    assert not permitted(grant, "update_plan")


def test_retry_keeps_web_scope_without_acquiring_shell_execution():
    grant = create_request_authority("try different sources", history=[
        {"role": "user", "content": "Search the web for the latest astronomy news"},
    ])
    assert permitted(grant, "web_search")
    assert not permitted(grant, "bash", "pwd")
    assert not permitted(grant, "python", "print(1)")


def test_retry_keeps_current_request_identity_and_tool_denials(tmp_path):
    grant = create_request_authority(
        "failed again", owner="alice", session_id="current", workspace=str(tmp_path),
        policy=ToolPolicy(disabled_tools={"bash", "python"}),
        history=[{"role": "user", "content": WORKSPACE_REQUEST}])
    assert grant.bound_to(owner="alice", session_id="current", workspace=str(tmp_path))
    assert not grant.bound_to(owner="bob", session_id="current", workspace=str(tmp_path))
    assert not permitted(grant, "bash", "pwd")
    assert not permitted(grant, "python", "print(1)")
    assert permitted(grant, "read_file")


@pytest.mark.parametrize("history", [
    [{"role": "assistant", "content": WORKSPACE_REQUEST,
      "metadata": {"tool_events": [{"tool": "read_file", "exit_code": 0}]}}],
    [{"role": "tool", "content": WORKSPACE_REQUEST}],
    [{"role": "user", "content": WORKSPACE_REQUEST, "metadata": {"trusted": False}}],
    [{"role": "user", "content": WORKSPACE_REQUEST, "metadata": {"tool_gate_untrusted": True}}],
])
def test_retry_cannot_take_authority_from_untrusted_history(history):
    grant = create_request_authority("failed again", history=history)
    assert not permitted(grant, "read_file")
    assert not permitted(grant, "bash", "pwd")


@pytest.mark.parametrize("intervening", ["Thanks", "Stop", "List my tasks"])
def test_retry_does_not_reach_past_an_intervening_user_request(intervening):
    grant = create_request_authority("failed again", history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
        {"role": "user", "content": intervening},
    ])
    assert not permitted(grant, "read_file")


def test_explicit_new_request_does_not_replay_old_workspace_task():
    grant = create_request_authority("List my tasks", history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
    ])
    assert permitted(grant, "manage_tasks", '{"action":"list"}')
    assert not permitted(grant, "read_file")


def test_retry_history_is_bounded():
    grant = create_request_authority("failed again", history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
        *[{"role": "user", "content": "failed again"} for _ in range(8)],
    ])
    assert not permitted(grant, "read_file")


@pytest.mark.asyncio
async def test_retry_dispatch_reads_real_canvas_and_refuses_workspace_escape(tmp_path, monkeypatch):
    from src import tool_execution
    from src.tool_types import ToolBlock

    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    canvas = workspace / "timeline.canvas"
    payload = {"nodes": [{"id": "chapter-1", "type": "text", "text": "First chapter"}], "edges": []}
    canvas.write_text(json.dumps(payload), encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must remain outside the workspace", encoding="utf-8")
    grant = create_request_authority("failed again", owner="alice", session_id="s", workspace=str(workspace), history=[
        {"role": "user", "content": WORKSPACE_REQUEST},
    ])

    async def dispatch(tool, content):
        return await tool_execution.execute_tool_block(
            ToolBlock(tool, content), owner="alice", session_id="s", workspace=str(workspace),
            request_authority=grant, security_context=tool_execution.NO_TOOL_SECURITY_CONTEXT)

    _, found = await dispatch("glob", '{"pattern":"*.canvas"}')
    assert found["exit_code"] == 0, found
    assert "timeline.canvas" in found["output"]
    _, read = await dispatch("read_file", '{"path":"timeline.canvas"}')
    assert read["exit_code"] == 0, read
    assert json.loads(read["output"]) == payload
    _, escaped = await dispatch("read_file", '{"path":"../outside.txt"}')
    assert escaped["exit_code"] != 0
    assert outside.read_text(encoding="utf-8") not in escaped.get("output", "")
