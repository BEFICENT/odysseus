"""Synthetic workspace clarification regressions; no private session fixtures."""
import json

import pytest

from src.agent_runtime.authority import create_request_authority, ExactOperation, OperationGrant, RequestAuthority
from src.tool_policy import ToolPolicy


ORIGINAL = "Analyze the diagram in the workspace canvas file."
CLARIFICATION = (
    "The numeric labels are outdated. Use the cards inside the diagram groups, "
    "order the notes by vertical position, and interpret outlines as draft status."
)
READ_TOOLS = {"get_workspace", "ls", "glob", "grep", "read_file"}
DIAGNOSTIC = "Do you lack permissions to read it?"


def allowed(grant, tool, content="{}"):
    return grant.permits(ExactOperation.normalize(tool, content))


def history(workspace, *followups):
    return [{"role": "user", "content": text, "metadata": {"workspace": str(workspace)}}
            for text in (ORIGINAL, *followups)]


@pytest.mark.parametrize("message", [
    CLARIFICATION,
    "Do not use filename numbering; use the enclosing groups.",
    "Stop following the old numbering; use the vertical positions of those cards.",
    "Use the cards inside the canvas, not my saved notes.",
    DIAGNOSTIC,
    "Do you need administrator access or Bash permissions to continue?",
])
def test_contextual_workspace_followups_retain_only_read_grants(tmp_path, message):
    grant = create_request_authority(message, workspace=str(tmp_path), history=history(tmp_path))
    assert READ_TOOLS <= {g.tool for g in grant.grants}
    for tool in READ_TOOLS:
        assert allowed(grant, tool)
    for tool in ["manage_notes", "write_file", "edit_file", "apply_patch", "manage_settings", "web_search"]:
        assert not allowed(grant, tool), tool
    assert not allowed(grant, "bash", "pwd")
    assert not allowed(grant, "python", "print(1)")


def test_clarification_permission_question_and_retry_chain_preserves_read_context(tmp_path):
    rows = history(tmp_path, CLARIFICATION, DIAGNOSTIC)
    for message in [DIAGNOSTIC, "failed again"]:
        grant = create_request_authority(message, workspace=str(tmp_path), history=rows)
        assert allowed(grant, "read_file")
        assert not allowed(grant, "manage_notes")
        assert not allowed(grant, "write_file")


def test_route_history_already_containing_current_user_turn(tmp_path):
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                    history=history(tmp_path, CLARIFICATION, DIAGNOSTIC))
    assert allowed(grant, "read_file")


@pytest.mark.parametrize("appended_current", [False, True])
def test_qualified_retry_does_not_break_later_workspace_clarifications(tmp_path, appended_current):
    retry = "Could you retry now please?"
    rows = history(tmp_path, CLARIFICATION, DIAGNOSTIC)
    for message in (retry, CLARIFICATION):
        if appended_current:
            rows.append({"role": "user", "content": message})
        grant = create_request_authority(message, workspace=str(tmp_path), history=rows)
        assert allowed(grant, "read_file")
        for tool in ("manage_notes", "write_file", "edit_file", "bash", "python"):
            assert not allowed(grant, tool)
        disabled = create_request_authority(message, workspace=str(tmp_path), history=rows,
                                             policy=ToolPolicy(disabled_tools={"read_file"}))
        assert not allowed(disabled, "read_file")
        if not appended_current:
            rows.append({"role": "user", "content": message})


@pytest.mark.parametrize("topic,operation", [
    ("List my saved notes", {"action": "list"}),
    ("Ignore the canvas; list my saved notes", {"action": "list"}),
    ("Create a note about the canvas", {"action": "create", "title": "Example", "content": "Synthetic"}),
])
def test_explicit_personal_notes_request_uses_fresh_admission(tmp_path, topic, operation):
    grant = create_request_authority(topic, workspace=str(tmp_path), history=history(tmp_path))
    assert allowed(grant, "manage_notes", json.dumps(operation))
    assert not allowed(grant, "read_file")


@pytest.mark.parametrize("boundary", [
    "List my tasks", "Thanks", "How do I bake bread?", "Stop reading the workspace files",
    "Cancel the workspace analysis", "Do not access the canvas", "Do not use read_file",
    "Never access the actual file contents; only interpret the canvas",
    "Do not read any more details from those files",
    "Do not read restricted-record.txt; only use the canvas metadata",
    "Thanks for the details about those files",
    "Stop the review of the canvas; its status is irrelevant",
])
def test_context_does_not_cross_new_topics_or_read_revocations(tmp_path, boundary):
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                    history=history(tmp_path, boundary))
    assert not allowed(grant, "read_file")
    assert not allowed(grant, "manage_notes")
    assert not allowed(grant, "bash", "pwd")


@pytest.mark.parametrize("boundary", [
    "Use the groups but do not read any files",
    "Follow those positions but stop the analysis",
    "Use the canvas groups, but never access those files",
    "Use the groups instead do not access those files",
    "Use the groups; however stop the analysis",
    "Use the groups and do not read any files",
])
def test_revocation_in_a_later_clause_blocks_current_and_following_turns(tmp_path, boundary):
    direct = create_request_authority(boundary, workspace=str(tmp_path), history=history(tmp_path))
    following = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                         history=history(tmp_path, boundary))
    for grant in (direct, following):
        assert not allowed(grant, "read_file")
        assert not allowed(grant, "manage_notes")
        assert not allowed(grant, "bash", "pwd")


@pytest.mark.parametrize("topic", [
    "My saved notes are outdated", "The weather is unusually cold today",
    "Why do my calendar settings lack permissions?",
])
def test_another_product_subject_does_not_borrow_workspace_context(tmp_path, topic):
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                    history=history(tmp_path, topic))
    assert not allowed(grant, "read_file")


def test_known_workspace_change_prevents_context_inheritance(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    grant = create_request_authority(DIAGNOSTIC, workspace=str(second), history=history(first))
    assert not allowed(grant, "read_file")


def test_missing_workspace_does_not_inherit_read_access(tmp_path):
    grant = create_request_authority(DIAGNOSTIC, history=history(tmp_path))
    assert not allowed(grant, "read_file")


@pytest.mark.parametrize("rows", [
    [{"role": "assistant", "content": ORIGINAL, "metadata": {"tool_events": [{"tool": "read_file", "exit_code": 0}]}}],
    [{"role": "tool", "content": ORIGINAL}],
    [{"role": "user", "content": ORIGINAL, "metadata": {"trusted": False}}],
    [{"role": "user", "content": ORIGINAL, "metadata": {"tool_gate_untrusted": True}}],
])
def test_non_user_or_untrusted_history_cannot_supply_context(tmp_path, rows):
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path), history=rows)
    assert not allowed(grant, "read_file")


def test_current_policy_and_carried_guide_only_restrictions_win(tmp_path):
    disabled = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path), history=history(tmp_path),
                                        policy=ToolPolicy(disabled_tools={"read_file"}))
    assert not allowed(disabled, "read_file")
    assert allowed(disabled, "glob")
    guide = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                     history=history(tmp_path, "Analyze the canvas in guide-only mode; do not use any tools."))
    assert guide.block_all
    assert not allowed(guide, "read_file")
    assert not allowed(guide, "ask_user")


def test_clarification_history_limit_fails_closed(tmp_path):
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path),
                                    history=history(tmp_path, *[CLARIFICATION] * 8))
    assert not allowed(grant, "read_file")


def test_context_keeps_original_input_restrictions(tmp_path, monkeypatch):
    from src.agent_runtime import authority
    create = authority.create_request_authority
    pinned = OperationGrant("read_file", inputs=frozenset({'{"path":"one.txt"}'}))

    def exact_original(text, **kwargs):
        if text == ORIGINAL:
            return RequestAuthority("original", "", "", str(tmp_path),
                                    (pinned, OperationGrant("manage_notes"), OperationGrant("bash")))
        return create(text, **kwargs)

    monkeypatch.setattr(authority, "create_request_authority", exact_original)
    grant = create_request_authority(DIAGNOSTIC, workspace=str(tmp_path), history=history(tmp_path))
    assert next(g for g in grant.grants if g.tool == "read_file") is pinned
    assert allowed(grant, "read_file", '{"path":"one.txt"}')
    assert not allowed(grant, "read_file", '{"path":"two.txt"}')
    assert not allowed(grant, "glob")


@pytest.mark.asyncio
async def test_contextual_read_uses_real_dispatcher_without_write_or_escape_access(tmp_path, monkeypatch):
    from src import tool_execution
    from src.tool_types import ToolBlock
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"nodes": [{"id": "item-a", "type": "text", "text": "Synthetic entry"}], "edges": []}
    (workspace / "sample.canvas").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside workspace", encoding="utf-8")
    grant = create_request_authority(DIAGNOSTIC, owner="alice", session_id="context-test", workspace=str(workspace),
                                    history=history(workspace, CLARIFICATION))

    async def dispatch(tool, content):
        return (await tool_execution.execute_tool_block(
            ToolBlock(tool, content), owner="alice", session_id="context-test", workspace=str(workspace),
            request_authority=grant, security_context=tool_execution.NO_TOOL_SECURITY_CONTEXT))[1]

    read = await dispatch("read_file", '{"path":"sample.canvas"}')
    assert read["exit_code"] == 0
    assert json.loads(read["output"]) == payload
    write = await dispatch("write_file", '{"path":"new.txt","content":"unexpected"}')
    assert write["failure_kind"] == "request_authority_denied"
    assert not (workspace / "new.txt").exists()
    escape = await dispatch("read_file", '{"path":"../outside.txt"}')
    assert escape["exit_code"] != 0
