"""Synthetic regressions for server-owned conversation read permissions."""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import core.database as database
from src.agent_runtime.authority import ExactOperation, OperationGrant, RequestAuthority, create_request_authority, request_authority_for_http
from src.agent_runtime.conversation_scope import (
    WORKSPACE_READ_TOOLS, admit_conversation_scope, bind_scope_run, invalidate_scope, scope_is_current,
)
from src.tool_policy import ToolPolicy


ORIGIN = "Analyze the diagram in the workspace canvas file."
CLARIFICATION = "The numeric labels are obsolete; use the cards inside the groups and their vertical positions."


@pytest.fixture
def scope_db(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    database.Base.metadata.create_all(engine, tables=[database.Session.__table__, database.ChatMessage.__table__,
                                                      database.SessionReadScope.__table__])
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    with factory() as db:
        db.add(database.Session(id="conversation", name="Synthetic task", endpoint_url="https://example.invalid",
                                model="fixture", owner="alice"))
        db.commit()
    yield factory
    engine.dispose()


def admit(workspace, text=ORIGIN, **kwargs):
    return admit_conversation_scope(text, owner=kwargs.pop("owner", "alice"),
        session_id=kwargs.pop("session_id", "conversation"), workspace=str(workspace), **kwargs)


def permits(authority, tool, content="{}"):
    return authority.permits(ExactOperation.normalize(tool, content))


@pytest.mark.parametrize("text", [
    "Could you take another shot whenever you're ready?",
    "Those outlines aren't quite what I meant.",
    "A different angle might make this clearer.",
    "Once more, with feeling.",
    "Devam edelim, farklı bir açıdan bakabilir misin?",
    "もう一度、別の観点からお願いします。",
    "Reprenons avec une autre perspective.",
    "🤔",
    "The notes belong to the diagram, and the ordering depends on their geometry.",
    "Do you need administrator access or Bash permissions to continue?",
    "Do not use filename numbering; use the enclosing groups.",
    "Thanks, one more angle would help.",
])
def test_arbitrary_followups_reuse_server_scope_without_history_or_phrase_matching(scope_db, tmp_path, text):
    initial = admit(tmp_path)
    followup = admit(tmp_path, text, history=())
    assert followup.task_continuation
    assert followup.request_id != initial.request_id
    assert followup.task_scope_token != initial.task_scope_token
    assert scope_is_current(followup)
    assert {g.tool for g in followup.grants} == WORKSPACE_READ_TOOLS | {"ask_user", "update_plan"}
    for tool in WORKSPACE_READ_TOOLS:
        assert permits(followup, tool)
    for tool in ("bash", "python", "write_file", "edit_file", "manage_notes", "manage_settings"):
        assert not permits(followup, tool)


def test_long_chain_and_reloaded_store_do_not_need_original_transcript(scope_db, tmp_path):
    admit(tmp_path)
    for number in range(24):
        current = admit(tmp_path, f"Perspective {number}: does that change your interpretation?", history=())
        assert current.task_continuation and permits(current, "read_file")
    # Every admission opened a new DB connection. There is no process-local cache.
    with scope_db() as db:
        saved = db.get(database.SessionReadScope, "conversation")
        assert saved.authority_json and saved.token == current.task_scope_token
        assert "Perspective" not in saved.authority_json


def test_incidental_notes_classification_does_not_replace_read_task(scope_db, tmp_path):
    admit(tmp_path)
    message = "The notes have obsolete numbers. Order them by vertical position within the diagram groups."
    # This was the original routing ambiguity; durable permission is independent.
    followup = admit(tmp_path, message)
    assert followup.task_continuation
    assert permits(followup, "read_file")
    assert not permits(followup, "manage_notes")


@pytest.mark.parametrize("text", [
    "List my saved notes", "Create a note about the canvas", "List my calendar events",
])
def test_explicit_new_operations_replace_scope_without_inheriting_file_access(scope_db, tmp_path, text):
    previous = admit(tmp_path)
    current = admit(tmp_path, text)
    assert not current.task_continuation
    assert not permits(current, "read_file")
    assert not scope_is_current(previous)
    later = admit(tmp_path, "A different angle would help.")
    assert not permits(later, "read_file")


@pytest.mark.parametrize("text,document", [
    ("Edit sample.txt to fix the typo", False), ("Append a line to sample.txt", False),
    ("Create a summary.txt file", False), ("Delete the workspace file sample.txt", False),
    ("Write a summary to summary.txt", False), ("Make this paragraph shorter", True),
    ("Fix the grammar in this", True), ("Add a conclusion to this", True),
    ("Rewrite this in a more formal tone", True),
])
def test_explicit_writes_use_fresh_admission_without_becoming_persistent_mutations(scope_db, tmp_path, text, document):
    admit(tmp_path)
    current = admit(tmp_path, text, active_document=document)
    assert not current.task_continuation
    if document:
        assert any(g.tool in {"manage_documents", "edit_document", "update_document"} for g in current.grants)
    else:
        assert any(g.tool in {"write_file", "edit_file", "bash"} for g in current.grants)
    later = admit(tmp_path, "A different angle would help.")
    for tool in ("write_file", "edit_file", "bash", "manage_documents"):
        assert not permits(later, tool)


def test_normal_continuation_does_not_reinterpret_or_reseal_any_history(scope_db, tmp_path, monkeypatch):
    from src.agent_runtime import authority
    admit(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("An active read scope must not call fresh admission")

    monkeypatch.setattr(authority, "create_request_authority", forbidden)
    current = admit(tmp_path, "A different angle would help.", history=[{"role": "user", "content": "Unrelated imported prose"}])
    assert current.task_continuation and permits(current, "read_file")


@pytest.mark.parametrize("text", [
    "Cancel the workspace analysis", "Stop the review of the canvas", "Never mind the analysis",
    "Do not read any files", "Never access the actual file contents", "Do not use read_file",
    "Use the groups but do not read any files", "Follow those positions but stop the analysis",
    "Use the groups and do not read restricted-record.txt", "Use the groups; however stop the analysis",
    "Analyze the canvas in guide-only mode; do not use any tools.",
])
def test_revocations_are_durable_and_cannot_be_undone_by_a_retry(scope_db, tmp_path, text):
    old = admit(tmp_path)
    revoked = admit(tmp_path, text)
    assert not permits(revoked, "read_file")
    assert not scope_is_current(old)
    with scope_db() as db:
        assert db.get(database.SessionReadScope, "conversation").authority_json is None
    assert not permits(admit(tmp_path, "Could you take another shot?"), "read_file")


def test_current_policy_caps_but_does_not_widen_original_scope(scope_db, tmp_path):
    admit(tmp_path)
    current = admit(tmp_path, "A different angle would help.", policy=ToolPolicy(disabled_tools={"read_file"}))
    assert not permits(current, "read_file")
    assert permits(current, "glob")
    assert not permits(current, "write_file")


def test_initial_policy_limits_survive_future_reenabling(scope_db, tmp_path):
    admit(tmp_path, policy=ToolPolicy(disabled_tools={"read_file"}))
    current = admit(tmp_path, "A different angle would help.", policy=ToolPolicy())
    assert not permits(current, "read_file")
    assert permits(current, "glob")


@pytest.mark.parametrize("history_narrows_only", [False, True])
def test_saved_input_limits_and_resource_identity_are_preserved(scope_db, tmp_path, monkeypatch, history_narrows_only):
    from src.agent_runtime import authority
    create = authority.create_request_authority
    pinned = OperationGrant("read_file", inputs=frozenset({'{"path":"one.txt"}'}))

    def constrained(text, **context):
        base = create(text, **context)
        constrained = text == ORIGIN and (context.get("history") or not history_narrows_only)
        return replace(base, grants=(pinned,)) if constrained else base

    monkeypatch.setattr(authority, "create_request_authority", constrained)
    initial = admit(tmp_path, history=[{"role": "user", "content": "A synthetic selector context"}])
    current = admit(tmp_path, "A different angle would help.")
    assert current.resource_roots == initial.resource_roots
    assert current.grants == (pinned,)
    assert permits(current, "read_file", '{"path":"one.txt"}')
    assert not permits(current, "read_file", '{"path":"two.txt"}')
    assert not permits(current, "glob")


def test_workspace_change_clears_scope_and_return_does_not_resurrect_it(scope_db, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    old = admit(first)
    assert not permits(admit(second, "A different angle would help."), "read_file")
    assert not permits(admit(first, "A different angle would help."), "read_file")
    assert not scope_is_current(old)


def test_replaced_root_is_not_silently_resealed(scope_db, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    admit(workspace)
    workspace.rename(tmp_path / "previous")
    workspace.mkdir()
    assert not permits(admit(workspace, "A different angle would help."), "read_file")


def test_owner_and_session_boundaries_and_deleted_session_recreation(scope_db, tmp_path):
    old = admit(tmp_path)
    assert not permits(admit(tmp_path, "A different angle would help.", owner="bob"), "read_file")
    assert not permits(admit(tmp_path, "A different angle would help.", session_id="other"), "read_file")
    with scope_db() as db:
        db.query(database.SessionReadScope).delete()
        db.query(database.Session).delete()
        db.add(database.Session(id="conversation", name="Replacement", owner="alice", model="fixture", endpoint_url="https://example.invalid"))
        db.commit()
    replacement = admit(tmp_path)
    assert replacement.task_scope_token != old.task_scope_token
    assert not scope_is_current(old)
    assert scope_is_current(replacement)


def test_auth_disabled_single_user_can_continue_owner_stamped_session(scope_db, tmp_path, monkeypatch):
    import src.auth_helpers as auth
    monkeypatch.setattr(auth, "_auth_disabled", lambda: True)
    admit(tmp_path, owner=None)
    current = admit(tmp_path, "A different angle would help.", owner=None)
    assert current.task_continuation and current.owner == ""
    assert permits(current, "read_file") and scope_is_current(current)
    monkeypatch.setattr(auth, "_auth_disabled", lambda: False)
    assert not scope_is_current(current)
    assert not permits(admit(tmp_path, owner=None), "read_file")


def test_old_stop_or_run_binding_cannot_revoke_or_attach_to_a_new_turn(scope_db, tmp_path):
    old = admit(tmp_path)
    assert bind_scope_run(old, "run-a")
    current = admit(tmp_path, "A different angle would help.")
    assert bind_scope_run(current, "run-b")
    assert not bind_scope_run(old, "late-run-a")
    assert not invalidate_scope("conversation", expected_run_id="run-a")
    assert scope_is_current(current)
    assert invalidate_scope("conversation", expected_run_id="run-b")
    assert not scope_is_current(current)
    assert not bind_scope_run(current, "late-completion")


def test_concurrent_invalidation_wins_over_pending_continuation(scope_db, tmp_path, monkeypatch):
    from src.agent_runtime import conversation_scope as scopes
    admit(tmp_path)

    def invalidate_during_admission(*args, **kwargs):
        invalidate_scope("conversation")
        return False

    monkeypatch.setattr(scopes, "_new_operation", invalidate_during_admission)
    current = admit(tmp_path, "A different angle would help.")
    assert not permits(current, "read_file")
    with scope_db() as db:
        assert db.get(database.SessionReadScope, "conversation").authority_json is None


def test_first_admission_cannot_overwrite_a_concurrent_revocation(scope_db, tmp_path, monkeypatch):
    from src.agent_runtime import conversation_scope as scopes
    snapshot = scopes._read_snapshot

    def invalidate_before_insert(authority):
        invalidate_scope("conversation")
        return snapshot(authority)

    monkeypatch.setattr(scopes, "_read_snapshot", invalidate_before_insert)
    current = admit(tmp_path)
    assert not permits(current, "read_file")
    with scope_db() as db:
        assert db.get(database.SessionReadScope, "conversation").authority_json is None


def test_actual_session_deletion_cascades_scope_and_cannot_reuse_old_lease(scope_db, tmp_path):
    old = admit(tmp_path)
    with scope_db() as db:
        db.query(database.Session).filter(database.Session.id == "conversation").delete()
        db.commit()
        assert db.get(database.SessionReadScope, "conversation") is None
        db.add(database.Session(id="conversation", name="Replacement", owner="alice", model="fixture", endpoint_url="https://example.invalid"))
        db.commit()
    replacement = admit(tmp_path)
    assert replacement.task_scope_token != old.task_scope_token
    assert not scope_is_current(old)


def test_real_workspace_update_endpoint_invalidates_scope(scope_db, tmp_path, monkeypatch):
    from fastapi import APIRouter, FastAPI
    from fastapi.testclient import TestClient
    from core import session_manager as managers
    from routes import session_routes
    monkeypatch.setattr(managers, "SessionLocal", scope_db)
    monkeypatch.setattr(session_routes, "SessionLocal", scope_db)
    monkeypatch.setattr(session_routes, "router", APIRouter(prefix="/api"))
    manager = managers.SessionManager()
    old = admit(tmp_path)
    app = FastAPI()

    @app.middleware("http")
    async def authenticated(request, call_next):
        request.state.current_user = "alice"
        return await call_next(request)

    app.include_router(session_routes.setup_session_routes(manager, {}))
    response = TestClient(app).patch("/api/session/conversation", data={"cwd": str(tmp_path / "next")})
    assert response.status_code == 200
    assert not scope_is_current(old)
    assert not permits(admit(tmp_path, "A different angle would help."), "read_file")


@pytest.mark.asyncio
async def test_real_stop_endpoint_matches_run_identity_before_revoking(scope_db, tmp_path, monkeypatch):
    import asyncio
    from src import agent_runs
    from routes import chat_routes, session_routes
    monkeypatch.setattr(session_routes, "SessionLocal", scope_db)
    monkeypatch.setattr(agent_runs, "_RUNS", {})

    async def pending():
        await asyncio.Event().wait()
        yield ""

    generator_a, generator_b = pending(), pending()
    old = admit(tmp_path)
    run_a = agent_runs.start("conversation", generator_a)
    assert bind_scope_run(old, run_a.run_id)
    current = admit(tmp_path, "A different angle would help.")
    run_b = agent_runs.start("conversation", generator_b)
    assert bind_scope_run(current, run_b.run_id)
    placeholder = SimpleNamespace()
    router = chat_routes.setup_chat_routes(placeholder, placeholder, placeholder, placeholder, placeholder, placeholder)
    stop = next(route.endpoint for route in router.routes if route.path == "/api/chat/stop/{session_id}")
    request = SimpleNamespace(headers={"X-Odysseus-Run-Id": run_a.run_id}, state=SimpleNamespace(current_user="alice"))
    assert await stop(request, "conversation") == {"stopped": False}
    assert scope_is_current(current)
    request.headers["X-Odysseus-Run-Id"] = run_b.run_id
    assert await stop(request, "conversation") == {"stopped": True}
    assert not scope_is_current(current)
    await asyncio.gather(run_a.task, run_b.task, return_exceptions=True)
    await generator_a.aclose()
    await generator_b.aclose()


def test_raw_history_and_model_proposals_cannot_establish_persistent_authority(scope_db, tmp_path):
    history = [{"role": role, "content": ORIGIN,
                "metadata": {"trusted": True, "request_authority": {"grants": ["read_file"]}}}
               for role in ("user", "assistant", "tool")]
    current = admit(tmp_path, "A different angle would help.", history=history)
    assert not current.task_scope_token
    assert not permits(current, "read_file")


@pytest.mark.parametrize("message", ["Read it", "Show it again", "A different angle would help."])
def test_revoked_or_imported_history_cannot_mint_unleased_operation_classes(scope_db, tmp_path, message):
    admit(tmp_path)
    invalidate_scope("conversation")
    current = admit(tmp_path, message, history=[{"role": "user", "content": ORIGIN}])
    assert not current.task_scope_token
    for tool in ("read_file", "bash", "python", "write_file", "manage_notes"):
        assert not permits(current, tool)


@pytest.mark.parametrize("message", ["Read it", "Show it again", "Open the first one", "Read it again"])
def test_old_other_product_evidence_cannot_switch_an_active_workspace_task(scope_db, tmp_path, message):
    admit(tmp_path)
    old_notes = [{"role": "user", "content": "List my notes"},
                 {"role": "assistant", "content": "A note was listed.", "metadata": {"tool_events": [
                     {"tool": "manage_notes", "exit_code": 0, "command": '{"action":"list"}',
                      "output": json.dumps({"notes": [{"id": "old-note", "title": "Synthetic entry"}]})}]}}]
    current = admit(tmp_path, message, history=old_notes)
    assert current.task_continuation
    assert permits(current, "read_file")
    assert not permits(current, "manage_notes")


def test_loopback_cannot_load_or_change_saved_scope(scope_db, tmp_path):
    from core.middleware import INTERNAL_TOOL_HEADER, INTERNAL_TOOL_TOKEN
    existing = admit(tmp_path)
    request = SimpleNamespace(headers={INTERNAL_TOOL_HEADER: INTERNAL_TOOL_TOKEN}, state=SimpleNamespace(current_user="internal-tool"))
    blocked = request_authority_for_http(request, ORIGIN, persist_workspace_scope=True,
        owner="alice", session_id="conversation", workspace=str(tmp_path))
    assert not permits(blocked, "read_file")
    assert scope_is_current(existing)


def test_stateless_and_incognito_admission_does_not_create_durable_scope(scope_db, tmp_path):
    request = SimpleNamespace(headers={}, state=SimpleNamespace(current_user="alice"))
    authority = request_authority_for_http(request, ORIGIN, persist_workspace_scope=False,
        owner="alice", session_id="conversation", workspace=str(tmp_path))
    assert not authority.task_scope_token
    with scope_db() as db:
        assert db.get(database.SessionReadScope, "conversation") is None


def test_snapshot_contains_only_read_resources_and_not_transcript_data(scope_db, tmp_path):
    admit(tmp_path)
    with scope_db() as db:
        value = json.loads(db.get(database.SessionReadScope, "conversation").authority_json)
    assert all(g["tool"] in WORKSPACE_READ_TOOLS | {"ask_user", "update_plan"} for g in value["grants"])
    assert value["task_scope_token"] == ""
    for key in ("backend_resources", "owned_scopes", "launch_scopes", "process_resources", "job_resources", "browser_sessions", "browser_pages"):
        assert value[key] == []
    assert ORIGIN not in json.dumps(value)


def test_lease_store_failure_denies_old_scope(scope_db, tmp_path, monkeypatch):
    from sqlalchemy.exc import OperationalError
    authority = admit(tmp_path)

    def unavailable():
        raise OperationalError("unavailable", {}, None)

    monkeypatch.setattr(database, "SessionLocal", unavailable)
    assert not scope_is_current(authority)
    assert not permits(admit(tmp_path, "A different angle would help."), "read_file")


@pytest.mark.parametrize("operation", ["truncate", "replace", "compact"])
def test_history_rewrites_invalidate_but_trusted_compaction_preserves(scope_db, tmp_path, monkeypatch, operation):
    from core import session_manager as managers
    from core.models import ChatMessage
    monkeypatch.setattr(managers, "SessionLocal", scope_db)
    manager = managers.SessionManager()
    manager.add_message("conversation", ChatMessage("user", "Synthetic prior request"))
    old = admit(tmp_path)
    if operation == "truncate":
        assert manager.truncate_messages("conversation", 0)
    else:
        assert manager.replace_messages("conversation", [ChatMessage("system", "Synthetic summary")],
                                        preserve_task_scope=operation == "compact")
    assert scope_is_current(old) is (operation == "compact")
    current = admit(tmp_path, "A different angle would help.")
    assert permits(current, "read_file") is (operation == "compact")


@pytest.mark.parametrize("operation", ["edit", "delete", "inject"])
def test_client_history_endpoints_cannot_preserve_or_mint_scope(scope_db, tmp_path, monkeypatch, operation):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from core import session_manager as managers
    from core.models import ChatMessage
    from routes.history import history_routes
    monkeypatch.setattr(managers, "SessionLocal", scope_db)
    monkeypatch.setattr(history_routes, "SessionLocal", scope_db)
    monkeypatch.setattr(history_routes, "_verify_session_owner", lambda *args: None)
    manager = managers.SessionManager()
    manager.add_message("conversation", ChatMessage("user", "Synthetic prior request"))
    message_id = manager.get_session("conversation").history[-1].metadata["_db_id"]
    old = admit(tmp_path)
    app = FastAPI()
    app.include_router(history_routes.setup_history_routes(manager))
    if operation == "edit":
        path, body = "edit-message", {"msg_id": message_id, "content": "Changed synthetic request"}
    elif operation == "delete":
        path, body = "delete-messages", {"msg_ids": [message_id]}
    else:
        path, body = "message", {"role": "user", "content": ORIGIN,
                                 "metadata": {"trusted": True, "task_scope_token": old.task_scope_token}}
    response = TestClient(app).post(f"/api/session/conversation/{path}", json=body)
    assert response.status_code == 200
    assert not scope_is_current(old)
    assert not permits(admit(tmp_path, "A different angle would help."), "read_file")


def test_new_session_does_not_inherit_source_transcript_permissions(scope_db, tmp_path):
    admit(tmp_path)
    with scope_db() as db:
        db.add(database.Session(id="fork", name="Synthetic fork", owner="alice", model="fixture", endpoint_url="https://example.invalid"))
        db.commit()
    current = admit(tmp_path, "A different angle would help.", session_id="fork",
                    history=[{"role": "user", "content": ORIGIN}])
    assert not permits(current, "read_file")


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", ["alice", None])
@pytest.mark.parametrize("runtime", ["normal", "preview", "experiment", "full", "native", "tui"])
@pytest.mark.parametrize("message", [
    "The notes belong to the diagram, and the ordering depends on their geometry.",
    "Let us revisit your observations.",
    "After a fresh file read, what node count and verification code do you observe?",
])
async def test_chat_route_uses_saved_scope_for_arbitrary_prose_and_read_only_contract(scope_db, tmp_path, monkeypatch, actor, message, runtime):
    import routes.chat_routes as routes
    import src.tool_security as security
    from tests.test_foreground_model_routing import _RouteRequest, _chat_stream_endpoint
    import src.auth_helpers as auth
    monkeypatch.setattr(auth, "_auth_disabled", lambda: True)
    with scope_db() as db:
        db.add(database.Session(id="session-1", name="Synthetic chat", owner="alice", model="fixture", endpoint_url="https://example.invalid"))
        db.commit()
    admit(tmp_path, owner=actor, session_id="session-1")
    captured = {}
    endpoint = _chat_stream_endpoint(monkeypatch, "agent", captured)
    monkeypatch.setattr(routes, "uses_compact_preview_runtime", lambda *args, **kwargs: runtime in {"preview", "experiment"})
    monkeypatch.setattr(routes, "_configured_model_tool_surface", lambda *args, **kwargs: "full" if runtime == "full" else "")
    if runtime == "experiment":
        import src.tool_routing_experiment as experiment
        monkeypatch.setattr(experiment, "experiment_mode", lambda *args, **kwargs: "all")
    monkeypatch.setattr(routes, "effective_user", lambda request: actor)
    monkeypatch.setattr(security, "owner_is_admin_or_single_user", lambda *args, **kwargs: True)
    monkeypatch.setattr(routes, "coerce_message_and_session", lambda *args, **kwargs: (message, "session-1"))

    async def model(*args, **kwargs):
        captured["authority"] = kwargs["request_authority"]
        captured["contract"] = kwargs["turn_contract"]
        yield 'data: {"delta":"Synthetic answer"}\n\n'
        yield 'data: [DONE]\n\n'

    monkeypatch.setattr(routes, "stream_agent_loop", model)
    request = _RouteRequest("agent")
    request._form.update(message=message, workspace=str(tmp_path), compare_mode="false", allow_bash="true")
    if runtime in {"native", "tui"}:
        request._form["client_runtime_context"] = json.dumps({
            "surface": "odysseus-native" if runtime == "native" else "odysseus-tui",
            "terminal_agent": True, "unattended_mode": True,
        })
    response = await endpoint(request)
    async for _ in response.body_iterator:
        pass
    assert captured["authority"].task_continuation
    assert permits(captured["authority"], "read_file")
    assert captured["contract"].offered <= WORKSPACE_READ_TOOLS | {"ask_user", "update_plan"}
    assert "read_file" in captured["contract"].offered
    from src.agent_loop import _contract_allows_early_completion
    assert not _contract_allows_early_completion(captured["contract"])
    assert not permits(captured["authority"], "manage_notes")


@pytest.mark.asyncio
async def test_real_dispatcher_read_write_escape_and_revoked_lease(scope_db, tmp_path, monkeypatch):
    from src import tool_execution
    from src.tool_types import ToolBlock
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "example.canvas").write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    admit(workspace)
    current = admit(workspace, "A different angle would help.")

    async def dispatch(tool, args):
        return (await tool_execution.execute_tool_block(ToolBlock(tool, json.dumps(args)), owner="alice",
            session_id="conversation", workspace=str(workspace), request_authority=current,
            security_context=tool_execution.NO_TOOL_SECURITY_CONTEXT))[1]

    assert (await dispatch("read_file", {"path": "example.canvas"}))["exit_code"] == 0
    assert (await dispatch("write_file", {"path": "new.txt", "content": "unexpected"}))["failure_kind"] == "request_authority_denied"
    assert (await dispatch("read_file", {"path": "../outside.txt"}))["exit_code"] != 0
    invalidate_scope("conversation")
    assert (await dispatch("read_file", {"path": "example.canvas"}))["failure_kind"] == "request_authority_denied"
    from src.agent_runtime.authority import bind_request_authority
    unleased_parent = create_request_authority(ORIGIN, owner="alice", session_id="conversation", workspace=str(workspace))
    with bind_request_authority(unleased_parent):
        # Intersecting with an unleased parent must not strip the child's lease.
        assert (await dispatch("read_file", {"path": "example.canvas"}))["failure_kind"] == "request_authority_denied"
    assert not (workspace / "new.txt").exists()
