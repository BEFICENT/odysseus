"""Durable, server-owned workspace read scopes, independent of follow-up wording.

The transcript is never a permission store. Only authenticated chat admission
can establish a scope. Each change rotates its lease; execution checks it fresh.
"""
from dataclasses import replace
import json
import os
import re
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError

from src.action_intents import classify_tool_intent
from src.path_confinement import canonical_root
from src.tool_policy import build_effective_tool_policy, detect_guide_only_turn
from src.turn_contract import (
    _REQUEST_PREFIX, _has_action_signal, required_read_operation_for_request,
    requested_capabilities, selected_tools_for_request, targets_bound_editor_request,
)


WORKSPACE_READ_TOOLS = frozenset({"get_workspace", "ls", "glob", "grep", "read_file"})
_CONTROLS = frozenset({"ask_user", "update_plan"})
_CLAUSE_START = r"(?:^\s*|[;.!?,]\s*|\b(?:but|instead|however|and)\s+)"
_CANCEL = re.compile(
    _CLAUSE_START + _REQUEST_PREFIX +
    r"(?:stop|cancel|abort|pause|quit|never\s*mind|forget\s+(?:it|that|this))"
    r"(?:[.!?]*\s*$|\s+(?:(?:the|this|that|current|workspace)\s+)*"
    r"(?:task|analysis|work|review|inspection|reading|request|operation)\b)", re.I)
_READ_DENIAL = re.compile(
    _CLAUSE_START + _REQUEST_PREFIX + r"(?:do\s+not|don['’]?t|never|stop)\s+"
    r"(?:(?:read(?:ing)?|access(?:ing)?|inspect(?:ing)?|open(?:ing)?|list(?:ing)?|search(?:ing)?)\b|"
    r"us(?:e|ing)\s+(?:(?:any|the)\s+)*(?:tools?|file\s+tools?|filesystem|"
    r"read_file|get_workspace|glob|grep|ls)\b)", re.I)
_FILE_MUTATION = re.compile(
    r"^\s*" + _REQUEST_PREFIX +
    r"(?:write|create|edit|append|delete|remove|rename|move|copy|replace|update|modify|save|fix|"
    r"add|insert|change|rewrite|refactor|implement|patch|apply|revert|undo)\b", re.I)
# Existing router reasons for workspace changes or commands. Reads and bare
# workspace nouns are excluded; they continue the saved read scope.
_WORKSPACE_ACTION_REASONS = frozenset({
    "repo implementation request", "assistant repo implementation request",
    "direct code creation request", "direct code file request", "direct repository coding request",
    "test/build command request", "server/process debugging request",
})
# A bare approval of the previous turn. It adds no operation of its own.
_CONFIRMATION = re.compile(
    r"^\s*(?:(?:yes|yep|yeah|yup|sure|ok(?:ay)?|alright|great|perfect|cool|sounds\s+good|looks\s+good|lgtm|"
    r"confirm(?:ed)?|approved?|agreed|correct|exactly|please)\b[\s,.!—–-]*)*"
    r"(?:(?:go\s+ahead|do\s+it|do\s+that|proceed|please\s+do|continue|carry\s+on|make\s+it\s+so|ship\s+it)\b"
    r"(?:\s+(?:please|now|then|thanks|thank\s+you))?[\s,.!]*)?$", re.I)
# The web client's Continue and step-limit prompts resume the previous turn.
_RESUME = re.compile(
    r"^\s*(?:continue\s+from\s+(?:exactly\s+)?where\s+you\s+left\s+off|"
    r"you\s+hit\s+the\s+step\s+limit\s+before\s+finishing)\b", re.I)


def _owner(value):
    return str(value or "").strip().casefold()


def _authorized_parent(parent, owner):
    if parent is None:
        return False
    if not owner:
        from src.auth_helpers import _auth_disabled
        return _auth_disabled()
    return _owner(parent.owner) == owner


def _workspace_change_request(text):
    """An explicit change or command for the active workspace task."""
    if requested_capabilities(text, (), workspace=True) - {"shell_files", "unknown"}:
        return False  # Another product, e.g. "Create a note", gets its own admission.
    intent = classify_tool_intent(text)
    return bool(_FILE_MUTATION.match(text) or (
        intent.needs_tools and intent.category == "workspace" and intent.reason in _WORKSPACE_ACTION_REASONS))


def _new_operation(text, *, active_document=False):
    # This is existing fresh-operation admission, not a continuation classifier.
    # Incidental product nouns alone cannot replace the saved read ceiling.
    intent = classify_tool_intent(text)
    return bool(_workspace_change_request(text) or (active_document and targets_bound_editor_request(text))
                or required_read_operation_for_request(text)
                or (intent.needs_tools and intent.category != "workspace")
                or (_has_action_signal(text) and selected_tools_for_request(text) is not None))


def _read_snapshot(authority):
    grants = tuple(g for g in authority.grants if g.tool in WORKSPACE_READ_TOOLS | _CONTROLS)
    if not any(g.tool in WORKSPACE_READ_TOOLS for g in grants) or not authority.resource_roots:
        return None
    for root in authority.resource_roots:
        root.validate()
    return replace(authority, grants=grants, backend_resources=(), owned_scopes=(),
                   launch_scopes=(), process_resources=(), job_resources=(), browser_sessions=(),
                   browser_pages=(), task_scope_token="", task_continuation=False)


def _restore(row, owner, session_id, workspace):
    from src.agent_runtime.authority import RequestAuthority
    if not row or not row.authority_json or row.owner != owner or not workspace:
        return None
    authority = RequestAuthority.from_dict(json.loads(row.authority_json))
    if (authority.owner != owner or authority.session_id != session_id
            or authority.task_scope_token or authority.task_continuation
            or any(g.tool not in WORKSPACE_READ_TOOLS | _CONTROLS for g in authority.grants)
            or not authority.resource_roots
            or os.path.normcase(canonical_root(authority.workspace)) != os.path.normcase(canonical_root(workspace))):
        return None
    for root in authority.resource_roots:
        root.validate()
    return authority


def _same_workspace(left, right):
    if not left or not right:
        return not left and not right
    return os.path.normcase(canonical_root(left)) == os.path.normcase(canonical_root(right))


def _carries_more_than_reads(authority):
    return any(g.tool not in WORKSPACE_READ_TOOLS | _CONTROLS for g in authority.grants)


def _restore_carry(row, owner, session_id, workspace):
    """The previous turn's fresh admission, usable by one confirmation only."""
    from src.agent_runtime.authority import RequestAuthority
    if not row or not row.carry_json or row.owner != owner:
        return None
    authority = RequestAuthority.from_dict(json.loads(row.carry_json))
    if (authority.owner != owner or authority.session_id != session_id
            or authority.task_scope_token or authority.task_continuation
            or not _same_workspace(authority.workspace, workspace)):
        return None
    for root in authority.resource_roots:
        root.validate()
    return authority


def admit_conversation_scope(request_text, **context):
    """Admit once, then retain the immutable read subset until invalidated."""
    from core.database import SessionLocal, Session as DBSession, SessionReadScope
    from src.agent_runtime.authority import OperationGrant, RequestAuthority, create_request_authority
    owner = _owner(context.get("owner"))
    session_id = str(context.get("session_id") or "")
    workspace = str(context.get("workspace") or "")
    empty = RequestAuthority.empty(owner=owner, session_id=session_id, workspace=workspace)
    if not session_id:
        return empty
    try:
        with SessionLocal() as db:
            parent = db.query(DBSession).filter(DBSession.id == session_id).first()
            if not _authorized_parent(parent, owner):
                return empty
            row = db.query(SessionReadScope).filter(SessionReadScope.session_id == session_id).first()
            previous_token = row.token if row else None
            try:
                saved = _restore(row, owner, session_id, workspace)
            except (ValueError, TypeError, KeyError, OSError, RuntimeError):
                saved = None
            try:
                carried = _restore_carry(row, owner, session_id, workspace)
            except (ValueError, TypeError, KeyError, OSError, RuntimeError):
                carried = None
            active_document = context.get("active_document", False)
            current_policy = build_effective_tool_policy(last_user_message=request_text)
            revoked = bool(detect_guide_only_turn(request_text) or _CANCEL.search(request_text)
                           or _READ_DENIAL.search(request_text))
            confirming = bool(carried is not None and not revoked and request_text.strip()
                              and (_CONFIRMATION.match(request_text) or _RESUME.match(request_text)))
            continuing = bool(not confirming and saved is not None and not revoked
                              and not _new_operation(request_text, active_document=active_document))
            carry = None
            if confirming:
                # "Yes, do it" approves what the server admitted last turn, for
                # this turn only. Nothing is re-derived from the transcript.
                snapshot = saved
                result = replace(carried, request_id=uuid4().hex, workspace=workspace, inherited=False).restrict(
                    context.get("policy")).restrict(current_policy)
            elif continuing:
                snapshot = saved
                result = replace(saved, request_id=uuid4().hex, workspace=workspace,
                                 task_continuation=True).restrict(context.get("policy")).restrict(current_policy)
            elif revoked:
                snapshot = None
                result = replace(empty, grants=tuple(OperationGrant(name) for name in sorted(_CONTROLS))).restrict(
                    context.get("policy")).restrict(current_policy)
            else:
                fresh_context = dict(context)
                if (saved is not None and _workspace_change_request(request_text)
                        and not (active_document and targets_bound_editor_request(request_text))):
                    # The saved scope is server proof of an active workspace
                    # task. It replaces the transcript as context for a
                    # follow-up change such as "Fix the off-by-one".
                    fresh_context["capabilities"] = frozenset(context.get("capabilities") or ()) | {"shell_files"}
                standalone = create_request_authority(request_text, **{**fresh_context, "history": ()})
                fresh = create_request_authority(request_text, **fresh_context) if context.get("history") else standalone
                # Historical selectors can narrow current operation classes,
                # never introduce classes after a task is absent/revoked.
                fresh = replace(standalone.intersect(fresh), inherited=False)
                snapshot = _read_snapshot(fresh) if workspace else None
                result = fresh
                if _carries_more_than_reads(fresh):
                    carry = fresh
            token = uuid4().hex
            values = {"owner": owner, "token": token, "run_id": None,
                      "authority_json": json.dumps(snapshot.to_dict()) if snapshot else None,
                      "carry_json": json.dumps(carry.to_dict()) if carry else None}
            if row is None:
                db.add(SessionReadScope(session_id=session_id, **values))
            elif db.query(SessionReadScope).filter(SessionReadScope.session_id == session_id,
                                                   SessionReadScope.token == previous_token).update(values) != 1:
                return empty
            db.commit()
            return replace(result, task_scope_token=token) if snapshot else result
    except (SQLAlchemyError, ValueError, TypeError, KeyError, OSError, RuntimeError):
        # Failure to store/validate authority must never fall back to old prose.
        return empty


def scope_is_current(authority):
    """Execution-time lease check, never cached across tool calls."""
    if not authority.task_scope_token:
        return True
    from core.database import SessionLocal, SessionReadScope, Session as DBSession
    try:
        with SessionLocal() as db:
            row = db.query(SessionReadScope).join(DBSession, DBSession.id == SessionReadScope.session_id).filter(
                SessionReadScope.session_id == authority.session_id,
                SessionReadScope.owner == authority.owner,
                SessionReadScope.token == authority.task_scope_token,
                SessionReadScope.authority_json.isnot(None)).first()
            return bool(row and _authorized_parent(db.get(DBSession, authority.session_id), authority.owner))
    except SQLAlchemyError:
        return False


def bind_scope_run(authority, run_id):
    if not authority.task_scope_token:
        return True
    from core.database import SessionLocal, SessionReadScope
    try:
        with SessionLocal() as db:
            changed = db.query(SessionReadScope).filter(SessionReadScope.session_id == authority.session_id,
                SessionReadScope.owner == authority.owner, SessionReadScope.token == authority.task_scope_token,
                SessionReadScope.authority_json.isnot(None)).update({"run_id": run_id})
            db.commit()
            return changed == 1
    except SQLAlchemyError:
        return False


def invalidate_scope(session_id, *, db=None, expected_run_id=None):
    """Clear in the caller's transaction; an old run cannot revoke a new lease."""
    from core.database import SessionLocal, SessionReadScope, Session as DBSession
    if db is None:
        with SessionLocal() as transaction:
            changed = invalidate_scope(session_id, db=transaction, expected_run_id=expected_run_id)
            transaction.commit()
            return changed
    query = db.query(SessionReadScope).filter(SessionReadScope.session_id == session_id)
    if expected_run_id is not None:
        query = query.filter(SessionReadScope.run_id == expected_run_id)
    changed = query.update({"authority_json": None, "carry_json": None, "token": uuid4().hex, "run_id": None})
    if expected_run_id is not None:
        # Turns without a read scope carry no run lease. Dropping a carried
        # grant only removes permission, so any Stop may clear it.
        db.query(SessionReadScope).filter(SessionReadScope.session_id == session_id).update({"carry_json": None})
    if not changed and expected_run_id is None:
        parent = db.get(DBSession, session_id)
        if parent is not None:
            db.add(SessionReadScope(session_id=session_id, owner=_owner(parent.owner), token=uuid4().hex))
    return changed == 1
