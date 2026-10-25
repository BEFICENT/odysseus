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
    selected_tools_for_request, requested_capabilities, targets_bound_editor_request,
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
    r"(?:write|create|edit|append|delete|remove|rename|move|copy|replace|update|modify|save|fix)\b", re.I)


def _owner(value):
    return str(value or "").strip().casefold()


def _authorized_parent(parent, owner):
    if parent is None:
        return False
    if not owner:
        from src.auth_helpers import _auth_disabled
        return _auth_disabled()
    return _owner(parent.owner) == owner


def _new_operation(text, *, active_document=False):
    # This is existing fresh-operation admission, not a continuation classifier.
    # Incidental product nouns alone cannot replace the saved read ceiling.
    intent = classify_tool_intent(text)
    explicit_file_mutation = bool(_FILE_MUTATION.match(text)
        and "shell_files" in requested_capabilities(text, (), workspace=True))
    return bool(explicit_file_mutation or (active_document and targets_bound_editor_request(text))
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
            revoked = bool(detect_guide_only_turn(request_text) or _CANCEL.search(request_text)
                           or _READ_DENIAL.search(request_text))
            continuing = bool(saved is not None and not revoked
                              and not _new_operation(request_text, active_document=context.get("active_document", False)))
            if continuing:
                snapshot = saved
                result = replace(saved, request_id=uuid4().hex, workspace=workspace,
                                 task_continuation=True).restrict(context.get("policy")).restrict(
                                     build_effective_tool_policy(last_user_message=request_text))
            elif revoked:
                snapshot = None
                result = replace(empty, grants=tuple(OperationGrant(name) for name in sorted(_CONTROLS))).restrict(
                    context.get("policy")).restrict(build_effective_tool_policy(last_user_message=request_text))
            else:
                standalone = create_request_authority(request_text, **{**context, "history": ()})
                fresh = create_request_authority(request_text, **context) if context.get("history") else standalone
                # Historical selectors can narrow current operation classes,
                # never introduce classes after a task is absent/revoked.
                fresh = replace(standalone.intersect(fresh), inherited=False)
                snapshot = _read_snapshot(fresh) if workspace else None
                result = fresh
            token = uuid4().hex
            values = {"owner": owner, "token": token, "run_id": None,
                      "authority_json": json.dumps(snapshot.to_dict()) if snapshot else None}
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
    changed = query.update({"authority_json": None, "token": uuid4().hex, "run_id": None})
    if not changed and expected_run_id is None:
        parent = db.get(DBSession, session_id)
        if parent is not None:
            db.add(SessionReadScope(session_id=session_id, owner=_owner(parent.owner), token=uuid4().hex))
    return changed == 1
