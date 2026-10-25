"""Bounded read-only workspace context from trusted user requests."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re

from src.path_confinement import canonical_root
from src.tool_policy import detect_guide_only_turn
from src.turn_contract import _REQUEST_PREFIX


WORKSPACE_READ_TOOLS = frozenset({"get_workspace", "ls", "glob", "grep", "read_file"})
_WORKSPACE_SUBJECT = re.compile(
    r"\b(?:workspace|canvas|diagram|vault|directory|folder|files?|filenames?|cards?|nodes?|"
    r"chapters?|entries|items|notes?|this|that|these|those|their|them)\b", re.I)
_WORKSPACE_REFERENCE = re.compile(r"/workspace/|\b(?:workspace|canvas|diagram|vault|directory|folder|files?)\b", re.I)
_READ_REQUEST = re.compile(
    r"^\s*" + _REQUEST_PREFIX +
    r"(?:read|read_file|analy[sz]e|anaylze|inspect|review|examine|explore|summari[sz]e)\b", re.I)
_INTERPRETATION = re.compile(
    r"\b(?:order|ordering|sort|arrange|coordinates?|positions?|height|vertical|horizontal|"
    r"boundaries|boundary|borders?|bounds|groups?|grouping|sections?|contained|inside|within|outside|"
    r"colou?rs?|outlines?|finali[sz]ed|drafts?|status|numbering|numbered|numeric|filenames?|"
    r"archived|focus|only|instead|rather|ignore|obsolete|outdated|interpretation|details?)\b|"
    r"\b[xy][ -]?(?:level|coordinate|position)\b", re.I)
_PERMISSION = re.compile(r"\b(?:permissions?|access|privileges?|administrator|admin|blocked|denied)\b", re.I)
_DIAGNOSTIC = re.compile(r"\?|\b(?:you\s+(?:lack|need)|permission\s+denied|access\s+denied)\b", re.I)
_NEW_MUTATION = re.compile(
    r"^\s*" + _REQUEST_PREFIX +
    r"(?:create|write|edit|delete|remove|save|send|reply|schedule|enable|disable|install|"
    r"run|execute)\b|\b(?:create|add)\s+(?:a\s+|new\s+)?(?:note|file|document)\b", re.I)
_PERSONAL_READ = re.compile(
    r"\b(?:list|show|read|open|search|find)\s+(?:(?:all|the)\s+)?"
    r"(?:(?:my|our|saved|personal)\s+)+(?:saved\s+)?"
    r"(?:notes?|emails?|inbox|calendar|events?|tasks?|contacts?|memories)\b", re.I)
_TOPIC_CHANGE = re.compile(r"^\s*(?:new\s+(?:topic|task|question)|unrelated\b)", re.I)
_PERSONAL_SUBJECT = re.compile(r"\b(?:my|our|saved|personal)\s+(?:saved\s+)?notes?\b", re.I)
_OTHER_PRODUCT = re.compile(r"\b(?:weather|emails?|inbox|calendar|appointments?|contacts?|endpoints?|integrations?)\b", re.I)
_SETTINGS = re.compile(r"\bsettings\b", re.I)
_ACKNOWLEDGMENT = re.compile(r"^\s*" + _REQUEST_PREFIX + r"(?:thanks?|thank\s+you)\b", re.I)
_CLAUSE_START = r"(?:^\s*|[;.!?,]\s*|\b(?:but|instead|however|and)\s+)"
_CANCEL = re.compile(
    _CLAUSE_START + _REQUEST_PREFIX +
    r"(?:stop|cancel|abort|pause|quit|never\s*mind|forget\s+(?:it|that|this))"
    r"(?:[.!?]*\s*$|\s+(?:(?:the|this|that|current|workspace)\s+)*"
    r"(?:task|analysis|work|review|inspection|reading|request|operation)\b)", re.I)
_READ_DENIAL = re.compile(
    _CLAUSE_START + _REQUEST_PREFIX +
    r"(?:do\s+not|don['’]?t|never|stop)\s+"
    r"(?:(?:read(?:ing)?|access(?:ing)?|inspect(?:ing)?|open(?:ing)?|list(?:ing)?|search(?:ing)?)\b|"
    r"us(?:e|ing)\s+(?:(?:any|the)\s+)*(?:tools?|file\s+tools?|filesystem|"
    r"read_file|get_workspace|glob|grep|ls)\b)", re.I)


@dataclass(frozen=True)
class WorkspaceReadContinuation:
    request_text: str | None = None
    history: tuple = ()
    restrictions: tuple[str, ...] = ()


def _get(row, key, default=None):
    return row.get(key, default) if isinstance(row, dict) else getattr(row, key, default)


def _workspace_matches(row, workspace):
    metadata = _get(row, "metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except ValueError:
            metadata = {}
    recorded = _get(row, "workspace")
    if recorded is None and isinstance(metadata, dict):
        recorded = metadata.get("workspace")
    if recorded is None:
        # Legacy user turns do not record a workspace. Reads still receive
        # fresh resource bindings to the currently selected workspace.
        return True
    if not isinstance(recorded, str) or not recorded.strip():
        return False
    try:
        return os.path.normcase(canonical_root(recorded)) == os.path.normcase(canonical_root(workspace))
    except (OSError, ValueError):
        return False


def _revokes_read_context(text):
    return bool(detect_guide_only_turn(text) or _CANCEL.search(text) or _READ_DENIAL.search(text)
                or _ACKNOWLEDGMENT.match(text))


def _new_operation(text):
    diagnostic = bool(_PERMISSION.search(text) and _DIAGNOSTIC.search(text))
    return bool(_NEW_MUTATION.search(text) or _PERSONAL_READ.search(text) or _TOPIC_CHANGE.search(text)
                or (_PERSONAL_SUBJECT.search(text) and not _WORKSPACE_REFERENCE.search(text))
                or _OTHER_PRODUCT.search(text) or (_SETTINGS.search(text) and not diagnostic))


def _read_request(text):
    return bool(_READ_REQUEST.match(text) and _WORKSPACE_REFERENCE.search(text))


def _contextual(text):
    return bool((_PERMISSION.search(text) and _DIAGNOSTIC.search(text))
                or (_WORKSPACE_SUBJECT.search(text) and _INTERPRETATION.search(text)))


def resolve_workspace_read_continuation(request_text, history, workspace, *, trusted_user_history, is_retry):
    """Resolve read ancestry; tool availability and model prose are irrelevant."""
    if _read_request(request_text) or _new_operation(request_text):
        return None
    retry = bool(is_retry(request_text))
    if not retry and not (_contextual(request_text) or _revokes_read_context(request_text)):
        return None
    if not workspace:
        return None if retry else WorkspaceReadContinuation(restrictions=(request_text,))
    rows = tuple(history or ())
    restrictions = [request_text]
    if _revokes_read_context(request_text):
        return WorkspaceReadContinuation(restrictions=tuple(restrictions))
    user_turns = 0
    skipped_current = False
    for index in range(len(rows) - 1, -1, -1):
        trusted = trusted_user_history((rows[index],))
        if not trusted:
            continue
        user_turns += 1
        if user_turns > 8:
            break
        content = trusted[0]["content"]
        if not skipped_current and user_turns == 1 and content == request_text:
            skipped_current = True
            continue
        if not isinstance(content, str) or not content.strip():
            break
        restrictions.append(content)
        if not _workspace_matches(rows[index], workspace) or _revokes_read_context(content):
            return WorkspaceReadContinuation(restrictions=tuple(restrictions))
        if _read_request(content):
            return WorkspaceReadContinuation(content, rows[:index], tuple(restrictions))
        if _new_operation(content) or not (is_retry(content) or _contextual(content)):
            # An ordinary non-workspace retry still uses normal request
            # admission, rather than borrowing an older workspace task.
            return None if retry else WorkspaceReadContinuation(restrictions=tuple(restrictions))
    return None if retry else WorkspaceReadContinuation(restrictions=tuple(restrictions))
