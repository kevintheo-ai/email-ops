"""Optional: hand a saved reply draft to Draft Desk, an outbox app for the Mac where a person reviews and sends it.

Set draftdesk_account = "<account name in Draft Desk>" for a mailbox in config/email-ops.toml. mail.py draft then
saves the draft in the Drafts folder as always and also runs `draftdesk add`. Draft Desk's command line cannot send;
only its app does, after a click. `mailbox_draft` names the draft in the Drafts folder, so Draft Desk can remove it
after sending. Draft Desk: https://github.com/kevintheo-ai/draft-desk
"""

from __future__ import annotations

import json
import shutil
import subprocess
from email.message import EmailMessage
from pathlib import Path

THREAD_CHARS = 200_000  # Draft Desk keeps at most this much of the earlier text
TIMEOUT_S = 60


def find_program() -> str | None:
    """Draft Desk's command line: on PATH, else where its installer puts it (~/.local/bin)."""
    return shutil.which("draftdesk") or shutil.which("draftdesk", path=str(Path.home() / ".local/bin"))


def as_draft(mailbox_draft: EmailMessage, body: str, thread: str, account: str) -> dict:
    """The mailbox draft in Draft Desk's format (draftdesk/1): same sender, recipients, subject, text and threading."""
    sender = mailbox_draft["From"].addresses[0]
    mid = mailbox_draft["Message-ID"]
    out: dict = {"schema": "draftdesk/1", "account": account, "from": {"address": sender.addr_spec}}
    if sender.display_name:
        out["from"]["name"] = sender.display_name
    out["to"] = [str(a) for a in mailbox_draft["To"].addresses]
    if mailbox_draft["Cc"]:
        out["cc"] = [str(a) for a in mailbox_draft["Cc"].addresses]
    out["subject"] = str(mailbox_draft["Subject"])
    out["body"] = body
    if mailbox_draft["In-Reply-To"]:
        refs = str(mailbox_draft["References"] or "").split()
        out["reply"] = {"in_reply_to": str(mailbox_draft["In-Reply-To"]), "references": refs}
    out["thread"] = thread[:THREAD_CHARS]
    out["mailbox_draft"] = {"message_id": mid}
    out["origin"] = {"agent": "email-ops", "correlation": mid}  # adding the same draft twice gives the same item
    return out


def hand_to_draftdesk(program: str, data: dict) -> str:
    """`draftdesk add` with the draft on stdin; the item id it returns. Every failure is a RuntimeError."""
    try:
        # A fixed program (find_program), fixed arguments, the draft only on stdin.
        proc = subprocess.run(  # noqa: S603
            [program, "add", "/dev/stdin"],
            input=json.dumps(data, ensure_ascii=False),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"draftdesk add gave no answer within {TIMEOUT_S} s") from None
    except OSError as exc:
        raise RuntimeError(f"draftdesk add could not be started: {exc.strerror}") from None
    if proc.returncode != 0:
        raise RuntimeError(f"draftdesk add ended with exit {proc.returncode}: {proc.stderr.strip()[-500:]}")
    try:
        item = json.loads(proc.stdout).get("item_id")
    except (ValueError, AttributeError):
        item = None
    if not isinstance(item, str) or not item:
        raise RuntimeError("draftdesk add gave no item id")
    return item
