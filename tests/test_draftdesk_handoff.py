import email
import json
from email.message import EmailMessage
from pathlib import Path

import pytest

import draftdesk_handoff as desk
import mail

ACCT = {"account": "work", "user": "me@example.com", "display_name": "Me Myself"}


def _fake_draftdesk(folder: Path, code: int = 0, stdout: str = "", stderr: str = "") -> Path:
    """A `draftdesk` that keeps its arguments and the JSON it was given, and answers like the real one."""
    exe = folder / "draftdesk"
    exe.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{folder}/argv.txt"\n'
        f'cat > "{folder}/draft.json"\n'
        f"printf %s '{stdout}'\n"
        f"printf %s '{stderr}' >&2\n"
        f"exit {code}\n"
    )
    exe.chmod(0o700)
    return exe


def _original() -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "Jane Doe <jane@example.com>"
    msg["Reply-To"] = "billing@example.net"
    msg["To"] = "me@example.com, Dave <dave@example.org>"
    msg["Cc"] = "carol@example.org"
    msg["Subject"] = "Offer"
    msg["Date"] = "Thu, 05 Nov 2026 10:00:00 +0000"
    msg["Message-ID"] = "<m1@example.com>"
    msg.set_content("Can you send a price?")
    return email.message_from_bytes(msg.as_bytes())


def test_the_draftdesk_draft_is_the_mailbox_draft():
    orig = _original()
    draft = mail.compose_reply(orig, "Thanks, we will check.\n", ACCT)
    mid = draft["Message-ID"]
    assert desk.as_draft(draft, "Thanks, we will check.\n", "earlier", "desk") == {
        "schema": "draftdesk/1",
        "account": "desk",
        "from": {"address": "me@example.com", "name": "Me Myself"},
        "to": ["billing@example.net"],
        "cc": ["Dave <dave@example.org>", "carol@example.org"],
        "subject": "Re: Offer",
        "body": "Thanks, we will check.\n",
        "reply": {"in_reply_to": "<m1@example.com>", "references": ["<m1@example.com>"]},
        "thread": "earlier",
        "mailbox_draft": {"message_id": mid},
        "origin": {"agent": "email-ops", "correlation": mid},
    }


def test_without_name_cc_or_parent_those_fields_stay_out():
    orig = email.message_from_string("From: jane@example.com\r\nSubject: x\r\n\r\nbody")
    acct = {**ACCT, "display_name": ""}
    dd = desk.as_draft(mail.compose_reply(orig, "ok", acct), "ok", "x" * (desk.THREAD_CHARS + 5), "desk")
    assert dd["from"] == {"address": "me@example.com"}
    assert "cc" not in dd and "reply" not in dd
    assert len(dd["thread"]) == desk.THREAD_CHARS


def test_the_thread_is_the_original_mail_as_text():
    assert mail.thread_text(_original()) == (
        "From:     Jane Doe <jane@example.com>\n"
        "To:       me@example.com, Dave <dave@example.org>\n"
        "Cc:       carol@example.org\n"
        "Date:     Thu, 05 Nov 2026 10:00:00 +0000\n"
        "Subject:  Offer\n\n"
        "Can you send a price?"
    )


def test_hand_to_draftdesk_passes_the_draft_and_returns_the_item(tmp_path, monkeypatch):
    exe = _fake_draftdesk(tmp_path, stdout='{"item_id":"20261111-120000-0a1b2c3d","replaced":null}')
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    assert desk.find_program() == str(exe)
    assert desk.hand_to_draftdesk(str(exe), {"schema": "draftdesk/1", "body": "Grüße"}) == "20261111-120000-0a1b2c3d"
    assert (tmp_path / "argv.txt").read_text().split() == ["add", "/dev/stdin"]
    sent = json.loads((tmp_path / "draft.json").read_text(encoding="utf-8"))
    assert sent == {"schema": "draftdesk/1", "body": "Grüße"}


def test_a_refused_handover_is_an_error_with_the_reason(tmp_path):
    exe = _fake_draftdesk(tmp_path, code=2, stderr="from.address: not a sender of account desk")
    with pytest.raises(RuntimeError, match=r"exit 2: from\.address: not a sender"):
        desk.hand_to_draftdesk(str(exe), {})
    for answer in ("garbage", '{"item_id":null}', '{"item_id":""}', "[1]"):
        with pytest.raises(RuntimeError, match="no item id"):
            desk.hand_to_draftdesk(str(_fake_draftdesk(tmp_path, stdout=answer)), {})
    with pytest.raises(RuntimeError, match="could not be started"):
        desk.hand_to_draftdesk(str(tmp_path / "missing"), {})


def test_draftdesk_is_found_in_its_install_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert desk.find_program() is None
    (tmp_path / ".local/bin").mkdir(parents=True)
    exe = _fake_draftdesk(tmp_path / ".local/bin")
    assert desk.find_program() == str(exe)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('"desk"', "was not found"),
        ('""', "must be the name"),
        ("1", "must be the name"),
        ('" desk"', "must be the name"),
    ],
)
def test_draft_refuses_before_saving_when_draftdesk_is_missing_or_misset(
    offline, tmp_path, monkeypatch, capsys, value, reason
):
    offline.write_text(
        offline.read_text(encoding="utf-8")
        + '\n[accounts.w]\nhost = "imap.example.com"\nuser = "me@example.com"\npassword_env = "X"\n'
        + f"draftdesk_account = {value}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("HOME", str(tmp_path))
    reply = tmp_path / "r.txt"
    reply.write_text("ok", encoding="utf-8")
    # A refusal (exit 2) before any IMAP: the password variable X is not even set.
    assert mail.main(["draft", "--account", "w", "--reply-to", "1", "--body-file", str(reply)]) == 2
    assert reason in capsys.readouterr().err


def test_the_draft_goes_over_as_utf8_whatever_the_locale(tmp_path, monkeypatch):
    seen = {}

    def run(argv, **kwargs):
        seen.update(kwargs)
        raise OSError(2, "stop here")

    monkeypatch.setattr(desk.subprocess, "run", run)
    with pytest.raises(RuntimeError):
        desk.hand_to_draftdesk("draftdesk", {"body": "Grüße"})
    assert seen["encoding"] == "utf-8"


def test_whatever_breaks_after_saving_says_the_draft_is_saved(monkeypatch, capsys):
    orig = _original()
    draft = mail.compose_reply(orig, "ok", ACCT)

    def broken(*_a):
        raise ValueError("odd header")

    monkeypatch.setattr(desk, "as_draft", broken)
    assert (
        mail.hand_over("/nonexistent/draftdesk", orig, draft, "ok", {**ACCT, "draftdesk_account": "desk"}, "Drafts")
        == 1
    )
    out = capsys.readouterr().out
    assert "ERROR: Draft Desk did not take the draft (ValueError: odd header)" in out
    assert "It is saved in 'Drafts': do not save it again." in out
