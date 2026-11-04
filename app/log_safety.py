"""Every log line is one line of plain text: values that came from a visitor or another server
(a username, a path, an error message) can't start a fake log line (CR/LF), recolour or rewrite a
terminal (ANSI escapes), flood the log (length cap), or leak a secret (tokens, passwords and
cookies are masked)."""

import logging

MAX_MESSAGE = 4000
_SECRET_KEYS = ("password", "passwd", "secret", "token", "authorization", "cookie", "api_key", "apikey", "code_hash")


def _escape(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F or ch in "  ":
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _mask_tokens(text: str) -> str:
    """JWTs ("eyJ…") and Bearer values become "[redacted]"."""
    words = text.split(" ")
    for i, word in enumerate(words):
        bare = word.strip("\"',;()[]{}")
        if bare.startswith("eyJ") and bare.count(".") == 2 and len(bare) > 30:
            words[i] = word.replace(bare, "[redacted]")
        elif i > 0 and words[i - 1].lower().rstrip(":") == "bearer" and len(bare) > 8:
            words[i] = word.replace(bare, "[redacted]")
    return " ".join(words)


def _mask_pairs(text: str) -> str:
    """key=value and "key": "value" pairs whose key names a secret."""
    lowered = text.lower()
    for key in _SECRET_KEYS:
        start = 0
        while (i := lowered.find(key, start)) != -1:
            j = i + len(key)
            while j < len(text) and text[j] in "\"' ":
                j += 1
            if j < len(text) and text[j] in "=:":
                j += 1
                while j < len(text) and text[j] in "\"' ":
                    j += 1
                end = j
                while end < len(text) and text[end] not in "\"',;& }\n":
                    end += 1
                if end > j:
                    text = text[:j] + "[redacted]" + text[end:]
                    lowered = text.lower()
            start = i + len(key)
    return text


def clean(message: str) -> str:
    message = _mask_pairs(_mask_tokens(message))
    if len(message) > MAX_MESSAGE:
        # Both ends: a traceback's last line (the actual error) matters as much as its first.
        half = MAX_MESSAGE // 2
        message = f"{message[:half]} ... [{len(message) - MAX_MESSAGE} characters cut] ... {message[-half:]}"
    return _escape(message)


class SafeLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple):
            # uvicorn's access formatter unpacks the arguments (client, method, path, version,
            # status): each is cleaned where it stands instead of being folded into the message.
            record.args = tuple(clean(a) if isinstance(a, str) else a for a in record.args)
            return True
        try:
            record.msg = clean(record.getMessage())
            record.args = None
            if hasattr(record, "color_message"):
                # uvicorn's coloured formatter formats this copy with record.args (now gone).
                record.color_message = record.msg
        except Exception:  # never lose a log line over this
            record.msg, record.args = "[a log message that could not be cleaned]", None
        return True


def install() -> None:
    """On every handler that writes our logs and uvicorn's (set up before the app is imported)."""
    guard = SafeLogFilter()
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "app"):
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, SafeLogFilter) for f in handler.filters):
                handler.addFilter(guard)
