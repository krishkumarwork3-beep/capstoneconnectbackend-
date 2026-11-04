"""LIKE patterns from what a visitor typed: their %, _ and \\ are matched literally, never as
wildcards (otherwise searching "%" lists everything and "_" matches any character)."""

ESCAPE = "\\"


def _escape(term: str) -> str:
    return term.replace(ESCAPE, ESCAPE * 2).replace("%", ESCAPE + "%").replace("_", ESCAPE + "_")


def contains(term: str) -> str:
    """For `column.like(contains(q), escape=ESCAPE)`: q anywhere in the column."""
    return f"%{_escape(term)}%"


def starts_with(term: str) -> str:
    return f"{_escape(term)}%"
