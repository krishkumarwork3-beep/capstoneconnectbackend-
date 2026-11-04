"""Every request body is an explicit allowlist (unknown fields are refused: no mass assignment), every
string has a maximum length and every list a maximum size (no unbounded input), and every query
parameter that is a string is bounded too. Checked on the OpenAPI schema, so new models are covered."""

from app.main import app


def _resolve(spec, schema):
    while "$ref" in schema:
        schema = spec["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
    return schema


def _problems(spec, schema, where, seen) -> list[str]:
    schema = _resolve(spec, schema)
    out = []
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key, []):
            out += _problems(spec, sub, where, seen)
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        title = schema.get("title", where)
        if title in seen:
            return out
        seen.add(title)
        if schema.get("additionalProperties", True) is not False:
            out.append(f"{title}: unknown fields are not refused (extra='forbid')")
        for name, sub in schema.get("properties", {}).items():
            out += _problems(spec, sub, f"{title}.{name}", seen)
    elif kind == "string" and "enum" not in schema and "const" not in schema and schema.get("format") not in ("date-time", "binary"):
        if "maxLength" not in schema:
            out.append(f"{where}: string without maxLength")
    elif kind == "array":
        if "maxItems" not in schema:
            out.append(f"{where}: list without maxItems")
        out += _problems(spec, schema.get("items", {}), f"{where}[]", seen)
    return out


def test_request_bodies_are_strict_and_bounded():
    spec = app.openapi()
    problems, seen = [], set()
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            content = (op.get("requestBody") or {}).get("content", {})
            for ctype, media in content.items():
                if ctype == "application/json":
                    problems += _problems(spec, media["schema"], f"{method.upper()} {path}", seen)
    assert problems == [], "\n".join(sorted(set(problems)))


def test_query_and_path_strings_are_bounded():
    spec = app.openapi()
    problems = []
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            for p in op.get("parameters", []):
                schema = _resolve(spec, p.get("schema", {}))
                options = schema.get("anyOf", [schema])
                for option in options:
                    option = _resolve(spec, option)
                    if option.get("type") == "string" and "enum" not in option and "maxLength" not in option and option.get("format") != "date-time":
                        problems.append(f"{method.upper()} {path} {p['in']} {p['name']}: no maxLength")
    assert problems == [], "\n".join(problems)
