"""Part 5: SSRF through the GitHub client. Hostile usernames never reach a URL; the transport only
talks HTTPS to GitHub's two hosts at public addresses, follows no redirect and reads a bounded body.
No test here touches the network: DNS and the far side are replaced."""

import asyncio

import httpx
import pytest

from app.services import github

HOSTILE_NAMES = [
    "https://evil.example/foo", "http://127.0.0.1/", "127.0.0.1", "[::1]", "0x7f000001", "2130706433", "169.254.169.254",
    "github.com.evil.example/foo", "https://github.com@evil.example/foo", "https://github.com/foo@evil.example", "foo@evil.example",
    "foo#@evil.example", "foo#bar", "foo?x=1", "foo\\evil", "foo/../../admin", "..", "%2e%2e", "foo%2f..%2fadmin",
    "foo\r\nHost: evil", "foo bar", "-foo", "foo-", "a" * 40, "ｆｏｏ", "foo\x00", "localhost", "metadata.google.internal",
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "dict://127.0.0.1:11211/",
]


@pytest.mark.parametrize("value", HOSTILE_NAMES)
def test_hostile_usernames_are_not_usernames(value):
    name = github.username_from(value)
    assert name is None or github.USERNAME.match(name), (value, name)
    assert name is None or all(ch not in name for ch in "/@#?\\.:%[] \r\n\x00"), (value, name)


@pytest.mark.parametrize("value", ["https://github.com/octocat", "github.com/octocat/", "@octocat", "octocat", "https://www.github.com/Octo-Cat"])
def test_real_usernames_still_work(value):
    assert github.username_from(value) in ("octocat", "Octo-Cat")


@pytest.mark.parametrize("value", HOSTILE_NAMES)
def test_hostile_names_never_leave_the_server(value, monkeypatch):
    if github.USERNAME.match(value):
        pytest.skip("a valid GitHub username: it can only ever be looked up on api.github.com")

    async def no_network(*a, **k):
        raise AssertionError("a request was attempted")

    monkeypatch.setattr(github.GuardedTransport, "handle_async_request", no_network)
    assert asyncio.run(github.lookup(value)) is None
    with pytest.raises(github.GitHubUnavailable):
        asyncio.run(github.activity(value, 0))


def _run(transport: httpx.AsyncBaseTransport, url: str, method: str = "GET") -> httpx.Response:
    async def go():
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as c:
            return await c.request(method, url)

    return asyncio.run(go())


def _resolver(monkeypatch, *addresses):
    async def fake(host):
        return list(addresses)

    monkeypatch.setattr(github, "_resolve", fake)


def _far_side(handler) -> github.GuardedTransport:
    return github.GuardedTransport(inner=httpx.MockTransport(handler), require_peer=False)


@pytest.mark.parametrize("url", [
    "http://api.github.com/users/x", "https://evil.example/", "https://api.github.com.evil.example/", "https://github.com:8443/",
    "https://user:pw@github.com/", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest/meta-data/",
    "https://gist.github.com/", "https://raw.githubusercontent.com/x",
])
def test_only_github_over_https(url, monkeypatch):
    _resolver(monkeypatch, "140.82.112.3")
    with pytest.raises(github.GitHubBlocked):
        _run(_far_side(lambda r: httpx.Response(200)), url)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1",
                                     "fe80::1", "fc00::1", "::ffff:127.0.0.1", "100.64.0.1", "224.0.0.1", "240.0.0.1"])
def test_dns_answers_pointing_inside_are_refused(address, monkeypatch):
    """DNS rebinding: github.com made to resolve to an internal address."""
    _resolver(monkeypatch, "140.82.112.3", address)
    with pytest.raises(github.GitHubBlocked):
        _run(_far_side(lambda r: httpx.Response(200)), "https://api.github.com/users/octocat")


def test_the_connected_address_is_checked_again(monkeypatch):
    """Resolved to a public address, but the socket ended up on an internal one."""
    _resolver(monkeypatch, "140.82.112.3")

    class Stream:
        def get_extra_info(self, name):
            return ("127.0.0.1", 443) if name == "server_addr" else None

    transport = github.GuardedTransport(inner=httpx.MockTransport(lambda r: httpx.Response(200, extensions={"network_stream": Stream()})))
    with pytest.raises(github.GitHubBlocked):
        _run(transport, "https://api.github.com/users/octocat")


def test_an_unconfirmed_peer_is_refused_in_production(monkeypatch):
    _resolver(monkeypatch, "140.82.112.3")
    transport = github.GuardedTransport(inner=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(github.GitHubBlocked):
        _run(transport, "https://api.github.com/users/octocat")


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_not_followed(status, monkeypatch):
    _resolver(monkeypatch, "140.82.112.3")
    handler = lambda r: httpx.Response(status, headers={"Location": "http://169.254.169.254/latest/meta-data/"})  # noqa: E731
    with pytest.raises(github.GitHubBlocked):
        _run(_far_side(handler), "https://github.com/users/octocat/contributions")


def test_huge_answers_are_cut_off(monkeypatch):
    _resolver(monkeypatch, "140.82.112.3")
    big = b"1," * (github.MAX_BYTES // 2 + 10)
    with pytest.raises(github.GitHubBlocked):
        _run(_far_side(lambda r: httpx.Response(200, content=big)), "https://api.github.com/users/octocat")
    with pytest.raises(github.GitHubBlocked):  # a lying Content-Length is caught by counting too
        _run(_far_side(lambda r: httpx.Response(200, content=big, headers={"Content-Length": "10"})), "https://api.github.com/users/x")


def test_compressed_answers_are_refused(monkeypatch):
    """A gzip "bomb" would unpack to far more than the cap: only identity bodies are read."""
    _resolver(monkeypatch, "140.82.112.3")
    with pytest.raises(github.GitHubBlocked):
        _run(_far_side(lambda r: httpx.Response(200, content=b"\x1f\x8b", headers={"Content-Encoding": "gzip"})), "https://api.github.com/users/x")


def test_a_normal_answer_passes(monkeypatch):
    _resolver(monkeypatch, "140.82.112.3", "2606:50c0:8000::153")
    r = _run(_far_side(lambda r: httpx.Response(200, json={"login": "octocat"})), "https://api.github.com/users/octocat")
    assert r.json() == {"login": "octocat"}


def test_requests_ask_for_uncompressed_bodies_and_send_no_token_to_github_com(monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "github_token", "test-token-value")
    assert github._headers()["Accept-Encoding"] == "identity"
    assert "Authorization" not in github._headers(json=False)  # the calendar page on github.com


def test_hostile_github_answers_never_become_links(monkeypatch):
    """A profile answer with a crafted login can't plant a link or path."""
    assert github._login({"login": "../../evil"}, "octocat") == "octocat"
    assert github._login({"login": "evil.example/x"}, "octocat") == "octocat"
    assert github._login({"login": ["x"]}, "octocat") == "octocat"
    assert github._login({"login": "Octo-Cat"}, "octocat") == "Octo-Cat"


def test_the_lookup_cache_is_bounded(monkeypatch):
    async def fake(username, client=None):
        return None

    monkeypatch.setattr(github, "all_time_contributions", fake)
    monkeypatch.setattr(github, "_LOOKUPS", {})
    for i in range(github._LOOKUP_MAX + 50):
        asyncio.run(github.lookup(f"user{i}"))
    assert len(github._LOOKUPS) == github._LOOKUP_MAX


def test_the_verify_route_refuses_hostile_names_without_a_request(client, monkeypatch):
    async def no_network(*a, **k):
        raise AssertionError("a request was attempted")

    monkeypatch.setattr(github.GuardedTransport, "handle_async_request", no_network)
    for value in ["http://127.0.0.1/", "foo@evil.example", "169.254.169.254", "foo#@evil.example", "foo\evil"]:
        r = client.get("/api/github/verify", params={"username": value})
        assert r.status_code in (200, 400, 422), r.text
        if r.status_code == 200:
            assert r.json().get("valid") is False
