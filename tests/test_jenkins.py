import base64
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from app.asset_types import jenkins, jenkins_http, jenkins_logs, pinned
from app.asset_types.base import Context
from app.core.config import DEFAULTS
from app.core.db import Store
from app.core.security import GatewayError, NetworkPolicy
from tests.conftest import rpc


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.closed, self.reads = chunks, False, 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


def response(data=None, status=200, headers=None, body=None):
    raw = body if body is not None else json.dumps(data or {}).encode()
    return httpx.Response(status, headers=headers, stream=Chunks([raw]))


@pytest.fixture
def rig(config, monkeypatch):
    ctx = Context(
        {"id": "ci", "connection": {"url": "https://mcp.example.test/jenkins"}},
        {"id": "ci-reader", "config": {"username": "reader"}, "policy": {}},
        {"api_token": "test-token-never-expose"},
        dict(DEFAULTS),
        NetworkPolicy(config),
    )
    ctx.limits.update(max_output_bytes=262144, max_cell_chars=10000, max_result_rows=500, query_timeout_seconds=30)
    monkeypatch.setattr(ctx.network, "resolve", lambda *a: "192.0.2.30")
    routes, calls = {}, []

    async def handle(request):
        assert request.url.host == "192.0.2.30"
        assert request.headers["host"] == "mcp.example.test"
        assert request.extensions["sni_hostname"] == "mcp.example.test"
        assert request.headers["accept-encoding"] == "identity"
        assert request.headers["authorization"].startswith("Basic ")
        calls.append(
            {
                "method": request.method,
                "path": request.url.path,
                "raw": request.url.raw_path,
                "headers": dict(request.headers),
                "body": request.content,
                "params": dict(request.url.params),
            }
        )
        route = routes.get((request.method, request.url.path.removeprefix("/jenkins/")))
        if callable(route):
            return route(request)
        if isinstance(route, httpx.Response):
            return route
        if route is None:
            return response(status=404)
        return response(route)

    monkeypatch.setattr(pinned.httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    kind = jenkins.JenkinsAssetType("test-cursor-key")

    async def run(name, args=None):
        value = await kind.execute("jenkins_" + name, args or {}, ctx, None)
        return json.loads(value["content"][0]["text"])

    return ctx, routes, calls, kind, run


JOB = {
    "_class": "hudson.model.FreeStyleProject",
    "name": "demo",
    "fullName": "demo",
    "buildable": True,
    "lastBuild": {"number": 7},
    "property": [],
}
PIPELINE = {"_class": "org.jenkinsci.plugins.workflow.job.WorkflowRun", "number": 7}
# 仅组装脱敏校验用的假凭据，不关闭测试目录的秘密扫描。
XML = b"""<project><scm class="hudson.plugins.git.GitSCM"><userRemoteConfigs><config><url>https://{userinfo}@git.example/team/code.git</url><credentialsId>hidden-credential-id</credentialsId></config></userRemoteConfigs><branches><branch><name>*/main</name></branch></branches></scm></project>""".replace(
    b"{userinfo}", b"user:secret"
)
HTML = b"""<html><form method="post" action="run"><div class="jenkins-form-item"><div class="jenkins-form-label">Main Script</div><textarea name="_.mainScript">node {\n echo '&lt;hello&gt;&amp;'\n}</textarea></div><div class="jenkins-form-item"><div class="jenkins-form-label">lib.Helper</div><div class="setting-main"><textarea name="_.lib_Helper">return &quot;original&quot;\n</textarea></div></div></form></html>"""


def definition(name, kind="String", default="value", **extra):
    return {
        "name": name,
        "_class": "hudson.model." + kind + "ParameterDefinition",
        "defaultParameterValue": {"value": default},
        **extra,
    }


def parameter_job(*definitions):
    return {**JOB, "property": [{"parameterDefinitions": list(definitions)}]}


def test_metadata_and_config(rig):
    ctx, _, _, kind, _ = rig
    assert kind.async_mode and not kind.proxied and kind.type_id == "jenkins"
    assert len(kind.tools) == 19 and len({t["name"] for t in kind.tools}) == 19
    assert sum(not t["annotations"]["readOnlyHint"] for t in kind.tools) == 4
    assert kind.connection_schema["properties"]["ca_file"]["x-upload"]
    kind.validate_config(ctx.asset["connection"], ctx.account["config"], {}, ctx.credential)
    for username, token in (("a:b", "abc"), ("a\n", "abc"), ("abc", "bad\r")):
        with pytest.raises(GatewayError, match="控制字符|冒号"):
            kind.validate_config(ctx.asset["connection"], {"username": username}, {}, {"api_token": token})


@pytest.mark.parametrize(
    "name",
    [
        "../admin",
        "foo/../bar",
        "foo//bar",
        "/foo",
        "foo/",
        "foo/%2e%2e",
        "foo/%252e%252e",
        "foo/ab\\cd",
        "foo/%0a",
        "foo/a%2F..%2Fprivate",
    ],
)
def test_bad_job_paths(name):
    with pytest.raises(GatewayError):
        jenkins_http.job_path(name)


@pytest.mark.parametrize(
    "url",
    [
        "https://" + "u:p@host",
        "https://host/a?token=x",
        "https://host/#x",
        "file:///x",
        "https://host/../a",
        "https://host/\nx",
        "https://host:bad",
        "https://host/%252e%252e/admin",
    ],
)
def test_bad_roots(url):
    with pytest.raises(GatewayError):
        jenkins_http.root_url(url)


async def test_unicode_nested_job_query_and_parameter_sanitizing(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/团队/job/repo/job/feature%2Fone/api/json"] = parameter_job(
        definition("password", "Password", "do-not-return")
    )
    value = await run("get_job", {"jobFullName": "团队/repo/feature%2Fone"})
    assert "do-not-return" not in json.dumps(value)
    assert b"job/%E5%9B%A2%E9%98%9F/job/repo/job/feature%252Fone/api/json?tree=" in calls[0]["raw"]
    assert "parameterDefinitions" in calls[0]["params"]["tree"]


async def test_basic_reads_all_contracts(rig):
    _, routes, calls, _, run = rig
    routes.update(
        {
            ("GET", "job/demo/api/json"): JOB,
            ("GET", "api/json"): {"jobs": [{"name": "z"}, {"name": "a"}], "quietingDown": False},
            ("GET", "job/demo/7/api/json"): {"number": 7, "result": "SUCCESS"},
            ("GET", "queue/item/12/api/json"): {"id": 12, "executable": {"number": 7}},
            ("GET", "whoAmI/api/json"): {"name": "reader", "authenticated": True, "anonymous": False},
            ("GET", "user/reader/api/json"): {"id": "reader", "fullName": "读者"},
            ("GET", "queue/api/json"): {"items": []},
            ("GET", "computer/api/json"): {"totalExecutors": 4},
        }
    )
    assert (await run("get_jobs", {"limit": 1}))["jobs"] == [{"name": "a"}]
    assert (await run("get_build", {"jobFullName": "demo"}))["number"] == 7
    assert calls[-1]["path"].endswith("/7/api/json")
    assert (await run("get_queue_item", {"id": 12}))["state"] == "assigned"
    assert (await run("get_queue_item", {"id": 13}))["state"] == "expired_or_not_visible"
    assert (await run("who_am_i"))["user"]["fullName"] == "读者"
    status = await run("get_status")
    assert status["computer"]["totalExecutors"] == 4 and "clouds" in status["unavailable"]


async def test_trigger_crumb_cookie_arrays_and_boolean(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = parameter_job(
        definition("flag", "Boolean", False), definition("branch", "Choice", "main", choices=["main", "dev"])
    )
    routes["GET", "crumbIssuer/api/json"] = response(
        {"crumbRequestField": "Jenkins-Crumb", "crumb": "test-crumb"},
        headers={"Set-Cookie": "JSESSIONID=test-session; Path=/jenkins/; Secure"},
    )

    def submitted(request):
        assert request.headers["cookie"] == "JSESSIONID=test-session"
        assert request.headers["Jenkins-Crumb"] == "test-crumb"
        assert parse_qs(request.content.decode()) == {"flag": ["true"], "branch": ["main", "dev"]}
        return response(status=201, headers={"Location": "https://mcp.example.test/jenkins/queue/item/12/"})

    routes["POST", "job/demo/buildWithParameters"] = submitted
    value = await run("trigger_build", {"jobFullName": "demo", "parameters": {"flag": True, "branch": ["main", "dev"]}})
    assert value["queue_id"] == 12
    assert sum(c["method"] == "POST" for c in calls) == 1


async def test_plain_trigger_update_and_freestyle_rebuild(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = JOB
    routes["GET", "job/demo/7/api/json"] = {
        "_class": "hudson.model.FreeStyleBuild",
        "displayName": "old",
        "description": "keep",
        "actions": [],
    }
    routes["POST", "job/demo/build"] = lambda r: response(status=302, headers={"Location": "/jenkins/queue/item/12/"})
    routes["POST", "job/demo/7/configSubmit"] = response(status=303, headers={"Location": "."})
    assert (await run("trigger_build", {"jobFullName": "demo"}))["queue_id"] == 12
    assert (await run("update_build", {"jobFullName": "demo", "displayName": "new"}))["updated"]
    sent = json.loads(
        parse_qs(next(c["body"] for c in calls if c["path"].endswith("configSubmit")).decode())["json"][0]
    )
    assert sent == {"displayName": "new", "description": "keep"}
    assert (await run("rebuild_build", {"jobFullName": "demo"}))["queue_id"] == 12


@pytest.mark.parametrize(
    "kind,values",
    [
        ("File", {"p": "file"}),
        ("Unknown", {"p": "x"}),
        ("Choice", {"p": "bad"}),
        ("Boolean", {"p": "false"}),
        ("Password", {}),
        ("String", {"unknown": 1}),
    ],
)
async def test_parameters_fail_before_writes(rig, kind, values):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = parameter_job(definition("p", kind, choices=["good"]))
    with pytest.raises(GatewayError) as exc:
        await run("trigger_build", {"jobFullName": "demo", "parameters": values})
    assert exc.value.code == "JENKINS_PARAMETER"
    assert not any(c["method"] == "POST" for c in calls)


@pytest.mark.parametrize(
    "location,status",
    [
        ("https://evil.test/jenkins/queue/item/1/", 302),
        ("/jenkins/login", 302),
        ("/jenkins/queue/item/1/", 307),
        ("/jenkins/queue/item/1/?token=x", 303),
        ("/jenkins/queue/item/1/", 301),
    ],
)
async def test_write_redirect_restrictions(rig, location, status):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = JOB
    routes["POST", "job/demo/build"] = response(status=status, headers={"Location": location})
    with pytest.raises(GatewayError) as exc:
        await run("trigger_build", {"jobFullName": "demo"})
    assert exc.value.code == "UPSTREAM_REDIRECT"
    assert len(calls) == 3


async def test_no_write_retry_on_disconnect_or_csrf(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = JOB

    def failed(request):
        raise httpx.ReadTimeout("timeout")

    routes["POST", "job/demo/build"] = failed
    with pytest.raises(GatewayError) as exc:
        await run("trigger_build", {"jobFullName": "demo"})
    assert exc.value.code == "JENKINS_WRITE_UNKNOWN"
    routes["POST", "job/demo/build"] = response(status=403, body=b"No valid crumb")
    with pytest.raises(GatewayError) as exc:
        await run("trigger_build", {"jobFullName": "demo"})
    assert exc.value.code == "JENKINS_CSRF"
    assert sum(c["method"] == "POST" for c in calls) == 2


@pytest.mark.parametrize(
    "status,code",
    [(401, "JENKINS_AUTH"), (403, "JENKINS_FORBIDDEN"), (404, "JENKINS_NOT_FOUND"), (500, "JENKINS_UPSTREAM")],
)
async def test_http_errors(rig, status, code):
    _, routes, _, _, run = rig
    routes["GET", "job/demo/api/json"] = response(status=status, body=b"secret-upstream-error")
    with pytest.raises(GatewayError) as exc:
        await run("get_job", {"jobFullName": "demo"})
    assert exc.value.code == code and "secret-upstream" not in str(exc.value)


async def test_health_rejects_anonymous_and_html_login(rig):
    ctx, routes, _, kind, run = rig
    routes["GET", "whoAmI/api/json"] = {"authenticated": True, "anonymous": True, "name": "anonymous"}
    with pytest.raises(GatewayError, match="匿名"):
        await kind.health(ctx)
    routes["GET", "whoAmI/api/json"] = response(body=b"<html>login</html>")
    with pytest.raises(GatewayError) as exc:
        await run("who_am_i")
    assert exc.value.code == "JENKINS_RESPONSE"


async def test_empty_build_and_status_visibility(rig):
    _, routes, _, _, run = rig
    routes["GET", "job/demo/api/json"] = {"lastBuild": None}
    with pytest.raises(GatewayError) as exc:
        await run("get_build", {"jobFullName": "demo"})
    assert exc.value.code == "JENKINS_NO_BUILD"
    routes["GET", "api/json"] = {"quietingDown": True}
    routes["GET", "queue/api/json"] = response(status=403)
    value = await run("get_status")
    assert "queue" in value["unavailable"] and "computer" in value["unavailable"]


async def test_replay_original_scripts_mapping_and_pipeline_rebuild(rig):
    _, routes, calls, _, run = rig
    routes.update(
        {
            ("GET", "job/demo/api/json"): JOB,
            ("GET", "job/demo/7/api/json"): PIPELINE,
            ("GET", "job/demo/config.xml"): lambda r: response(body=XML),
            ("GET", "job/demo/7/replay/"): lambda r: response(body=HTML),
            ("POST", "job/demo/7/replay/run"): lambda r: response(status=302, headers={"Location": "../.."}),
            ("POST", "job/demo/7/replay/rebuild"): lambda r: response(status=303, headers={"Location": "../.."}),
        }
    )
    scripts = await run("get_replay_scripts", {"jobFullName": "demo"})
    assert scripts["mainScript"] == "node {\n echo '<hello>&'\n}"
    assert scripts["loadedScripts"] == {"lib.Helper": 'return "original"\n'}
    value = await run("replay_build", {"jobFullName": "demo", "mainScript": "node {echo 'new'}"})
    assert value["submitted"] and value["queue_id"] is None
    body = json.loads(parse_qs(calls[-1]["body"].decode())["json"][0])
    assert body == {"mainScript": "node {echo 'new'}", "lib_Helper": 'return "original"\n'}
    value = await run(
        "replay_build", {"jobFullName": "demo", "mainScript": "new", "loadedScripts": {"lib.Helper": "changed"}}
    )
    assert json.loads(parse_qs(calls[-1]["body"].decode())["json"][0])["lib_Helper"] == "changed"
    assert (await run("rebuild_build", {"jobFullName": "demo"}))["queue_id"] is None
    assert not any(c["path"].endswith("/build") for c in calls)


@pytest.mark.parametrize(
    "html,code",
    [
        (b'<form method="post" action="rebuild"></form>', "JENKINS_REPLAY_FORBIDDEN"),
        (b"<html>unknown</html>", "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML.replace(b"lib.Helper", b"other.Name"), "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML.replace(b"_.mainScript", b"unknown"), "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML[:100], "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML.replace(b"</textarea>", b""), "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML.replace(b"</form>", b""), "JENKINS_REPLAY_UNSUPPORTED"),
        (HTML + HTML, "JENKINS_REPLAY_UNSUPPORTED"),
    ],
)
async def test_replay_unknown_pages_never_submit(rig, html, code):
    _, routes, calls, _, run = rig
    routes.update(
        {
            ("GET", "job/demo/api/json"): JOB,
            ("GET", "job/demo/7/api/json"): PIPELINE,
            ("GET", "job/demo/config.xml"): response(body=XML),
            ("GET", "job/demo/7/replay/"): response(body=html),
        }
    )
    with pytest.raises(GatewayError) as exc:
        await run("replay_build", {"jobFullName": "demo", "mainScript": "new"})
    assert exc.value.code == code
    assert not any(c["method"] == "POST" for c in calls)


async def test_replay_permission_and_incomplete_source(rig):
    ctx, routes, calls, _, run = rig
    routes.update({("GET", "job/demo/7/api/json"): PIPELINE, ("GET", "job/demo/config.xml"): response(status=403)})
    with pytest.raises(GatewayError) as exc:
        await run("get_replay_scripts", {"jobFullName": "demo", "buildNumber": 7})
    assert exc.value.code == "JENKINS_FORBIDDEN" and len(calls) == 2
    routes["GET", "job/demo/config.xml"] = response(body=XML)
    routes["GET", "job/demo/7/replay/"] = response(body=HTML)
    ctx.limits["max_cell_chars"] = 10
    with pytest.raises(GatewayError) as exc:
        await run("get_replay_scripts", {"jobFullName": "demo", "buildNumber": 7})
    assert exc.value.code == "OUTPUT_LIMIT"


async def test_rebuild_hidden_password_refused(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/7/api/json"] = {
        "_class": "hudson.model.FreeStyleBuild",
        "actions": [
            {"parameters": [{"name": "password", "_class": "hudson.model.PasswordParameterValue", "value": "****"}]}
        ],
    }
    with pytest.raises(GatewayError) as exc:
        await run("rebuild_build", {"jobFullName": "demo", "buildNumber": 7})
    assert exc.value.code == "JENKINS_REBUILD_UNSUPPORTED"
    assert not any(c["method"] == "POST" for c in calls)


async def test_test_results_failures_and_flaky_support(rig):
    _, routes, _, _, run = rig
    cases = [
        {"name": "old", "status": "FAILED", "flakyFailures": []},
        {"name": "new", "status": "REGRESSION", "flakyFailures": [{"message": "intermittent"}]},
        {"name": "ok", "status": "PASSED", "flakyFailures": []},
    ]
    routes["GET", "job/demo/7/testReport/api/json"] = {"suites": [{"cases": cases}], "failCount": 2}
    args = {"jobFullName": "demo", "buildNumber": 7}
    assert len((await run("get_test_results", {**args, "onlyFailingTests": True}))["tests"]) == 2
    assert (await run("get_flaky_failures", args))["tests"][0]["name"] == "new"
    cases[0].pop("flakyFailures")
    with pytest.raises(GatewayError) as exc:
        await run("get_flaky_failures", args)
    assert exc.value.code == "JENKINS_UNSUPPORTED"
    assert not (await run("get_test_results", {**args, "buildNumber": 8}))["reportAvailable"]


async def test_scm_config_build_history_changes_and_search(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/config.xml"] = lambda r: response(body=XML)
    config = await run("get_job_scm", {"jobFullName": "demo"})
    assert config["scms"][0]["remoteUrls"] == ["https://git.example/team/code.git"]
    assert "secret" not in json.dumps(config) and "credential" not in json.dumps(config)
    routes["GET", "job/demo/7/api/json"] = {
        "actions": [
            {
                "_class": "hudson.plugins.git.util.BuildData",
                "remoteUrls": ["https://" + "u:p@git.example/old.git"],
                "lastBuiltRevision": {"SHA1": "deadbeef", "branch": [{"name": "origin/main"}]},
            }
        ],
        "changeSet": {"items": [{"commitId": "abc", "msg": "change", "paths": [{"file": "a", "editType": "edit"}]}]},
    }
    args = {"jobFullName": "demo", "buildNumber": 7}
    assert (await run("get_build_scm", args))["scms"][0]["revision"] == "deadbeef"
    assert (await run("get_build_change_sets", args))["changes"][0]["commitId"] == "abc"
    assert not any(c["path"].endswith("config.xml") for c in calls[1:])
    routes["GET", "api/json"] = {"jobs": [JOB, {"name": "hidden", "fullName": "hidden"}]}
    found = await run("find_jobs_with_scm_url", {"scmUrl": "git@git.example:team/code.git", "branch": "main"})
    assert found["matched"] == 1 and found["partial"] and found["unreadable"] == 1


@pytest.mark.parametrize(
    "body",
    [b'<!DOCTYPE project [<!ENTITY x "secret">]><project>&x;</project>', b"<project>bad", b"\xff\xfe<\x00x\x00>\x00"],
)
def test_xml_rejects_entities_and_invalid_encoding(body):
    with pytest.raises(GatewayError):
        jenkins.scm_config(body)


async def test_logs_cursor_tail_and_search(rig):
    ctx, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = JOB
    routes["GET", "job/demo/7/consoleText"] = lambda r: response(body="一行\nERROR two\nthree\nfour\n".encode())
    args = {"jobFullName": "demo"}
    first = await run("get_build_log", {**args, "limit": 2})
    assert first["lines"] == ["一行", "ERROR two"] and first["totalLines"] is None
    routes["GET", "job/demo/api/json"] = {"lastBuild": {"number": 8}}
    second = await run("get_build_log", {**args, "cursor": first["nextCursor"]})
    assert second["buildNumber"] == 7 and second["lines"] == ["three", "four"] and second["totalLines"] == 4
    tail = await run("get_build_log", {**args, "buildNumber": 7, "skip": -2})
    assert tail["lines"] == ["three", "four"] and tail["totalLines"] == 4
    searched = await run(
        "search_build_log", {**args, "buildNumber": 7, "pattern": "error", "ignoreCase": True, "contextLines": 1}
    )
    assert searched["matches"] == [{"lineNumber": 2, "line": "ERROR two", "before": ["一行"], "after": ["three"]}]
    before = len(calls)
    ctx.account["id"] = "different"
    with pytest.raises(GatewayError) as exc:
        await run("get_build_log", {**args, "cursor": first["nextCursor"]})
    assert exc.value.code == "JENKINS_CURSOR" and len(calls) == before


async def test_log_tail_budget_long_unicode_line_and_early_close(rig):
    ctx, routes, _, _, run = rig
    ctx.account["policy"]["max_log_scan_bytes"] = 1024
    routes["GET", "job/demo/7/consoleText"] = lambda r: response(body=("长" * 1000 + "\nlast\n").encode())
    args = {"jobFullName": "demo", "buildNumber": 7}
    value = await run("get_build_log", {**args, "skip": -2})
    assert value["scanLimited"] and value["lines"] == [] and value["totalLines"] is None
    ctx.account["policy"]["max_log_scan_bytes"] = 100000
    ctx.limits["max_cell_chars"] = 200
    stream = Chunks([b"one\n" * 2048, b"never-read\n" * 2000])
    routes["GET", "job/demo/7/consoleText"] = httpx.Response(200, stream=stream)
    value = await run("get_build_log", {**args, "limit": 1})
    assert value["lines"] == ["one"] and stream.closed and stream.reads == 1


async def test_log_regex_timeout_and_bad_regex(rig, monkeypatch):
    _, routes, _, _, run = rig
    args = {"jobFullName": "demo", "buildNumber": 7, "pattern": "[", "useRegex": True}
    with pytest.raises(GatewayError) as exc:
        await run("search_build_log", args)
    assert exc.value.code == "JENKINS_LOG_PATTERN"

    class Slow:
        def search(self, *a, **kw):
            raise TimeoutError

    compile_pattern = jenkins_logs.regex.compile
    monkeypatch.setattr(jenkins_logs.regex, "compile", lambda p, *a: Slow() if p == "x" else compile_pattern(p, *a))
    routes["GET", "job/demo/7/consoleText"] = response(body=b"hello\n")
    with pytest.raises(GatewayError) as exc:
        await run("search_build_log", {**args, "pattern": "x"})
    assert exc.value.code == "JENKINS_LOG_REGEX_TIMEOUT"


async def test_response_budgets_encoding_redirect_defaults_and_redaction(rig):
    ctx, routes, _, _, run = rig
    routes["GET", "job/demo/api/json"] = response(headers={"content-encoding": "gzip"}, body=b"bad")
    with pytest.raises(GatewayError) as exc:
        await run("get_job", {"jobFullName": "demo"})
    assert exc.value.code == "UPSTREAM_ENCODING"
    routes["GET", "job/demo/api/json"] = response(status=302, headers={"Location": "/jenkins/queue/item/1/"})
    with pytest.raises(GatewayError) as exc:
        await run("get_job", {"jobFullName": "demo"})
    assert exc.value.code == "UPSTREAM_REDIRECT"
    routes["GET", "job/demo/api/json"] = {**JOB, "description": ctx.credential["api_token"]}
    assert "test-token" not in json.dumps(await run("get_job", {"jobFullName": "demo"}))
    routes["GET", "large"] = lambda r: response(body=b"x" * 100)
    async with jenkins_http.JenkinsHTTP(ctx) as http:
        with pytest.raises(GatewayError) as exc:
            await http.request("large", maximum=50)
        assert exc.value.code == "JENKINS_RESPONSE_LIMIT"
    async with jenkins_http.JenkinsHTTP(ctx) as http:
        http.transport.maximum = 150
        await http.request("large")
        with pytest.raises(GatewayError) as exc:
            await http.request("large")
        assert exc.value.code == "UPSTREAM_SIZE"
    # 不配置 Jenkins 钩子的其它资产仍拒绝全部重定向。
    routes["GET", "redirect"] = response(status=303, headers={"Location": "/jenkins/queue/item/1/"})
    async with httpx.AsyncClient(transport=pinned.PinnedTransport(ctx, 1024), auth=("reader", "token")) as client:
        with pytest.raises(GatewayError) as exc:
            await client.get("https://mcp.example.test/jenkins/redirect")
        assert exc.value.code == "UPSTREAM_REDIRECT"


def test_api_authorization_target_audit_and_revoke(admin, app, monkeypatch):
    calls = []

    def save(table, data):
        value = admin.post("/api/" + table, json=data)
        assert value.status_code == 200, value.text
        return value.json()["data"]

    save(
        "assets",
        {
            "id": "ci",
            "name": "测试 Jenkins",
            "type": "jenkins",
            "connection": {"url": "https://mcp.example.test/jenkins"},
        },
    )
    for aid in ("ci-a", "ci-b"):
        saved = save(
            "accounts",
            {
                "id": aid,
                "asset_id": "ci",
                "name": aid,
                "config": {"username": "reader"},
                "credential": {"api_token": "integration-secret"},
                "policy": {},
            },
        )
        assert "integration-secret" not in json.dumps(saved)
    client = save("clients", {"id": "ci-client", "name": "测试智能体"})
    grant = save(
        "grants",
        {
            "client_ids": ["ci-client"],
            "entries": [
                {
                    "account_id": aid,
                    "tools": ["jenkins_get_job"],
                    "parameter_rules": {
                        "jenkins_get_job": {"jobFullName": {"allow": [{"match": "exact", "value": "demo"}], "deny": []}}
                    },
                }
                for aid in ("ci-a", "ci-b")
            ],
        },
    )
    gateway = app.state.gateway
    monkeypatch.setattr(gateway.network, "resolve", lambda *a: "192.0.2.30")

    def handle(request):
        calls.append(request.url.path)
        return response(JOB)

    monkeypatch.setattr(pinned.httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    token = client["token"]
    tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["jenkins_get_job"]

    def invoke(name="jenkins_get_job", **args):
        return rpc(admin, token, "tools/call", {"name": name, "arguments": args}).json()["result"]

    assert invoke(jobFullName="demo")["isError"]
    denied = invoke(jobFullName="other", target="ci-a")
    assert denied["isError"] and not calls
    assert invoke("jenkins_trigger_build", jobFullName="demo", target="ci-a")["isError"] and not calls
    assert not invoke(jobFullName="demo", target="ci-b")["isError"] and len(calls) == 1
    with gateway.store.connect() as conn:
        rows = conn.execute("SELECT detail_json FROM audit_log WHERE tool='jenkins_get_job' AND status='ok'").fetchall()
        assert rows and "integration-secret" not in str([tuple(row) for row in rows])
        assert "argument_hash" in rows[0][0]
    deleted = admin.delete("/api/grants/" + grant["id"], params={"revision": grant["revision"]})
    assert deleted.status_code == 200
    assert invoke(jobFullName="demo", target="ci-a")["isError"] and len(calls) == 1


@pytest.mark.parametrize(
    "skip,limit,expected", [(-4, 2, ["1", "2"]), (0, -2, ["3", "4"]), (-1, -2, ["2", "3"]), (3, -2, ["2", "3"])]
)
async def test_log_end_relative_windows(rig, skip, limit, expected):
    _, routes, _, _, run = rig
    routes["GET", "job/demo/7/consoleText"] = response(body=b"1\n2\n3\n4\n")
    value = await run("get_build_log", {"jobFullName": "demo", "buildNumber": 7, "skip": skip, "limit": limit})
    assert value["lines"] == expected


async def test_running_log_partial_line_and_cursor_tamper(rig):
    _, routes, _, _, run = rig
    args = {"jobFullName": "demo", "buildNumber": 7}
    routes["GET", "job/demo/7/consoleText"] = response(body="完成\n写入中".encode())
    first = await run("get_build_log", args)
    routes["GET", "job/demo/7/consoleText"] = response(body="完成\n写入中，结束\n".encode())
    value = await run("get_build_log", {**args, "cursor": first["nextCursor"]})
    assert value["lines"] == ["写入中，结束"]
    with pytest.raises(GatewayError) as exc:
        await run("get_build_log", {**args, "cursor": "A" + first["nextCursor"][1:]})
    assert exc.value.code == "JENKINS_CURSOR"


async def test_scm_search_budget_and_folders(rig):
    ctx, routes, _, _, run = rig
    ctx.account["policy"]["max_scan_jobs"] = 2
    routes["GET", "api/json"] = {
        "jobs": [{"name": "folder", "fullName": "folder", "_class": "com.cloudbees.hudson.plugins.folder.Folder"}]
    }
    routes["GET", "job/folder/api/json"] = {
        "jobs": [{"name": "a", "fullName": "folder/a"}, {"name": "b", "fullName": "folder/b"}]
    }
    routes["GET", "job/folder/job/a/config.xml"] = response(body=XML)
    value = await run("find_jobs_with_scm_url", {"scmUrl": "ssh://git@git.example/team/code", "branch": "main"})
    assert value["partial"] and value["scanned"] == 2 and value["matched"] == 1


async def test_replay_unknown_script_no_post_and_timeout_no_retry(rig):
    _, routes, calls, _, run = rig
    routes.update(
        {
            ("GET", "job/demo/7/api/json"): PIPELINE,
            ("GET", "job/demo/config.xml"): lambda r: response(body=XML),
            ("GET", "job/demo/7/replay/"): lambda r: response(body=HTML),
        }
    )
    args = {"jobFullName": "demo", "buildNumber": 7, "mainScript": "new"}
    with pytest.raises(GatewayError):
        await run("replay_build", {**args, "loadedScripts": {"wrong": "new"}})
    assert not any(c["method"] == "POST" for c in calls)

    def failed(request):
        raise httpx.ConnectError("disconnected")

    routes["POST", "job/demo/7/replay/run"] = failed
    with pytest.raises(GatewayError) as exc:
        await run("replay_build", args)
    assert exc.value.code == "JENKINS_WRITE_UNKNOWN" and sum(c["method"] == "POST" for c in calls) == 1


async def test_default_case_sensitive_search_and_small_field_keys(rig):
    ctx, routes, _, _, run = rig
    routes["GET", "job/demo/7/consoleText"] = response(body=b"ERROR\n")
    value = await run("search_build_log", {"jobFullName": "demo", "buildNumber": 7, "pattern": "error"})
    assert value["matches"] == [] and value["scanComplete"]
    routes["GET", "job/demo/7/api/json"] = {"displayName": "long value", "number": 7}
    ctx.limits["max_cell_chars"] = 2
    value = await run("get_build", {"jobFullName": "demo", "buildNumber": 7})
    assert value["displayName"] == "lo" and value["number"] == 7 and value["truncated"]


async def test_numeric_parameters_and_unrecoverable_original_defaults(rig):
    _, routes, calls, _, run = rig
    routes["GET", "job/demo/api/json"] = parameter_job(definition("count"))
    routes["POST", "job/demo/buildWithParameters"] = response(
        status=201, headers={"Location": "/jenkins/queue/item/2/"}
    )
    await run("trigger_build", {"jobFullName": "demo", "parameters": {"count": 42}})
    assert parse_qs(calls[-1]["body"].decode()) == {"count": ["42"]}
    routes["GET", "job/demo/7/api/json"] = {"_class": "hudson.model.FreeStyleBuild", "actions": []}
    with pytest.raises(GatewayError) as exc:
        await run("rebuild_build", {"jobFullName": "demo", "buildNumber": 7})
    assert exc.value.code == "JENKINS_REBUILD_UNSUPPORTED"
    assert sum(c["method"] == "POST" for c in calls) == 1


async def test_log_secret_redacted_before_field_truncation(rig):
    ctx, routes, _, _, run = rig
    ctx.limits["max_cell_chars"] = 200
    routes["GET", "job/demo/7/consoleText"] = response(body=("x" * 190 + ctx.credential["api_token"] + "\n").encode())
    value = await run("get_build_log", {"jobFullName": "demo", "buildNumber": 7})
    assert "test-token" not in value["lines"][0]
    assert "[REDACTED]" in value["lines"][0] and value["truncated"]


@pytest.mark.parametrize("basic_auth", [False, True])
async def test_repeated_log_secrets_do_not_expose_truncated_prefix(rig, basic_auth):
    ctx, routes, _, _, run = rig
    ctx.limits["max_cell_chars"] = 200
    secret = ctx.credential["api_token"]
    if basic_auth:
        secret = base64.b64encode((ctx.account["config"]["username"] + ":" + secret).encode()).decode()
    routes["GET", "job/demo/7/consoleText"] = response(body=("x" * 5 + secret * 100 + "\n").encode())
    value = await run("get_build_log", {"jobFullName": "demo", "buildNumber": 7})
    assert secret[:5] not in value["lines"][0]
    assert value["lines"][0].replace("[REDACTED]", "") == "xxxxx"
    assert value["truncated"]


def test_scm_branch_patterns_and_unknown_regex():
    assert jenkins.branch_matches("*/feature/*", "feature/topic")
    assert jenkins.branch_matches("**/main", "main")
    assert jenkins.branch_matches("${BRANCH}", "main")
    assert jenkins.branch_matches("*/main", "feature/main")
    assert not jenkins.branch_matches("*/main", "feature/topic/main")
    assert not jenkins.branch_matches("main", "feature/main")
    assert jenkins.branch_matches("refs/heads/main", "refs/heads/main")
    assert jenkins.branch_matches("remotes/upstream/*", "main", "upstream")
    assert not jenkins.branch_matches("upstream/*", "main", "origin")
    assert jenkins.branch_matches(":origin/.*", "main")
    with pytest.raises(GatewayError) as exc:
        jenkins.branch_matches(":[", "main")
    assert exc.value.code == "JENKINS_SCM_PATTERN"


async def test_scm_search_matches_named_remote_for_requested_url(rig):
    _, routes, _, _, run = rig
    xml = XML.replace(b"<config><url>", b"<config><name>upstream</name><url>").replace(b"*/main", b"upstream/main")
    routes["GET", "api/json"] = {"jobs": [JOB]}
    routes["GET", "job/demo/config.xml"] = lambda r: response(body=xml)
    args = {"scmUrl": "git@git.example:team/code.git", "branch": "refs/heads/main"}
    found = await run("find_jobs_with_scm_url", args)
    assert found["matched"] == 1 and not found["partial"]
    found = await run("find_jobs_with_scm_url", {**args, "branch": "feature/main"})
    assert found["matched"] == 0


def test_tls_context_ca_failure_and_verification():
    import ssl

    context = jenkins_http.tls_context({})
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(GatewayError) as exc:
        jenkins_http.tls_context({"ca_file": "-----BEGIN CERTIFICATE-----\ninvalid"})
    assert exc.value.code == "JENKINS_TLS"


def test_migration_008_preserves_all_rows_and_foreign_keys(tmp_path):
    folder = Path(__file__).resolve().parents[1] / "app/core/migrations"
    store = Store(tmp_path / "migration.sqlite")
    with closing(sqlite3.connect(store.path)) as conn:
        conn.create_function("legacy_ssh_command", 1, lambda v: v)
        conn.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT,applied_at INTEGER)")
        for version in range(1, 8):
            script = folder / f"{version:03}.sql"
            conn.executescript(script.read_text())
            conn.execute(
                "INSERT INTO schema_migrations VALUES(?,?,1)",
                (version, hashlib.sha256(script.read_bytes()).hexdigest()),
            )
            conn.commit()
        conn.execute(
            "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at) VALUES('old','旧资产','gitrepo','{}',1,1)"
        )
        conn.execute(
            "INSERT INTO accounts(id,asset_id,name,config_json,credential_ciphertext,credential_key_id,created_at,updated_at) VALUES('acct','old','旧账号','{}','ciphertext','key',1,1)"
        )
        conn.execute("INSERT INTO grants(id,name,tools_json,created_at,updated_at) VALUES('grant','旧授权','[]',1,1)")
        conn.execute(
            "INSERT INTO grant_accounts(grant_id,account_id,tools_json,parameter_rules_json) VALUES('grant','acct','[\"read_file\"]',?)",
            (json.dumps({"read_file": {"path": {"allow": [{"match": "exact", "value": "README.md"}]}}}),),
        )
        conn.commit()
        before = {
            table: conn.execute("SELECT * FROM " + table).fetchall()
            for table in ("assets", "accounts", "grants", "grant_accounts")
        }
    store.migrate()
    with store.connect() as conn:
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()
        assert conn.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 8
        for table, expected in before.items():
            assert [tuple(r) for r in conn.execute("SELECT * FROM " + table)] == expected
