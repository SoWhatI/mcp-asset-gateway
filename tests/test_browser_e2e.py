"""可重复的 Chromium UI 验收；依赖仅在显式开启时导入，不进入生产镜像。"""

import csv
import io
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from local_stack import LocalStack, private_file

pytestmark = pytest.mark.skipif(os.getenv("RUN_BROWSER_E2E") != "1", reason="设置 RUN_BROWSER_E2E=1 才运行真实浏览器")


def test_browser_management_workflow():
    from playwright.sync_api import expect, sync_playwright

    stack = LocalStack(os.environ["LOCAL_E2E_STATE"])
    url = f"http://localhost:{stack.state['ports']['ui']}"
    identity = "ui-" + secrets.token_hex(4)
    errors, bad_responses, evidence = [], [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=os.getenv("PLAYWRIGHT_CHANNEL") or None)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        page = context.new_page()
        page.set_default_timeout(15000)
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on(
            "response",
            lambda response: (
                bad_responses.append((response.status, response.url))
                if response.status >= 400 and not response.url.endswith("/auth/me")
                else None
            ),
        )

        def login():
            page.get_by_placeholder("请输入管理员用户名").fill("admin")
            page.get_by_placeholder("请输入密码", exact=True).fill(stack.state["secrets"]["admin"])
            page.get_by_role("button", name="登录控制台").click()
            expect(page.locator(".app-shell")).to_be_visible()

        def navigate(name):
            page.locator("nav").get_by_role("button", name=re.compile(name)).click()
            expect(page.locator(".page-heading h1")).to_have_text(name)
            expect(page.locator(".el-loading-mask:visible")).to_have_count(0)

        def field(label, scope=None):
            scope = scope or page
            return (
                scope.locator(".el-form-item")
                .filter(has=page.locator("label").filter(has_text=re.compile("^" + re.escape(label) + "$")))
                .first
            )

        def fill(label, value, scope=None):
            field(label, scope).locator("input,textarea").first.fill(value)

        def select(label, option, scope=None):
            field(label, scope).locator(".el-select").click()
            page.locator(".el-select-dropdown:visible").get_by_role("option", name=option, exact=True).click()

        def dialog():
            return page.locator(".el-dialog:visible")

        def save(grant=False):
            dialog().get_by_role("button", name="保存授权组" if grant else "保存", exact=True).click()
            expect(page.locator(".el-dialog:visible").filter(has_text="显示名称")).to_have_count(0)
            if grant:
                expect(page.locator(".el-dialog:visible").filter(has_text="资产账号-工具")).to_have_count(0)

        def row(value):
            return page.locator(".el-table__body-wrapper tr").filter(has_text=value).first

        def confirm():
            page.locator(".el-message-box").get_by_role("button", name=re.compile("确定|确认")).click()

        def remove(value):
            row(value).get_by_role("button", name="删除", exact=True).click()
            expect(page.locator(".el-message-box")).not_to_contain_text(re.compile(r"(?:asset|acct|cli)-[0-9a-f]{12}"))
            confirm()
            expect(row(value)).to_have_count(0)

        try:
            page.goto(url)
            login()
            evidence.append("登录成功")
            navigate("资产管理")
            page.get_by_role("button", name="添加资产", exact=True).click()
            fill("显示名称", identity + "资产", dialog())
            fill("主机", "mysql", dialog())
            select("TLS 模式", "DISABLED", dialog())
            save()
            expect(row(identity)).to_be_visible()
            expect(row(identity)).not_to_contain_text(re.compile(r"asset-[0-9a-f]{12}"))
            row(identity).get_by_role("button", name="编辑", exact=True).click()
            fill("显示名称", identity + "已编辑资产", dialog())
            save()
            expect(row(identity)).to_contain_text("已编辑资产")
            evidence.append("资产新增、编辑")

            navigate("账号与凭据")
            page.get_by_role("button", name="添加账号", exact=True).click()
            fill("显示名称", identity + "账号", dialog())
            select("所属资产", identity + "已编辑资产 · mysql", dialog())
            fill("数据库用户", "reader_a", dialog())
            fill("默认数据库", "tenant_a", dialog())
            fill("密码", stack.state["secrets"]["reader"], dialog())
            save()
            expect(row(identity)).not_to_contain_text(re.compile(r"acct-[0-9a-f]{12}"))
            row(identity).get_by_role("button", name="测试连接").click()
            expect(page.get_by_text("连接验证成功", exact=True)).to_be_visible()
            row(identity).get_by_role("button", name="编辑", exact=True).click()
            expect(dialog().get_by_text("凭据不会回读。开启「替换凭据」后填写新的完整认证信息。")).to_be_visible()
            expect(dialog().locator("input[type=password]")).to_have_count(0)
            fill("账号说明", "浏览器编辑验证", dialog())
            save()
            evidence.append("账号新增、编辑、凭据不回读、真实连接")

            navigate("客户端")
            page.locator(".heading-actions").get_by_role("button", name="创建客户端").click()
            fill("显示名称", identity + "客户端", dialog())
            save()
            expect(page.locator(".token-value")).to_be_visible()
            token = page.locator(".token-value").inner_text()
            assert len(token) > 32
            page.get_by_role("button", name="我已安全保存").click()
            expect(page.locator(".token-value:visible")).to_have_count(0)
            expect(row(identity)).not_to_contain_text(re.compile(r"cli-[0-9a-f]{12}"))
            row(identity).get_by_role("button", name="编辑", exact=True).click()
            assert token not in dialog().inner_text()
            fill("显示名称", identity + "已编辑客户端", dialog())
            save()
            evidence.append("客户端新增、编辑、token一次展示")

            navigate("授权矩阵")
            page.get_by_role("button", name="创建授权组", exact=True).click()
            grant_dialog = dialog().filter(has_text="授权组名称")
            fill("授权组名称", identity + "授权组", grant_dialog)
            grant_dialog.locator(".grant-add-card.add-client .el-select").click()
            page.locator(".el-select-dropdown:visible").get_by_role(
                "option", name=identity + "已编辑客户端", exact=True
            ).click()
            grant_dialog.locator(".grant-add-card.add-client").get_by_role("button", name="添加", exact=True).click()
            grant_dialog.locator(".grant-add-card.add-account .el-select").click()
            page.locator(".el-select-dropdown:visible").get_by_role(
                "option", name=identity + "已编辑资产 · " + identity + "账号", exact=True
            ).click()
            grant_dialog.locator(".grant-add-card.add-account").get_by_role("button", name="添加", exact=True).click()
            grant_dialog.locator("button[title='配置工具']").click()
            tools_panel = page.locator(".el-dialog:visible").filter(has_text="取消全选")
            tools_panel.locator("label.el-checkbox").filter(has_text=re.compile(r"^list_tables$")).click()
            expect(tools_panel.get_by_role("checkbox", name="list_tables", exact=True)).to_be_checked()
            tools_panel.get_by_role("button", name="完成", exact=True).click()
            save(grant=True)
            row(identity).get_by_role("button", name="编辑", exact=True).click()
            grant_dialog = dialog().filter(has_text="授权组名称")
            grant_dialog.locator("button[title='配置工具']").click()
            tools_panel = page.locator(".el-dialog:visible").filter(has_text="取消全选")
            tools_panel.locator("label.el-checkbox").filter(has_text=re.compile(r"^describe_table$")).click()
            expect(tools_panel.get_by_role("checkbox", name="describe_table", exact=True)).to_be_checked()
            tools_panel.get_by_role("button", name="完成", exact=True).click()
            save(grant=True)
            expect(row(identity)).to_contain_text("describe_table")
            page.locator(".el-switch:visible").click()
            expect(page.get_by_role("switch")).to_be_checked()
            expect(page.locator(".matrix")).to_contain_text(identity)
            page.locator(".el-switch:visible").click()
            expect(page.get_by_role("switch")).not_to_be_checked()
            evidence.append("授权新增、编辑、矩阵视图")

            navigate("工具调试台")
            select("模拟客户端", "验收 agent-a")
            for tool, arguments, marker in [
                ("list_tables", {}, "records"),
                ("read_file", {"path": "hello.txt"}, "本地真实 SFTP"),
                ("验收 up · echo", {"message": "浏览器验收"}, "真实上游"),
            ]:
                select("已授权工具", tool)
                field("参数（JSON）").locator("textarea").fill(json.dumps(arguments, ensure_ascii=False))
                page.get_by_role("button", name="执行工具", exact=True).click()
                confirm()
                expect(page.locator(".debug-output")).to_contain_text("执行完成")
                expect(page.locator(".debug-output pre")).to_contain_text(marker)
            select("模拟客户端", "验收 agent-b")
            field("已授权工具").locator(".el-select").click()
            options = page.locator(".el-select-dropdown:visible").get_by_role("option")
            expect(options).to_have_count(2)
            assert set(options.all_text_contents()) == {"list_tables", "execute_query"}
            page.keyboard.press("Escape")
            evidence.append("调试三类真实工具与客户端隔离")

            for index, status in enumerate(["ok", "error", "denied", "timeout", "interrupted", "started"]):
                navigate("概览")
                with page.expect_response(lambda response: "/api/audit?" in response.url) as received:
                    page.locator(".status-summary button").nth(index).click()
                params = parse_qs(urlsplit(received.value.url).query)
                assert params["status"] == [status] and params["event"] == ["tools.call"]
                assert "start" in params and "end" in params
            for index, key in ((0, "tool"), (1, "client_id")):
                navigate("概览")
                button = page.locator(".ranking-panel").nth(index).locator(".el-table__body button").first
                name = button.inner_text()
                with page.expect_response(lambda response: "/api/audit?" in response.url) as received:
                    button.click()
                raw = parse_qs(urlsplit(received.value.url).query)[key][0]
                if key == "client_id":
                    assert raw and name != raw
                    assert not re.search(r"cli-[0-9a-f]{12}", name)
                else:
                    assert name == raw or name.endswith(" · " + raw.split("__", 1)[-1])
            evidence.append("六状态、热门工具、活跃客户端下钻")

            navigate("审计日志")
            page.get_by_placeholder("工具名称", exact=True).fill("")
            # 返回不带下钻筛选的全量审计，并验证真实分页。
            page.reload()
            expect(page.locator(".app-shell")).to_be_visible()
            navigate("审计日志")
            page.get_by_role("button", name="下一页", exact=True).click()
            expect(page.get_by_role("button", name="上一页", exact=True)).to_be_enabled()
            page.get_by_role("button", name="上一页", exact=True).click()
            page.get_by_role("button", name="详情", exact=True).first.click()
            expect(page.locator(".el-drawer")).to_contain_text("request_id")
            page.locator(".el-drawer").get_by_role("button", name=re.compile("Close|关闭")).click()
            page.get_by_placeholder("事件名称", exact=True).fill("tools.call")
            page.get_by_placeholder("工具名称", exact=True).fill("list_tables")
            page.get_by_role("button", name="查询", exact=True).click()
            with page.expect_download() as received:
                page.get_by_role("button", name="导出 CSV").click()
            content = Path(received.value.path()).read_bytes()
            assert content.startswith(b"\xef\xbb\xbf")
            rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
            assert rows and all(item["tool"] == "list_tables" and item["event"] == "tools.call" for item in rows)
            assert all(secret not in content.decode() for secret in stack.state["secrets"].values())
            evidence.append("审计分页、详情、筛选及CSV内容/BOM/脱敏")

            navigate("系统设置")
            expect(page.get_by_text("资源与保留策略", exact=True)).to_be_visible()
            page.get_by_role("button", name="保存设置", exact=True).click()
            expect(page.get_by_text("设置已保存", exact=True)).to_be_visible()
            evidence.append("设置加载及保存")

            for name in ("授权矩阵", "客户端", "账号与凭据", "资产管理"):
                navigate(name)
                remove(identity)
            evidence.append("四类对象按引用顺序删除")
            navigate("概览")
            expect(page.locator(".el-message:visible")).to_have_count(0)
            page.screenshot(path=str(stack.folder / "browser-desktop.png"), full_page=True)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                for name in ("概览", "资产管理", "审计日志", "工具调试台", "系统设置"):
                    navigate(name)
                    overflow = page.evaluate("""() => [...document.querySelectorAll('main *, .topbar *')]
                        .filter(el => el.getBoundingClientRect().right > innerWidth + 1 && el.offsetWidth)
                        .slice(0, 12).map(el => ({tag: el.tagName, cls: el.className,
                            right: Math.round(el.getBoundingClientRect().right)}))""")
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (
                        f"{width}px {name} 横向溢出: {overflow}"
                    )
                navigate("概览")
                if width == 390:
                    page.screenshot(path=str(stack.folder / "browser-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.get_by_role("button", name="退出", exact=True).click()
            expect(page.get_by_role("button", name="登录控制台")).to_be_visible()
            login()
            evidence.append("1440/390响应式及退出/重新登录")
            assert not errors, errors
            assert not bad_responses, bad_responses
            private_file(
                stack.folder / "browser-result.json",
                json.dumps(
                    {"checks": evidence, "page_errors": errors, "failed_responses": bad_responses}, ensure_ascii=False
                ),
            )
        finally:
            context.close()
            browser.close()
