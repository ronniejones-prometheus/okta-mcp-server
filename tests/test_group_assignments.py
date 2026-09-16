# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for application group assignment tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.group_assignments import (
    assign_group_to_application,
    get_application_group_assignment,
    list_application_group_assignments,
    unassign_group_from_application,
)

APP_ID = "0oaTEST0000000001"
GROUP_ID = "00gTEST0000000001"
MODULE = "okta_mcp_server.tools.applications.group_assignments"


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(okta_auth_manager=FakeOktaAuthManager())
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _make_assignment_mock(group_id: str, priority: int | None = None):
    assignment = MagicMock()
    assignment.id = group_id
    assignment.to_dict.return_value = {"id": group_id, "priority": priority, "profile": {}}
    return assignment


def _make_last_page_response():
    """A transport response with no next page."""
    response = MagicMock()
    response.has_next.return_value = False
    response.headers = {}
    return response


class TestListApplicationGroupAssignments:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_returns_paginated_assignments(self, mock_get_client):
        client = AsyncMock()
        client.list_application_group_assignments.return_value = (
            [_make_assignment_mock(GROUP_ID, 1), _make_assignment_mock("00gTEST0000000002")],
            _make_last_page_response(),
            None,
        )
        mock_get_client.return_value = client

        result = await list_application_group_assignments(ctx=_make_ctx(), app_id=APP_ID, expand="group")

        client.list_application_group_assignments.assert_called_once_with(APP_ID, expand="group")
        assert result["total_fetched"] == 2
        assert result["has_more"] is False
        assert result["items"][0] == {"id": GROUP_ID, "priority": 1, "profile": {}}
        json.dumps(result)

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_clamps_limit_to_api_bounds(self, mock_get_client):
        client = AsyncMock()
        client.list_application_group_assignments.return_value = ([], _make_last_page_response(), None)
        mock_get_client.return_value = client

        await list_application_group_assignments(ctx=_make_ctx(), app_id=APP_ID, limit=5)
        client.list_application_group_assignments.assert_called_with(APP_ID, limit=20)

        await list_application_group_assignments(ctx=_make_ctx(), app_id=APP_ID, limit=999)
        client.list_application_group_assignments.assert_called_with(APP_ID, limit=200)

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_empty_assignment_list(self, mock_get_client):
        client = AsyncMock()
        client.list_application_group_assignments.return_value = ([], _make_last_page_response(), None)
        mock_get_client.return_value = client

        result = await list_application_group_assignments(ctx=_make_ctx(), app_id=APP_ID)

        assert result["items"] == []
        assert result["total_fetched"] == 0

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client):
        client = AsyncMock()
        client.list_application_group_assignments.return_value = (None, None, "Error: Not found")
        mock_get_client.return_value = client

        result = await list_application_group_assignments(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "Error: Not found"}

    @pytest.mark.asyncio
    async def test_rejects_invalid_app_id(self):
        result = await list_application_group_assignments(ctx=_make_ctx(), app_id="../etc/passwd")

        assert "error" in result


class TestGetApplicationGroupAssignment:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_returns_assignment(self, mock_get_client):
        client = AsyncMock()
        client.get_application_group_assignment.return_value = (_make_assignment_mock(GROUP_ID, 3), MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_application_group_assignment(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        client.get_application_group_assignment.assert_called_once_with(APP_ID, GROUP_ID)
        assert result == {"id": GROUP_ID, "priority": 3, "profile": {}}

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_none_body_is_reported(self, mock_get_client):
        client = AsyncMock()
        client.get_application_group_assignment.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_application_group_assignment(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        assert "empty response" in result["error"]
        assert "list_application_group_assignments()" in result["error"]


class TestAssignGroupToApplication:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_assigns_with_options(self, mock_get_client):
        client = AsyncMock()
        client.assign_group_to_application.return_value = (_make_assignment_mock(GROUP_ID, 1), MagicMock(), None)
        mock_get_client.return_value = client

        result = await assign_group_to_application(
            ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID, priority=1, profile={"role": "admin"}
        )

        args, _ = client.assign_group_to_application.call_args
        assert args[0] == APP_ID
        assert args[1] == GROUP_ID
        assert args[2].priority == 1
        assert args[2].profile == {"role": "admin"}
        assert result == {"id": GROUP_ID, "priority": 1, "profile": {}}

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_bare_assignment_sends_empty_body(self, mock_get_client):
        client = AsyncMock()
        client.assign_group_to_application.return_value = (_make_assignment_mock(GROUP_ID), MagicMock(), None)
        mock_get_client.return_value = client

        await assign_group_to_application(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        body = client.assign_group_to_application.call_args[0][2]
        assert body.to_dict() == {}

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client):
        client = AsyncMock()
        client.assign_group_to_application.return_value = (None, None, "Error: Forbidden")
        mock_get_client.return_value = client

        result = await assign_group_to_application(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        assert result == {"error": "Error: Forbidden"}


class TestUnassignGroupFromApplication:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_confirmed_unassign_calls_api(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.unassign_application_from_group.return_value = (None, None)
        mock_get_client.return_value = client

        result = await unassign_group_from_application(ctx=ctx_elicit_accept_true, app_id=APP_ID, group_id=GROUP_ID)

        client.unassign_application_from_group.assert_called_once_with(APP_ID, GROUP_ID)
        assert "successfully" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_declined_unassign_does_not_call_api(self, mock_get_client, ctx_elicit_accept_false):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await unassign_group_from_application(ctx=ctx_elicit_accept_false, app_id=APP_ID, group_id=GROUP_ID)

        client.unassign_application_from_group.assert_not_called()
        assert "cancelled" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_no_elicitation_support_auto_confirms(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.unassign_application_from_group.return_value = (None, None)
        mock_get_client.return_value = client

        result = await unassign_group_from_application(ctx=ctx_no_elicitation, app_id=APP_ID, group_id=GROUP_ID)

        client.unassign_application_from_group.assert_called_once_with(APP_ID, GROUP_ID)
        assert "successfully" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.unassign_application_from_group.return_value = (None, "Error: Not found")
        mock_get_client.return_value = client

        result = await unassign_group_from_application(ctx=ctx_elicit_accept_true, app_id=APP_ID, group_id=GROUP_ID)

        assert result == [{"error": "Error: Not found"}]
