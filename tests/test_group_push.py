# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for group push mapping tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.group_push import (
    create_group_push_mapping,
    delete_group_push_mapping,
    get_group_push_mapping,
    list_group_push_mappings,
    update_group_push_mapping,
)

APP_ID = "0oaTEST0000000001"
SOURCE_GROUP_ID = "00gTEST0000000001"
TARGET_GROUP_ID = "00gTEST0000000002"
MAPPING_ID = "gPmTEST0000000001"
MODULE = "okta_mcp_server.tools.applications.group_push"


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(okta_auth_manager=FakeOktaAuthManager())
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _make_mapping_mock(mapping_id: str = MAPPING_ID, status: str = "ACTIVE"):
    mapping = MagicMock()
    mapping.id = mapping_id
    mapping.to_dict.return_value = {
        "id": mapping_id,
        "sourceGroupId": SOURCE_GROUP_ID,
        "targetGroupId": TARGET_GROUP_ID,
        "status": status,
    }
    return mapping


def _make_last_page_response():
    response = MagicMock()
    response.has_next.return_value = False
    response.headers = {}
    return response


class TestListGroupPushMappings:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_returns_paginated_mappings(self, mock_get_client):
        client = AsyncMock()
        client.list_group_push_mappings.return_value = ([_make_mapping_mock()], _make_last_page_response(), None)
        mock_get_client.return_value = client

        result = await list_group_push_mappings(ctx=_make_ctx(), app_id=APP_ID)

        client.list_group_push_mappings.assert_called_once_with(APP_ID)
        assert result["total_fetched"] == 1
        assert result["items"][0]["status"] == "ACTIVE"
        json.dumps(result)

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_status_filter_is_passed_as_sdk_enum(self, mock_get_client):
        client = AsyncMock()
        client.list_group_push_mappings.return_value = ([], _make_last_page_response(), None)
        mock_get_client.return_value = client

        await list_group_push_mappings(ctx=_make_ctx(), app_id=APP_ID, status="error", source_group_id=SOURCE_GROUP_ID)

        client.list_group_push_mappings.assert_called_once_with(
            APP_ID, source_group_id=SOURCE_GROUP_ID, status=okta_models.GroupPushMappingStatus.ERROR
        )

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_invalid_status_filter_is_rejected_before_api_call(self, mock_get_client):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await list_group_push_mappings(ctx=_make_ctx(), app_id=APP_ID, status="BROKEN")

        client.list_group_push_mappings.assert_not_called()
        assert "Invalid status" in result["error"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client):
        client = AsyncMock()
        client.list_group_push_mappings.return_value = (None, None, "Error: provisioning not enabled")
        mock_get_client.return_value = client

        result = await list_group_push_mappings(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "Error: provisioning not enabled"}


class TestGetGroupPushMapping:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_returns_mapping(self, mock_get_client):
        client = AsyncMock()
        client.get_group_push_mapping.return_value = (_make_mapping_mock(), MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_group_push_mapping(ctx=_make_ctx(), app_id=APP_ID, mapping_id=MAPPING_ID)

        client.get_group_push_mapping.assert_called_once_with(APP_ID, MAPPING_ID)
        assert result["id"] == MAPPING_ID

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_none_body_is_reported(self, mock_get_client):
        client = AsyncMock()
        client.get_group_push_mapping.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_group_push_mapping(ctx=_make_ctx(), app_id=APP_ID, mapping_id=MAPPING_ID)

        assert "error" in result


class TestCreateGroupPushMapping:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_creates_mapping_with_target_group_name(self, mock_get_client):
        client = AsyncMock()
        client.create_group_push_mapping.return_value = (_make_mapping_mock(), MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, target_group_name="Engineering", status="inactive"
        )

        args, _ = client.create_group_push_mapping.call_args
        assert args[0] == APP_ID
        body = args[1]
        assert isinstance(body, okta_models.CreateGroupPushMappingRequest)
        assert body.to_dict() == {"sourceGroupId": SOURCE_GROUP_ID, "targetGroupName": "Engineering", "status": "INACTIVE"}
        assert result["id"] == MAPPING_ID

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_creates_mapping_linking_existing_target_group(self, mock_get_client):
        client = AsyncMock()
        client.create_group_push_mapping.return_value = (_make_mapping_mock(), MagicMock(), None)
        mock_get_client.return_value = client

        await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, target_group_id=TARGET_GROUP_ID
        )

        body = client.create_group_push_mapping.call_args[0][1]
        assert body.to_dict() == {"sourceGroupId": SOURCE_GROUP_ID, "targetGroupId": TARGET_GROUP_ID, "status": "ACTIVE"}

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_active_directory_app_config_keeps_all_fields(self, mock_get_client):
        client = AsyncMock()
        client.create_group_push_mapping.return_value = (_make_mapping_mock(), MagicMock(), None)
        mock_get_client.return_value = client

        ad_config = {
            "type": "ACTIVE_DIRECTORY",
            "distinguishedName": "CN=Test,OU=Groups,DC=example,DC=com",
            "groupScope": "DOMAIN_LOCAL",
            "groupType": "SECURITY",
            "samAccountName": "test",
        }
        await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, target_group_name="Test", app_config=ad_config
        )

        body = client.create_group_push_mapping.call_args[0][1]
        assert body.to_dict()["appConfig"] == ad_config

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    @pytest.mark.parametrize(
        "target_kwargs",
        [
            {},
            {"target_group_id": TARGET_GROUP_ID, "target_group_name": "Engineering"},
        ],
    )
    async def test_requires_exactly_one_target(self, mock_get_client, target_kwargs):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, **target_kwargs
        )

        client.create_group_push_mapping.assert_not_called()
        assert "exactly one" in result["error"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_rejects_error_status_on_create(self, mock_get_client):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, target_group_name="X", status="ERROR"
        )

        client.create_group_push_mapping.assert_not_called()
        assert "Invalid status" in result["error"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client):
        client = AsyncMock()
        client.create_group_push_mapping.return_value = (None, None, "Error: Forbidden")
        mock_get_client.return_value = client

        result = await create_group_push_mapping(
            ctx=_make_ctx(), app_id=APP_ID, source_group_id=SOURCE_GROUP_ID, target_group_name="X"
        )

        assert result == {"error": "Error: Forbidden"}


class TestUpdateGroupPushMapping:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_updates_status(self, mock_get_client):
        client = AsyncMock()
        client.update_group_push_mapping.return_value = (_make_mapping_mock(status="INACTIVE"), MagicMock(), None)
        mock_get_client.return_value = client

        result = await update_group_push_mapping(ctx=_make_ctx(), app_id=APP_ID, mapping_id=MAPPING_ID, status="inactive")

        args, _ = client.update_group_push_mapping.call_args
        assert args[:2] == (APP_ID, MAPPING_ID)
        assert args[2].to_dict() == {"status": "INACTIVE"}
        assert result["status"] == "INACTIVE"

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_rejects_invalid_status(self, mock_get_client):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await update_group_push_mapping(ctx=_make_ctx(), app_id=APP_ID, mapping_id=MAPPING_ID, status="PAUSED")

        client.update_group_push_mapping.assert_not_called()
        assert "Invalid status" in result["error"]


class TestDeleteGroupPushMapping:
    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_confirmed_delete_calls_api(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group_push_mapping.return_value = (None, None)
        mock_get_client.return_value = client

        result = await delete_group_push_mapping(ctx=ctx_elicit_accept_true, app_id=APP_ID, mapping_id=MAPPING_ID)

        client.delete_group_push_mapping.assert_called_once_with(APP_ID, MAPPING_ID, False)
        assert "successfully" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_delete_target_group_flag_is_forwarded(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group_push_mapping.return_value = (None, None)
        mock_get_client.return_value = client

        await delete_group_push_mapping(
            ctx=ctx_elicit_accept_true, app_id=APP_ID, mapping_id=MAPPING_ID, delete_target_group=True
        )

        client.delete_group_push_mapping.assert_called_once_with(APP_ID, MAPPING_ID, True)

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_declined_delete_does_not_call_api(self, mock_get_client, ctx_elicit_accept_false):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await delete_group_push_mapping(ctx=ctx_elicit_accept_false, app_id=APP_ID, mapping_id=MAPPING_ID)

        client.delete_group_push_mapping.assert_not_called()
        assert "cancelled" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_no_elicitation_returns_confirmation_prompt(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await delete_group_push_mapping(ctx=ctx_no_elicitation, app_id=APP_ID, mapping_id=MAPPING_ID)

        client.delete_group_push_mapping.assert_not_called()
        assert result[0]["confirmation_required"] is True
        assert result[0]["mapping_id"] == MAPPING_ID

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_no_elicitation_with_typed_confirmation_deletes(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.delete_group_push_mapping.return_value = (None, None)
        mock_get_client.return_value = client

        result = await delete_group_push_mapping(
            ctx=ctx_no_elicitation, app_id=APP_ID, mapping_id=MAPPING_ID, confirmation="DELETE"
        )

        client.delete_group_push_mapping.assert_called_once_with(APP_ID, MAPPING_ID, False)
        assert "successfully" in result[0]["message"]

    @pytest.mark.asyncio
    @patch(f"{MODULE}.get_okta_client")
    async def test_api_error_is_surfaced(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group_push_mapping.return_value = (None, "Error: mapping must be INACTIVE")
        mock_get_client.return_value = client

        result = await delete_group_push_mapping(ctx=ctx_elicit_accept_true, app_id=APP_ID, mapping_id=MAPPING_ID)

        assert result == [{"error": "Error: mapping must be INACTIVE"}]
