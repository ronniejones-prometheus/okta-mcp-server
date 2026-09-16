# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Group push mapping tools.

Wraps the Group Push Mappings API
(``/api/v1/apps/{appId}/group-push/mappings[/{mappingId}]``). A group push
mapping links an Okta source group to a group in a provisioning-enabled
downstream app so that Okta pushes membership changes to it.

Okta requires both an ``okta.apps.*`` and an ``okta.groups.*`` scope for
every group push operation; ``require_scopes`` enforces both.
"""

from typing import Any, Dict, Optional

import okta.models as okta_models
from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_GROUP_PUSH_MAPPING
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response, none_body_error
from okta_mcp_server.utils.validation import validate_ids

#: The Group Push Mappings API accepts 1 <= limit <= 1000 per page.
_MIN_LIMIT = 1
_MAX_LIMIT = 1000

#: Statuses accepted when creating or updating a mapping (ERROR is read-only).
_UPSERT_STATUSES = frozenset(s.value for s in okta_models.GroupPushMappingStatusUpsert)
#: Statuses accepted as a list filter.
_FILTER_STATUSES = frozenset(s.value for s in okta_models.GroupPushMappingStatus)


def _clamp_limit(limit: Optional[int]) -> Optional[int]:
    if limit is None:
        return None
    if limit < _MIN_LIMIT:
        logger.warning(f"Limit {limit} is below minimum ({_MIN_LIMIT}), setting to {_MIN_LIMIT}")
        return _MIN_LIMIT
    if limit > _MAX_LIMIT:
        logger.warning(f"Limit {limit} exceeds maximum ({_MAX_LIMIT}), setting to {_MAX_LIMIT}")
        return _MAX_LIMIT
    return limit


def _normalize_status(status: Optional[str], allowed: frozenset) -> Optional[str]:
    """Upper-case ``status`` and return it, or ``None`` if it is not in ``allowed``.

    Callers must treat ``None`` for a non-empty input as a validation failure.
    """
    if status is None or status == "":
        return None
    normalized = str(status).strip().upper()
    return normalized if normalized in allowed else None


def _build_app_config(app_config: Dict[str, Any]) -> Any:
    """Convert a plain ``appConfig`` dict to the matching typed SDK model.

    ``AppConfig`` is a discriminated base whose only field is ``type``; the
    SDK's own ``AppConfig.from_dict`` drops every other field for Active
    Directory configs, so select the subclass explicitly.
    """
    config_type = str(app_config.get("type", "")).upper()
    if config_type == "ACTIVE_DIRECTORY":
        return okta_models.AppConfigActiveDirectory.model_validate(app_config)
    return okta_models.AppConfig.model_validate(app_config)


@mcp.tool()
@require_scopes("okta.apps.read", "okta.groups.read")
@validate_ids("app_id", error_return_type="dict")
@json_response
async def list_group_push_mappings(
    ctx: Context,
    app_id: str,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    last_updated: Optional[str] = None,
    source_group_id: Optional[str] = None,
    status: Optional[str] = None,
    fetch_all: bool = False,
) -> dict:
    """List the group push mappings configured on an application.

    The app must have provisioning enabled; apps without provisioning have no
    mappings. Each mapping links an Okta source group to a target group in
    the downstream app.

    Parameters:
        app_id (str, required): The ID of the application
        after (str, optional): Pagination cursor for the next page of results
        limit (int, optional): Number of mappings per page (min 1, max 1000)
        last_updated (str, optional): Only return mappings updated on or after this
            UTC timestamp, formatted ``YYYY-MM-DDTHH:mm:ssZ``
        source_group_id (str, optional): Only return the mapping for this Okta source group
        status (str, optional): Only return mappings with this status: ACTIVE, INACTIVE or ERROR
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.

    Examples:
        - First call: list_group_push_mappings(app_id="0oa...")
        - Only broken mappings: list_group_push_mappings(app_id="0oa...", status="ERROR")
        - All pages: list_group_push_mappings(app_id="0oa...", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of group push mapping objects (``id``, ``sourceGroupId``,
          ``targetGroupId``, ``status``, ``lastPush``, ``errorSummary``)
        - total_fetched: Number of mappings returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Listing group push mappings for application {app_id}")
    logger.debug(
        f"Query parameters: limit={limit}, last_updated='{last_updated}', "
        f"source_group_id='{source_group_id}', status='{status}', fetch_all={fetch_all}"
    )

    status_filter = None
    if status:
        normalized = _normalize_status(status, _FILTER_STATUSES)
        if normalized is None:
            return {"error": f"Invalid status {status!r}. Expected one of: {', '.join(sorted(_FILTER_STATUSES))}."}
        status_filter = okta_models.GroupPushMappingStatus(normalized)

    limit = _clamp_limit(limit)
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(
            after=after, limit=limit, last_updated=last_updated, source_group_id=source_group_id, status=status_filter
        )

        logger.debug(f"Calling Okta API to list group push mappings for application {app_id}")
        mappings, response, err = await client.list_group_push_mappings(app_id, **query_params)

        if err:
            logger.error(f"Okta API error while listing group push mappings for application {app_id}: {err}")
            return {"error": str(err)}

        if not mappings:
            logger.info(f"No group push mappings found for application {app_id}")
            return create_paginated_response([], response, fetch_all)

        count = len(mappings)
        has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {count} mappings")

            async def _next_page(cursor):
                p = dict(query_params)
                p["after"] = cursor
                return await client.list_group_push_mappings(app_id, **p)

            async def _on_page(pages, total):
                await ctx.info(f"Fetching group push mappings... {total} fetched so far ({pages} pages)")

            all_mappings, pagination_info = await paginate_all_results(
                response, mappings, next_page_fn=_next_page, on_page=_on_page
            )
            logger.info(
                f"Successfully retrieved {len(all_mappings)} group push mappings for application {app_id} "
                f"across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_mappings, response, fetch_all_used=True, pagination_info=pagination_info
            )

        logger.info(f"Successfully retrieved {count} group push mappings for application {app_id}")
        return create_paginated_response(mappings, response, fetch_all_used=fetch_all)
    except Exception as e:
        logger.error(f"Exception while listing group push mappings for application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.read", "okta.groups.read")
@validate_ids("app_id", "mapping_id", error_return_type="dict")
@json_response
async def get_group_push_mapping(ctx: Context, app_id: str, mapping_id: str) -> Any:
    """Get a single group push mapping by ID.

    Parameters:
        app_id (str, required): The ID of the application
        mapping_id (str, required): The ID of the group push mapping (from list_group_push_mappings)

    Returns:
        Dictionary containing the mapping (``sourceGroupId``, ``targetGroupId``, ``status``,
        ``lastPush``, ``errorSummary``) or error information.
    """
    logger.info(f"Getting group push mapping {mapping_id} for application {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        mapping, _, err = await client.get_group_push_mapping(app_id, mapping_id)

        if err:
            logger.error(
                f"Okta API error while getting group push mapping {mapping_id} for application {app_id}: {err}"
            )
            return {"error": str(err)}

        if mapping is None:
            return none_body_error(
                "get_group_push_mapping",
                f"retrieving group push mapping {mapping_id!r} for application {app_id!r}",
                "Verify the IDs with list_group_push_mappings().",
            )

        logger.info(f"Successfully retrieved group push mapping {mapping_id} for application {app_id}")
        return mapping
    except Exception as e:
        logger.error(
            f"Exception while getting group push mapping {mapping_id} for application {app_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage", "okta.groups.manage")
@validate_ids("app_id", "source_group_id", error_return_type="dict")
@json_response
async def create_group_push_mapping(
    ctx: Context,
    app_id: str,
    source_group_id: str,
    target_group_id: Optional[str] = None,
    target_group_name: Optional[str] = None,
    status: str = "ACTIVE",
    app_config: Optional[Dict[str, Any]] = None,
) -> Any:
    """Create a group push mapping from an Okta group to a group in a provisioning-enabled app.

    Exactly one of ``target_group_id`` or ``target_group_name`` must be given:
    - ``target_group_id`` links the mapping to an existing group already imported
      from the app (its Okta ``id``, found via list_groups — these have
      ``type == "APP_GROUP"`` and are sourced from the app).
    - ``target_group_name`` creates a new group in the downstream app with that
      name (or links to it if a group by that name already exists).

    The source group is usually also assigned to the app (see
    assign_group_to_application) so its members are provisioned there.

    Parameters:
        app_id (str, required): The ID of the provisioning-enabled application
        source_group_id (str, required): The ID of the Okta source group whose membership is pushed
        target_group_id (str, optional): The ID of an existing app group to link to
        target_group_name (str, optional): The name of the group to create in the downstream app
        status (str, optional): ACTIVE (push immediately, default) or INACTIVE (create paused)
        app_config (dict, optional): Additional app-specific configuration. Currently only
            required for Active Directory targets, e.g.
            {"type": "ACTIVE_DIRECTORY", "distinguishedName": "CN=...,OU=...,DC=...",
             "groupScope": "DOMAIN_LOCAL", "groupType": "SECURITY", "samAccountName": "..."}

    Returns:
        Dictionary containing the created mapping or error information.
    """
    logger.info(f"Creating group push mapping for application {app_id} from source group {source_group_id}")
    logger.debug(
        f"Options: target_group_id='{target_group_id}', target_group_name='{target_group_name}', "
        f"status='{status}', app_config_keys={sorted(app_config) if app_config else []}"
    )

    if bool(target_group_id) == bool(target_group_name):
        return {
            "error": (
                "Provide exactly one of target_group_id (link to an existing app group) "
                "or target_group_name (create a new group in the app)."
            )
        }

    normalized_status = _normalize_status(status, _UPSERT_STATUSES)
    if normalized_status is None:
        return {"error": f"Invalid status {status!r}. Expected one of: {', '.join(sorted(_UPSERT_STATUSES))}."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        request_body = okta_models.CreateGroupPushMappingRequest(
            source_group_id=source_group_id,
            target_group_id=target_group_id or None,
            target_group_name=target_group_name or None,
            status=okta_models.GroupPushMappingStatusUpsert(normalized_status),
            app_config=_build_app_config(app_config) if app_config else None,
        )

        logger.debug(f"Calling Okta API to create group push mapping for application {app_id}")
        mapping, _, err = await client.create_group_push_mapping(app_id, request_body)

        if err:
            logger.error(f"Okta API error while creating group push mapping for application {app_id}: {err}")
            return {"error": str(err)}

        if mapping is None:
            return none_body_error(
                "create_group_push_mapping",
                f"creating a group push mapping for application {app_id!r}",
                "Use list_group_push_mappings() to confirm and retrieve the new mapping.",
            )

        logger.info(f"Successfully created group push mapping for application {app_id} from group {source_group_id}")
        return mapping
    except Exception as e:
        logger.error(f"Exception while creating group push mapping for application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage", "okta.groups.manage")
@validate_ids("app_id", "mapping_id", error_return_type="dict")
@json_response
async def update_group_push_mapping(ctx: Context, app_id: str, mapping_id: str, status: str) -> Any:
    """Activate or deactivate a group push mapping.

    Deactivating pauses pushes (the target group keeps its current members).
    A mapping must be INACTIVE (or in ERROR) before it can be deleted.

    Parameters:
        app_id (str, required): The ID of the application
        mapping_id (str, required): The ID of the group push mapping
        status (str, required): The new status: ACTIVE or INACTIVE

    Returns:
        Dictionary containing the updated mapping or error information.
    """
    logger.info(f"Updating group push mapping {mapping_id} for application {app_id} to status '{status}'")

    normalized_status = _normalize_status(status, _UPSERT_STATUSES)
    if normalized_status is None:
        return {"error": f"Invalid status {status!r}. Expected one of: {', '.join(sorted(_UPSERT_STATUSES))}."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        request_body = okta_models.UpdateGroupPushMappingRequest(status=normalized_status)

        logger.debug(f"Calling Okta API to update group push mapping {mapping_id} for application {app_id}")
        mapping, _, err = await client.update_group_push_mapping(app_id, mapping_id, request_body)

        if err:
            logger.error(
                f"Okta API error while updating group push mapping {mapping_id} for application {app_id}: {err}"
            )
            return {"error": str(err)}

        if mapping is None:
            return none_body_error(
                "update_group_push_mapping",
                f"updating group push mapping {mapping_id!r} for application {app_id!r}",
                "Re-fetch with get_group_push_mapping() to confirm the current state.",
            )

        logger.info(f"Successfully updated group push mapping {mapping_id} for application {app_id}")
        return mapping
    except Exception as e:
        logger.error(
            f"Exception while updating group push mapping {mapping_id} for application {app_id}: "
            f"{type(e).__name__}: {e}"
        )
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage", "okta.groups.manage", error_return_type="list")
@validate_ids("app_id", "mapping_id")
@json_response
async def delete_group_push_mapping(
    ctx: Context,
    app_id: str,
    mapping_id: str,
    delete_target_group: bool = False,
    confirmation: Optional[str] = None,
) -> list:
    """Delete a group push mapping, optionally deleting the target group in the downstream app.

    Okta only deletes mappings that are INACTIVE or in ERROR — deactivate an
    ACTIVE mapping first with update_group_push_mapping(status="INACTIVE").
    The user will be asked for confirmation before the deletion proceeds.

    Parameters:
        app_id (str, required): The ID of the application
        mapping_id (str, required): The ID of the group push mapping to delete
        delete_target_group (bool, optional): If True, also delete the target group in the
            downstream app. If False (default), the target group is left in place and merely unlinked.
        confirmation (str, optional): Only for clients without MCP elicitation support: pass
            "DELETE" to confirm after the tool has asked for confirmation. NEVER set this
            automatically — the human user must explicitly confirm.

    Returns:
        List containing the result of the deletion operation.
    """
    logger.warning(
        f"Deletion requested for group push mapping {mapping_id} on application {app_id} "
        f"(delete_target_group={delete_target_group})"
    )

    target_note = (
        " The target group in the downstream app will ALSO be deleted."
        if delete_target_group
        else " The target group in the downstream app is kept."
    )
    fallback_payload = {
        "confirmation_required": True,
        "message": (
            f"To confirm deletion of group push mapping {mapping_id} on application {app_id}, call "
            f"'delete_group_push_mapping' again with the same arguments and confirmation='DELETE'.{target_note}"
        ),
        "app_id": app_id,
        "mapping_id": mapping_id,
        "delete_target_group": delete_target_group,
    }

    if confirmation != "DELETE":
        outcome = await elicit_or_fallback(
            ctx,
            message=DELETE_GROUP_PUSH_MAPPING.format(mapping_id=mapping_id, app_id=app_id, target_note=target_note),
            schema=DeleteConfirmation,
            fallback_payload=fallback_payload,
        )

        if not outcome.used_elicitation:
            logger.info(
                f"Elicitation unavailable for group push mapping {mapping_id} — returning fallback confirmation prompt"
            )
            return [outcome.fallback_response]

        if not outcome.confirmed:
            logger.info(f"Deletion of group push mapping {mapping_id} cancelled by user")
            return [{"message": "Group push mapping deletion cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete group push mapping {mapping_id} for application {app_id}")

        result = await client.delete_group_push_mapping(app_id, mapping_id, delete_target_group)
        err = result[-1]

        if err:
            logger.error(
                f"Okta API error while deleting group push mapping {mapping_id} for application {app_id}: {err}"
            )
            return [{"error": str(err)}]

        logger.info(f"Successfully deleted group push mapping {mapping_id} for application {app_id}")
        return [{"message": f"Group push mapping {mapping_id} deleted from application {app_id} successfully"}]
    except Exception as e:
        logger.error(
            f"Exception while deleting group push mapping {mapping_id} for application {app_id}: "
            f"{type(e).__name__}: {e}"
        )
        return [{"exception": str(e)}]
