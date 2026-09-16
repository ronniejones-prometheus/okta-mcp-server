# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Application group assignment tools.

Wraps the Application Groups API
(``/api/v1/apps/{appId}/groups[/{groupId}]``): list, get, assign and
unassign the Okta groups that grant users access to an application.
"""

from typing import Any, Dict, Optional

import okta.models as okta_models
from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import UNASSIGN_GROUP_FROM_APPLICATION
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, extract_after_cursor, paginate_all_results
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response, none_body_error
from okta_mcp_server.utils.validation import validate_ids

#: The Application Groups API accepts 20 <= limit <= 200 per page.
_MIN_LIMIT = 20
_MAX_LIMIT = 200


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


@mcp.tool()
@require_scopes("okta.apps.read")
@validate_ids("app_id", error_return_type="dict")
@json_response
async def list_application_group_assignments(
    ctx: Context,
    app_id: str,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    expand: Optional[str] = None,
    fetch_all: bool = False,
) -> dict:
    """List the groups assigned to an application.

    This is the app-side view of assignments (which groups grant access to
    this app). For the group-side view (which apps a group is assigned to)
    use list_group_apps.

    Parameters:
        app_id (str, required): The ID of the application
        q (str, optional): Filters assigned groups whose name starts with this value
        after (str, optional): Pagination cursor for the next page of results
        limit (int, optional): Number of assignments per page (min 20, max 200)
        expand (str, optional): Set to "group" to embed each group's profile, or
            "metadata" to embed assignment metadata, in ``_embedded``
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.

    Examples:
        - First call: list_application_group_assignments(app_id="0oa...")
        - Next page: list_application_group_assignments(app_id="0oa...", after="cursor_value")
        - All pages: list_application_group_assignments(app_id="0oa...", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of application group assignment objects (each has the group ``id``,
          optional ``priority`` and app-specific ``profile``)
        - total_fetched: Number of assignments returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Listing group assignments for application {app_id}")
    logger.debug(f"Query parameters: q='{q}', limit={limit}, expand='{expand}', fetch_all={fetch_all}")

    limit = _clamp_limit(limit)
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(q=q, after=after, limit=limit, expand=expand)

        logger.debug(f"Calling Okta API to list group assignments for application {app_id}")
        assignments, response, err = await client.list_application_group_assignments(app_id, **query_params)

        if err:
            logger.error(f"Okta API error while listing group assignments for application {app_id}: {err}")
            return {"error": str(err)}

        if not assignments:
            logger.info(f"No groups assigned to application {app_id}")
            return create_paginated_response([], response, fetch_all)

        count = len(assignments)
        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {count} assignments")

            async def _next_page(cursor):
                p = dict(query_params)
                p["after"] = cursor
                return await client.list_application_group_assignments(app_id, **p)

            async def _on_page(pages, total):
                await ctx.info(f"Fetching group assignments... {total} fetched so far ({pages} pages)")

            all_assignments, pagination_info = await paginate_all_results(
                response, assignments, next_page_fn=_next_page, on_page=_on_page
            )
            logger.info(
                f"Successfully retrieved {len(all_assignments)} group assignments for application {app_id} "
                f"across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_assignments, response, fetch_all_used=True, pagination_info=pagination_info
            )

        logger.info(f"Successfully retrieved {count} group assignments for application {app_id}")
        return create_paginated_response(assignments, response, fetch_all_used=fetch_all)
    except Exception as e:
        logger.error(f"Exception while listing group assignments for application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.read")
@validate_ids("app_id", "group_id", error_return_type="dict")
@json_response
async def get_application_group_assignment(
    ctx: Context, app_id: str, group_id: str, expand: Optional[str] = None
) -> Any:
    """Get a single group assignment for an application.

    Parameters:
        app_id (str, required): The ID of the application
        group_id (str, required): The ID of the assigned group
        expand (str, optional): Set to "group" to embed the group's profile, or
            "metadata" to embed assignment metadata, in ``_embedded``

    Returns:
        Dictionary containing the assignment (group ``id``, ``priority``, app-specific
        ``profile``) or error information. A 404 means the group is not assigned.
    """
    logger.info(f"Getting assignment of group {group_id} for application {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(expand=expand)

        assignment, _, err = await client.get_application_group_assignment(app_id, group_id, **query_params)

        if err:
            logger.error(f"Okta API error while getting assignment of group {group_id} for application {app_id}: {err}")
            return {"error": str(err)}

        if assignment is None:
            return none_body_error(
                "get_application_group_assignment",
                f"retrieving the assignment of group {group_id!r} for application {app_id!r}",
                "Verify the IDs with list_application_group_assignments().",
            )

        logger.info(f"Successfully retrieved assignment of group {group_id} for application {app_id}")
        return assignment
    except Exception as e:
        logger.error(
            f"Exception while getting assignment of group {group_id} for application {app_id}: {type(e).__name__}: {e}"
        )
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage")
@validate_ids("app_id", "group_id", error_return_type="dict")
@json_response
async def assign_group_to_application(
    ctx: Context,
    app_id: str,
    group_id: str,
    priority: Optional[int] = None,
    profile: Optional[Dict[str, Any]] = None,
) -> Any:
    """Assign a group to an application, granting all group members access.

    Calling this for a group that is already assigned updates the assignment
    (``PUT`` semantics), so it is safe to retry.

    Parameters:
        app_id (str, required): The ID of the application
        group_id (str, required): The ID of the group to assign
        priority (int, optional): Assignment priority. When a user is assigned via
            several groups, the lowest number wins for conflicting profile attributes.
        profile (dict, optional): App-specific profile attributes applied to every
            member assigned through this group (for example a role or license tier
            in the downstream app). Attribute names depend on the app's schema.

    Returns:
        Dictionary containing the created or updated assignment, or error information.
    """
    logger.info(f"Assigning group {group_id} to application {app_id}")
    logger.debug(f"Assignment options: priority={priority}, profile_keys={sorted(profile) if profile else []}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        assignment_body = okta_models.ApplicationGroupAssignment(priority=priority, profile=profile)

        logger.debug(f"Calling Okta API to assign group {group_id} to application {app_id}")
        assignment, _, err = await client.assign_group_to_application(app_id, group_id, assignment_body)

        if err:
            logger.error(f"Okta API error while assigning group {group_id} to application {app_id}: {err}")
            return {"error": str(err)}

        if assignment is None:
            return none_body_error(
                "assign_group_to_application",
                f"assigning group {group_id!r} to application {app_id!r}",
                "Confirm with get_application_group_assignment().",
            )

        logger.info(f"Successfully assigned group {group_id} to application {app_id}")
        return assignment
    except Exception as e:
        logger.error(f"Exception while assigning group {group_id} to application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.apps.manage", error_return_type="list")
@validate_ids("app_id", "group_id")
@json_response
async def unassign_group_from_application(
    ctx: Context, app_id: str, group_id: str, confirmation: Optional[str] = None
) -> list:
    """Remove a group's assignment from an application.

    Members of the group lose the access granted through this assignment
    (they keep access if they are also assigned directly or via another
    group). If the app has provisioning enabled, Okta may deprovision the
    affected users in the downstream app. The user will be asked for
    confirmation before the removal proceeds.

    Parameters:
        app_id (str, required): The ID of the application
        group_id (str, required): The ID of the group to unassign
        confirmation (str, optional): Only for clients without MCP elicitation support: pass
            "UNASSIGN" to confirm after the tool has asked for confirmation. NEVER set this
            automatically — the human user must explicitly confirm.

    Returns:
        List containing the result of the removal operation.
    """
    logger.warning(f"Unassignment requested for group {group_id} from application {app_id}")

    fallback_payload = {
        "confirmation_required": True,
        "message": (
            f"To confirm unassigning group {group_id} from application {app_id}, call "
            f"'unassign_group_from_application' again with the same arguments and confirmation='UNASSIGN'. "
            f"Members of the group will lose the access granted through this assignment."
        ),
        "app_id": app_id,
        "group_id": group_id,
    }

    if confirmation != "UNASSIGN":
        outcome = await elicit_or_fallback(
            ctx,
            message=UNASSIGN_GROUP_FROM_APPLICATION.format(app_id=app_id, group_id=group_id),
            schema=DeleteConfirmation,
            fallback_payload=fallback_payload,
        )

        if not outcome.used_elicitation:
            logger.info(
                f"Elicitation unavailable for unassigning group {group_id} from application {app_id} — "
                f"returning fallback confirmation prompt"
            )
            return [outcome.fallback_response]

        if not outcome.confirmed:
            logger.info(f"Unassignment of group {group_id} from application {app_id} cancelled by user")
            return [{"message": "Group unassignment cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to unassign group {group_id} from application {app_id}")

        result = await client.unassign_application_from_group(app_id, group_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while unassigning group {group_id} from application {app_id}: {err}")
            return [{"error": str(err)}]

        logger.info(f"Successfully unassigned group {group_id} from application {app_id}")
        return [{"message": f"Group {group_id} unassigned from application {app_id} successfully"}]
    except Exception as e:
        logger.error(
            f"Exception while unassigning group {group_id} from application {app_id}: {type(e).__name__}: {e}"
        )
        return [{"exception": str(e)}]
