from lab.contracts import Action, Principal

LISTED = {"read_document", "query_record", "admin_action", "change_role", "tool_output"}
IMPLEMENTED = LISTED | {"capture", "unlisted_debug"}


def authorize(principal: Principal, action: Action, workspace: dict, layer: str) -> str | None:
    """Gateway and service independently enforce these resource invariants."""
    args = action.arguments
    if layer == "gateway" and action.tool not in LISTED:
        return "tool_not_listed"
    if action.tool not in IMPLEMENTED:
        return "unknown_tool"
    if args.get("tenant", principal.tenant) != principal.tenant:
        return "foreign_tenant"
    if action.tool == "read_document":
        resource = workspace["documents"].get(args.get("document_id"))
        if resource and resource["tenant"] != principal.tenant:
            return "foreign_resource"
    if action.tool in {"admin_action", "change_role", "unlisted_debug"}:
        if principal.role != "admin":
            return "admin_required"
    if action.tool == "change_role":
        target = workspace["principals"].get(args.get("principal_id"))
        if target and target["tenant"] != principal.tenant:
            return "foreign_principal"
    if action.tool == "capture":
        return "capture_prohibited"
    return None


def validate_result(tool: str, data: object) -> bool:
    if not isinstance(data, dict) or "authorization" in data:
        return False
    match tool:
        case "read_document":
            return (
                set(data) == {"id", "tenant", "body"}
                and all(isinstance(data[key], str) for key in data)
            )
        case "query_record":
            return set(data) == {"tenant", "record"} and all(
                isinstance(data[key], str) for key in data
            )
        case "admin_action":
            return set(data) == {"tenant", "action", "applied"} and data["applied"] is True
        case "change_role":
            return set(data) == {"principal_id", "role"} and data["role"] in {"reader", "admin"}
        case "tool_output":
            return set(data) == {"message", "suggested_actions"} and (
                isinstance(data["message"], str)
                and isinstance(data["suggested_actions"], list)
                and all(isinstance(action, dict) for action in data["suggested_actions"])
            )
        case _:
            return False

