// Agent B Cedar Policy
// Agent B (Responder) - write:events scope only

permit (
    principal,
    action in [A2A::WriteEvent],
    resource
)
when {
    principal.id == "agent-b" &&
    principal.org == "tonyai-org" &&
    "write:events" in principal.scopes
};
