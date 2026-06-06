// Agent A Cedar Policy
// Agent A (Requester) - read:events scope only

permit (
    principal,
    action in [A2A::ReadEvent],
    resource
)
when {
    principal.id == "agent-a" &&
    principal.org == "tonyai-org" &&
    "read:events" in principal.scopes
};
