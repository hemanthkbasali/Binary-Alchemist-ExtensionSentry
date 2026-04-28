from .services import get_active_organization


def active_organization(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {"active_organization": None, "user_memberships": []}
    memberships = request.user.memberships.select_related("organization")
    return {
        "active_organization": get_active_organization(request),
        "user_memberships": memberships,
    }
