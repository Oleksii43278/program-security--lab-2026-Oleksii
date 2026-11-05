from dataclasses import dataclass

ROLES = ["viewer", "maintainer", "owner"]
CRITICAL_OPS = {"add-user", "set-role", "passwd", "enroll-totp", "sign"}
STEPUP_WINDOW_S = 300  # 5 хвилин для step-up автентифікації

@dataclass
class Decision:
    allow: bool
    reason: str

def role_level(roles: list[str]) -> int:
    return max([ROLES.index(r) for r in roles if r in ROLES], default=-1)

def authorize(roles: list[str], operation: str, target_user: str = None,
              current_user: str = None, session_stepup_age: float = 0.0,
              repo_state: dict = None) -> Decision:
    max_role = role_level(roles)
    if max_role == -1:
        return Decision(False, "authz-deny:unknown-role")

    # 1. DAC
    if operation in ["passwd", "enroll-totp"] and target_user == current_user:
        pass
    else:
        # 2. RBAC
        if operation in ["list-users", "status"]:
            if max_role < ROLES.index("viewer"):
                return Decision(False, f"authz-deny:{operation}:rbac")
        elif operation in ["add-user", "set-role", "rotate-key"]:
            if max_role < ROLES.index("owner"):
                return Decision(False, f"authz-deny:{operation}:rbac")
        elif operation == "passwd":
            if max_role < ROLES.index("owner"):
                return Decision(False, f"authz-deny:passwd:not-owner")
        elif operation == "enroll-totp":
            return Decision(False, f"authz-deny:enroll-totp:not-owner")
        # Нові команди
        elif operation in ["build-manifest", "verify"]:
            if max_role < ROLES.index("owner"):
                return Decision(False, f"authz-deny:{operation}:rbac")
        elif operation == "sign":
            if max_role < ROLES.index("owner"):
                return Decision(False, f"authz-deny:sign:rbac")
            # ABAC-умова: підписуємо тільки якщо гілка master і дерево чисте
            if repo_state:
                if repo_state.get('branch') != 'master':
                    return Decision(False, "authz-deny:sign:abac-not-master")
                if repo_state.get('is_dirty'):
                    return Decision(False, "authz-deny:sign:abac-dirty")
        else:
            return Decision(False, f"authz-deny:unknown-operation:{operation}")

    # 3. ABAC (Step-up)
    if operation in CRITICAL_OPS:
        if session_stepup_age > STEPUP_WINDOW_S:
            return Decision(False, f"authz-deny:{operation}:stepup-required")

    return Decision(True, f"authz-allow:{operation}")