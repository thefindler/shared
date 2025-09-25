package auth

// RequireRoles creates an AuthRequirement for role-based authorization.
func RequireRoles(roles ...string) *AuthRequirement {
	return &AuthRequirement{RequiredRoles: roles}
}

// RequirePermissions creates an AuthRequirement for permission-based authorization.
func RequirePermissions(permissions ...string) *AuthRequirement {
	return &AuthRequirement{RequiredPermissions: permissions}
}

// RequireRoleAndPermissions creates an AuthRequirement for both role and permission-based authorization.
func RequireRoleAndPermissions(roles []string, permissions []string) *AuthRequirement {
	return &AuthRequirement{
		RequiredRoles:       roles,
		RequiredPermissions: permissions,
	}
}

// RequireAuth creates an AuthRequirement that only requires a valid token, with no specific roles or permissions.
func RequireAuth() *AuthRequirement {
	return &AuthRequirement{}
}
