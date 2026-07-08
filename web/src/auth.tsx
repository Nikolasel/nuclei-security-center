import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Identity } from "./api";

const roleRank: Record<string, number> = { viewer: 1, operator: 2, admin: 3 };

/** hasRole reports whether the identity meets a required role (admin ⊇ operator ⊇ viewer). */
export function hasRole(id: Identity | undefined, required: string): boolean {
  if (!id) return false;
  const need = roleRank[required] ?? 99;
  return id.roles.some((r) => (roleRank[r] ?? 0) >= need);
}

/** useMe loads the current session identity. `null` data means unauthenticated. */
export function useMe() {
  return useQuery({
    queryKey: ["me"],
    retry: false,
    queryFn: async (): Promise<Identity | null> => {
      try {
        return await api.me();
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });
}
