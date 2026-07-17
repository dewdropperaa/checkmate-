/**
 * Safe in-app redirect targets after sign-in (e.g. extension connect flow).
 */

const ALLOWED_NEXT = new Set([
  "/dashboard",
  "/connect-extension",
]);

export const EXTENSION_NEXT_PATH = "/connect-extension";
export const NEXT_QUERY_KEY = "next";
export const EXTENSION_ID_QUERY_KEY = "extensionId";
export const FROM_EXTENSION_QUERY_KEY = "from";

export function isSafeNextPath(path: string | null | undefined): path is string {
  if (!path || !path.startsWith("/") || path.startsWith("//")) {
    return false;
  }
  const pathname = path.split("?")[0]?.split("#")[0] ?? "";
  return ALLOWED_NEXT.has(pathname);
}

export function readAuthRedirectFromSearch(
  search: string,
): { next: string; extensionId: string | null } {
  const params = new URLSearchParams(search);
  const nextRaw = params.get(NEXT_QUERY_KEY);
  const fromExtension = params.get(FROM_EXTENSION_QUERY_KEY) === "extension";
  const extensionId = params.get(EXTENSION_ID_QUERY_KEY)?.trim() || null;

  let next = "/dashboard";
  if (isSafeNextPath(nextRaw)) {
    next = nextRaw.split("?")[0]!;
  } else if (fromExtension) {
    next = EXTENSION_NEXT_PATH;
  }

  if (extensionId && next === EXTENSION_NEXT_PATH) {
    const q = new URLSearchParams({ [EXTENSION_ID_QUERY_KEY]: extensionId });
    return { next: `${next}?${q.toString()}`, extensionId };
  }

  return { next, extensionId };
}

export function buildConnectExtensionPath(extensionId?: string | null): string {
  if (!extensionId?.trim()) {
    return EXTENSION_NEXT_PATH;
  }
  const q = new URLSearchParams({
    [EXTENSION_ID_QUERY_KEY]: extensionId.trim(),
  });
  return `${EXTENSION_NEXT_PATH}?${q.toString()}`;
}
