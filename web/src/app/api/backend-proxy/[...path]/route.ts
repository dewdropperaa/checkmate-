import { proxyBackendRequest } from "@/lib/backendProxy";
import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

async function handle(
  request: NextRequest,
  context: RouteContext,
): Promise<Response> {
  const { path } = await context.params;
  if (!path?.length) {
    return proxyBackendRequest(request, "");
  }
  return proxyBackendRequest(request, path.join("/"));
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const OPTIONS = handle;
export const HEAD = handle;
