import { approveLatest } from "../../../server/pseud0";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  try {
    await approveLatest(request);
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  } catch {
    return Response.json(
      { code: "local_approval_failed" },
      { status: 409, headers: { "cache-control": "no-store" } },
    );
  }
}
