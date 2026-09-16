import { canonicalDevelopmentSessionRequest, getHandlers } from "../../../../server/pseud0";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  return (await getHandlers()).sessions.POST(canonicalDevelopmentSessionRequest(request));
}
