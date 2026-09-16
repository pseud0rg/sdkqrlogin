import { getHandlers } from "../../../../../../server/pseud0";
import type { Pseud0NextRouteContext } from "@pseud0/web-login-adapter-next";

export const runtime = "nodejs";

interface RouteContext {
  params: Promise<{ session: string }>;
}

export async function POST(request: Request, context: RouteContext): Promise<Response> {
  return (await getHandlers()).status.POST(request, context as Pseud0NextRouteContext);
}
