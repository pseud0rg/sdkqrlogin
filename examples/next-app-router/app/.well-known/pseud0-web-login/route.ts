import { getHandlers } from "../../../server/pseud0";

export const runtime = "nodejs";

export async function GET(request: Request): Promise<Response> {
  return (await getHandlers()).metadata.GET(request);
}
