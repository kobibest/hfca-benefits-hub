import "jsr:@supabase/functions-js/edge-runtime.d.ts";

/**
 * Benefits Hub gate — verifies a visitor's national ID against the advisors registry.
 *
 * Deployed to the HFCA project (ref ekpkmqczjplamtadvqgv), NOT to the benefits site's own
 * project. The site lives in a different Supabase project, so it must not carry a key for
 * this one. This function is therefore public (verify_jwt disabled) and is the only door in:
 * it runs with the service role, hands the id to benefits_hub_verify_member, and returns
 * nothing but {ok, name, reason}. Abuse is bounded by the rate limit inside that function,
 * which is why the visitor's address is forwarded explicitly.
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

/* The benefits site, its Vercel preview builds, and local development. */
const ALLOWED_ORIGIN =
  /^https:\/\/([a-z0-9-]+\.)*hfca[a-z0-9-]*\.vercel\.app$|^https:\/\/([a-z0-9-]+\.)*hfca\.org\.il$|^http:\/\/localhost(:\d+)?$|^http:\/\/127\.0\.0\.1(:\d+)?$/;

function cors(origin: string | null): Record<string, string> {
  const h: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
  if (origin && ALLOWED_ORIGIN.test(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}

const json = (body: unknown, status: number, origin: string | null) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors(origin) },
  });

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });
  if (req.method !== "POST") return json({ ok: false, reason: "method" }, 405, origin);

  let id = "";
  try {
    const body = await req.json();
    id = String(body?.id ?? body?.p_id ?? "").replace(/\D/g, "");
  } catch {
    return json({ ok: false, reason: "invalid" }, 400, origin);
  }
  if (id.length < 5 || id.length > 9) return json({ ok: false, reason: "invalid" }, 200, origin);

  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || null;

  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/benefits_hub_verify_member`, {
      method: "POST",
      headers: {
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_id: id, p_ip: ip }),
    });
    if (!res.ok) {
      console.error("rpc failed", res.status, await res.text());
      return json({ ok: false, reason: "server" }, 502, origin);
    }
    const data = await res.json();
    return json(
      { ok: !!data?.ok, name: data?.name ?? "", reason: data?.reason ?? "" },
      200,
      origin,
    );
  } catch (e) {
    console.error("verify-member error", e);
    return json({ ok: false, reason: "server" }, 502, origin);
  }
});
