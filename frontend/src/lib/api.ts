/** Minimal typed JSON POST helper.
 *
 * All mutation endpoints require a JSON Content-Type (the server's CSRF gate)
 * and same-origin fetch supplies Sec-Fetch-Site automatically. */
export interface ApiResult<T> {
  ok: boolean;
  status: number;
  data: T;
}

export async function postJSON<T = Record<string, unknown>>(
  path: string,
  body: Record<string, unknown>,
): Promise<ApiResult<T>> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data: T;
  try {
    data = (await r.json()) as T;
  } catch {
    data = {} as T;
  }
  return { ok: r.ok, status: r.status, data };
}
