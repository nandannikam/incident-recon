import type { Incident } from "./types";

/**
 * Backend base URL. Override with VITE_API_BASE_URL in a `.env` file
 * (see `.env` note in README/report) — defaults to the local FastAPI.
 */
const API = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

/** Just the host:port of the backend, for display in the footer. */
export const API_HOST = (() => {
  try {
    return new URL(API).host;
  } catch {
    return API;
  }
})();

/** Pull a human-readable message out of a FastAPI error body, if any. */
async function extractDetail(res: Response): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
      return JSON.stringify(detail);
    }
  } catch {
    /* body was not JSON — fall through */
  }
  return "";
}

function networkError(err: unknown): Error {
  void err;
  return new Error(
    `Could not reach the analysis API at ${API}. ` +
      "Make sure the backend is running (uvicorn on :8000) and allows the origin http://localhost:5173.",
  );
}

/**
 * POST multipart /analyze. The field name MUST be "file" to match the
 * backend parameter, and we must NOT set Content-Type manually — the
 * browser needs to generate the multipart boundary for CORS to pass.
 */
export async function analyzeCsv(file: File): Promise<Incident> {
  const formData = new FormData();
  formData.append("file", file);

  let res: Response;
  try {
    res = await fetch(`${API}/analyze`, { method: "POST", body: formData });
  } catch (err) {
    throw networkError(err);
  }

  if (!res.ok) {
    const detail = await extractDetail(res);
    if (res.status === 413) {
      throw new Error(
        `File too large — the server accepts up to 50 MB.${detail ? ` (${detail})` : ""}`,
      );
    }
    if (res.status === 400 || res.status === 415 || res.status === 422) {
      throw new Error(
        `The server rejected this file${detail ? `: ${detail}` : "."}`,
      );
    }
    throw new Error(
      `Analysis failed with HTTP ${res.status}${detail ? ` — ${detail}` : "."}`,
    );
  }

  return (await res.json()) as Incident;
}

/** GET /incident/{id} — fetch a previously analyzed incident. */
export async function getIncident(id: string): Promise<Incident> {
  let res: Response;
  try {
    res = await fetch(`${API}/incident/${encodeURIComponent(id)}`);
  } catch (err) {
    throw networkError(err);
  }

  if (!res.ok) {
    const detail = await extractDetail(res);
    if (res.status === 404) {
      throw new Error(
        `No incident found with id "${id}".${detail ? ` (${detail})` : ""}`,
      );
    }
    throw new Error(
      `Fetching incident failed with HTTP ${res.status}${detail ? ` — ${detail}` : "."}`,
    );
  }

  return (await res.json()) as Incident;
}
