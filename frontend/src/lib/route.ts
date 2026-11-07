import type { Page } from "../components/Shell";

export interface Route {
  page: Page;
  id: string | null;
  params: URLSearchParams;
}

const PAGES: Page[] = ["overview", "incidents", "incident", "alerts", "logs", "intel", "data", "ask"];

export function parseRoute(hash: string): Route {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?");
  const [page, id] = path.split("/");
  return { page: (PAGES as string[]).includes(page) ? (page as Page) : "overview", id: id ? decodeURIComponent(id) : null, params: new URLSearchParams(query) };
}
