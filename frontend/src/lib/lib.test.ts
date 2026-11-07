import { describe, expect, it } from "vitest";
import { citationParts, duration, linkCitations, list, plural } from "./format";
import { parseRoute } from "./route";

describe("routes", () => {
  it("reads the page, id and query from the hash", () => {
    expect(parseRoute("#/incident/ab12").page).toBe("incident");
    expect(parseRoute("#/incident/ab12").id).toBe("ab12");
    const r = parseRoute("#/logs?ip=203.0.113.45&user=root");
    expect(r.page).toBe("logs");
    expect(r.params.get("ip")).toBe("203.0.113.45");
    expect(parseRoute("").page).toBe("overview");
    expect(parseRoute("#/nonsense").page).toBe("overview");
  });
});

describe("formatting", () => {
  it("joins lists the way people write them", () => {
    expect(list(["Linux"])).toBe("Linux");
    expect(list(["Firewall", "Linux", "Web server"])).toBe("Firewall, Linux and Web server");
  });
  it("pluralises and describes durations", () => {
    expect(plural(1, "alert")).toBe("1 alert");
    expect(plural(1200, "event")).toBe("1,200 events");
    expect(duration(0, 45)).toBe("45 s");
    expect(duration(0, 3 * 3600 + 20 * 60)).toBe("3 h 20 min");
  });
  it("turns [E12] citations into links and parts", () => {
    expect(linkCitations("seen [E12] and [E7]")).toBe("seen [E12](#event-12) and [E7](#event-7)");
    expect(citationParts("a [E3] b")).toEqual(["a ", 3, " b"]);
  });
});
