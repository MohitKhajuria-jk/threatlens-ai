/** Parses a text/event-stream body into { event, data } pairs as chunks arrive. */
export class SseParser {
  private buffer = "";

  push(chunk: string): Array<{ event: string; data: unknown }> {
    this.buffer += chunk.replace(/\r\n/g, "\n");
    const out: Array<{ event: string; data: unknown }> = [];
    let end: number;
    while ((end = this.buffer.indexOf("\n\n")) !== -1) {
      const block = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end + 2);
      let event = "message";
      const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      }
      if (!data.length) continue;
      try {
        out.push({ event, data: JSON.parse(data.join("\n")) });
      } catch {
        out.push({ event, data: data.join("\n") });
      }
    }
    return out;
  }
}
