import type { ScanResult, OutputFormat } from "../core/models.js";
import { renderTerminal } from "./terminal.js";
import { renderJSON } from "./json.js";
import { renderMarkdown } from "./markdown.js";

export function renderReport(result: ScanResult, format: OutputFormat): string {
  switch (format) {
    case "json":
      return renderJSON(result);
    case "markdown":
      return renderMarkdown(result);
    case "terminal":
    default:
      return renderTerminal(result);
  }
}

export { renderTerminal } from "./terminal.js";
export { renderJSON } from "./json.js";
export { renderMarkdown } from "./markdown.js";
