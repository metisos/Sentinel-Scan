import type { ModuleName } from "../core/models.js";

export interface CollectorResult {
  module: ModuleName;
  data: Record<string, unknown>;
  raw: string;
}

export abstract class BaseCollector {
  abstract readonly module: ModuleName;
  abstract collect(): Promise<CollectorResult>;
}
