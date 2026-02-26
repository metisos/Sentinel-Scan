import type { Finding, ModuleName } from "../core/models.js";
import type { CollectorResult } from "../collectors/base.js";
import type { ThreatDB } from "../threats/index.js";

export abstract class BaseAnalyzer {
  abstract readonly module: ModuleName;
  abstract analyze(data: CollectorResult, threatDB: ThreatDB): Finding[];
}
