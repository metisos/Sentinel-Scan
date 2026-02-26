import { type ModuleName, type OutputFormat, ALL_MODULES } from "./models.js";

export interface ScanCallbacks {
  onModuleStart?: (module: ModuleName) => void;
  onModuleComplete?: (module: ModuleName, durationMs: number) => void;
  onFinding?: (module: ModuleName, title: string) => void;
}

export class ScanContext {
  readonly modules: ModuleName[];
  readonly format: OutputFormat;
  readonly interactive: boolean;
  readonly noBanner: boolean;
  readonly callbacks: ScanCallbacks;

  constructor(opts: {
    modules?: ModuleName[];
    format?: OutputFormat;
    noBanner?: boolean;
    callbacks?: ScanCallbacks;
  } = {}) {
    this.modules = opts.modules ?? [...ALL_MODULES];
    this.format = opts.format ?? "terminal";
    this.noBanner = opts.noBanner ?? false;
    this.interactive =
      this.format === "terminal" && process.stdout.isTTY === true;
    this.callbacks = opts.callbacks ?? {};
  }
}
