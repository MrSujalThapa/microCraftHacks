export function printSectionHeader(title: string): void {
  const line = "─".repeat(Math.max(title.length + 4, 40));
  console.log("");
  console.log(line);
  console.log(`  ${title}`);
  console.log(line);
}

export function printMetric(label: string, value: string | number): void {
  console.log(`  ${label}: ${value}`);
}

export interface RuntimeMetricsSummary {
  elapsedMs?: number;
  cacheHit?: boolean;
  scanHash?: string;
  modelCalls?: number;
  tokens?: number;
  mode?: string;
  provider?: string;
  model?: string;
}

export function printRuntimeMetrics(metrics: RuntimeMetricsSummary): void {
  if (metrics.provider) {
    printMetric("Provider", metrics.provider);
  }
  if (metrics.model) {
    printMetric("Model", metrics.model);
  }
  if (metrics.mode) {
    printMetric("Mode", metrics.mode);
  }
  if (metrics.elapsedMs != null) {
    printMetric("Elapsed", `${metrics.elapsedMs} ms`);
  }
  if (metrics.scanHash) {
    printMetric("Cache", metrics.cacheHit ? "hit" : "miss");
    printMetric("Scan hash", metrics.scanHash);
  }
  if (metrics.cacheHit) {
    printMetric("Model calls", 0);
  } else if (metrics.modelCalls != null) {
    const tokenSuffix =
      metrics.tokens != null && metrics.tokens > 0 ? `  tokens=${metrics.tokens}` : "";
    printMetric("Model calls", `${metrics.modelCalls}${tokenSuffix}`);
  }
}
