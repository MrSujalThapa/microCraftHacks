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
  llmCacheHit?: boolean;
  scanHash?: string;
  modelCalls?: number;
  tokens?: number;
  mode?: string;
  latencyMode?: string;
  provider?: string;
  model?: string;
  inputTokenEstimate?: number;
  outputTokens?: number;
  modelLatencyMs?: number;
  stageTimings?: Record<string, number>;
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
  if (metrics.latencyMode) {
    printMetric("Latency", metrics.latencyMode);
  }
  if (metrics.elapsedMs != null) {
    printMetric("Elapsed", `${metrics.elapsedMs} ms`);
  }
  if (metrics.scanHash) {
    printMetric("Cache", metrics.cacheHit ? "hit" : "miss");
    printMetric("Scan hash", metrics.scanHash);
  }
  if (metrics.llmCacheHit != null) {
    printMetric("LLM cache", metrics.llmCacheHit ? "hit" : "miss");
  }
  if (metrics.inputTokenEstimate != null) {
    printMetric("Input token estimate", metrics.inputTokenEstimate);
  }
  if (metrics.outputTokens != null) {
    printMetric("Output tokens", metrics.outputTokens);
  }
  if (metrics.modelLatencyMs != null) {
    printMetric("Model latency", `${metrics.modelLatencyMs} ms`);
  }
  if (metrics.cacheHit) {
    printMetric("Model calls", 0);
  } else if (metrics.modelCalls != null) {
    const tokenSuffix =
      metrics.tokens != null && metrics.tokens > 0 ? `  tokens=${metrics.tokens}` : "";
    printMetric("Model calls", `${metrics.modelCalls}${tokenSuffix}`);
  }
  if (metrics.stageTimings) {
    printMetric("Stage timings", "");
    for (const [stage, ms] of Object.entries(metrics.stageTimings)) {
      console.log(`    ${stage}: ${ms} ms`);
    }
  }
}
