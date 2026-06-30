export function isTestFile(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  const basename = normalized.split("/").pop() ?? normalized;

  if (/\.(test|spec)\./.test(basename)) {
    return true;
  }

  if (
    normalized.includes("/__tests__/") ||
    normalized.includes("/fixtures/") ||
    normalized.startsWith("test/") ||
    normalized.startsWith("tests/") ||
    normalized.includes("/test/") ||
    normalized.includes("/tests/")
  ) {
    return true;
  }

  return false;
}
