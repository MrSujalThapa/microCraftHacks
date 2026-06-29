export const REDACTED_SECRET = "<REDACTED_SECRET>";

const NAMED_SECRET =
  /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)|api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*\S+/gi;

const SK_TOKEN = /\bsk-[A-Za-z0-9]{10,}\b/g;
const AWS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._\-+/=]{8,}\b/g;

const RAW_SECRET =
  /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)|api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*(?!<?REDACTED_SECRET>?)\S+/i;

const RAW_SK = /\bsk-[A-Za-z0-9]{10,}\b/;
const RAW_AWS = /\bAKIA[0-9A-Z]{16}\b/;

export function redactSecrets(text: string): string {
  if (!text) {
    return text;
  }
  let redacted = text.replace(NAMED_SECRET, (_match, key: string) => `${key}=${REDACTED_SECRET}`);
  redacted = redacted.replace(SK_TOKEN, REDACTED_SECRET);
  redacted = redacted.replace(AWS_KEY, REDACTED_SECRET);
  redacted = redacted.replace(BEARER, `Bearer ${REDACTED_SECRET}`);
  return redacted;
}

export function containsRawSecret(text: string): boolean {
  if (!text) {
    return false;
  }
  return RAW_SECRET.test(text) || RAW_SK.test(text) || RAW_AWS.test(text);
}

export function redactFindingText<T extends Record<string, unknown>>(finding: T): T {
  const redacted = { ...finding };
  for (const key of ["title", "claim", "impact_hypothesis", "attack_path"] as const) {
    const value = finding[key];
    if (typeof value === "string") {
      (redacted as Record<string, unknown>)[key] = redactSecrets(value);
    }
  }
  return redacted;
}
