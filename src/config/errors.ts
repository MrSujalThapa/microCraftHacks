export type ConfigErrorCode = "MISSING" | "INVALID" | "PARSE";

export class ConfigError extends Error {
  readonly code: ConfigErrorCode;
  readonly configPath: string;

  constructor(message: string, code: ConfigErrorCode, configPath: string) {
    super(message);
    this.name = "ConfigError";
    this.code = code;
    this.configPath = configPath;
  }
}
