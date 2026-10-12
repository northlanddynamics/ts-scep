import { FailInfo } from "./constants.js";

/** Base class for all errors thrown by this SDK. */
export class ScepError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ScepError";
  }
}

/** A message could not be parsed, verified or decrypted. Carries the failInfo a server would report. */
export class ScepProtocolError extends ScepError {
  constructor(
    message: string,
    public readonly failInfo: FailInfo = FailInfo.badRequest,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ScepProtocolError";
  }
}

/** The SCEP server answered with pkiStatus FAILURE. */
export class ScepFailureError extends ScepError {
  constructor(
    public readonly failInfo: FailInfo | undefined,
    public readonly failInfoText: string | undefined,
    public readonly transactionId: string,
  ) {
    const name = failInfo !== undefined ? (FailInfo[failInfo] ?? String(failInfo)) : "unspecified";
    super(`SCEP request failed: ${name}${failInfoText ? ` (${failInfoText})` : ""}`);
    this.name = "ScepFailureError";
  }
}

/** The HTTP transport returned an unexpected status or content type. */
export class ScepHttpError extends ScepError {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body?: Uint8Array,
  ) {
    super(message);
    this.name = "ScepHttpError";
  }
}
