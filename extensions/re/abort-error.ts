/** Thrown when the caller's AbortSignal fires. The rizin process is left alone for ordinary commands (their frames are still drained in order), so an aborted tool call never forces a respawn. */
export class AbortError extends Error {
  constructor(what: string) {
    super(`omp-re: ${what} aborted`);
    this.name = "AbortError";
  }
}
