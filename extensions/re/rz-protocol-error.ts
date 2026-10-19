/** The rizin pipe protocol broke: the process exited, a command timed out, or the stream lost sync. */
export class RzProtocolError extends Error {
  override name = "RzProtocolError";
}
