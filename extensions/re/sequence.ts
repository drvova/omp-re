/**
 * Ordered async iteration for steps that must not overlap.
 *
 * Much of omp-re is deliberately sequential: rizin answers one command at a
 * time over a single pipe, annotations and signatures replay in the order they
 * were recorded, teardowns run most-recent first, and a replay that fails part
 * way must stop. These helpers make that explicit instead of hiding it in a
 * loop body: each step starts only after the previous one settled, in input
 * order, and a step that throws stops the rest (exactly a `for…of` with an
 * `await` in its body).
 */

/** Run `step` over `items` one at a time, in order; resolves to the results in input order. A rejection stops the remaining steps. */
export const inSequence = <T, R>(
  items: Iterable<T>,
  step: (item: T, index: number) => Promise<R>
): Promise<R[]> => {
  const list = [...items];
  const results: R[] = [];
  const from = async (index: number): Promise<R[]> => {
    if (index >= list.length) {
      return results;
    }
    results.push(await step(list[index], index));
    return from(index + 1);
  };
  return from(0);
};

/** Run `step` over `items` one at a time, in order, until one returns a value other than `undefined`; resolves to that value (or `undefined`). Later steps don't run. */
export const firstInSequence = <T, R>(
  items: Iterable<T>,
  step: (item: T, index: number) => Promise<R | undefined>
): Promise<R | undefined> => {
  const list = [...items];
  const from = async (index: number): Promise<R | undefined> => {
    if (index >= list.length) {
      return undefined;
    }
    const found = await step(list[index], index);
    return found === undefined ? from(index + 1) : found;
  };
  return from(0);
};
