// The truth the carry figure moves by: what `/re carry` decides for one cited
// command, told as two keys on a comparator. A key's bitting (its cut depths,
// tip to bow) stands for the function's mnemonic sequence, the fingerprint
// extensions/re/anchor.ts records; the figure's readout and needle come only
// from this module.

/** The recorded key: the profile `/re report` wrote into the manifest. */
export const RECORDED = [3, 1, 4, 2, 5, 2, 3, 1];

/** Minimum share of matching cuts to call it the same function (RELOCATE_THRESHOLD in anchor.ts). */
export const RELOCATE_THRESHOLD = 0.8;

/** Cut width in world units; one cut along the slide is one step of relocation. */
export const CUT = 12;

/** The four outcomes, in the order the idle tour shows them. */
export const CASES = [
  { bits: RECORDED, id: "holds", offset: 0 },
  { bits: RECORDED, id: "relocated", offset: -2 },
  { bits: RECORDED.map((b, i) => (i === 4 ? 2 : b)), id: "drifted", offset: 0 },
  { bits: null, id: "broken", offset: 0 },
];

/** Share of cuts that match once the new key is aligned by `shift` cuts. */
export const matchShare = (recorded, bits, shift = 0) => {
  if (!bits) {
    return 0;
  }
  let same = 0;
  for (let i = 0; i < recorded.length; i += 1) {
    if (bits[i - shift] === recorded[i]) {
      same += 1;
    }
  }
  return same / recorded.length;
};

/** The verdict for a case: the status `/re carry` reports and the line the readout ends on. */
export const verdict = (c) => {
  if (!c.bits) {
    return { line: "broken · nothing under the stylus", status: "broken" };
  }
  const differing = c.bits.flatMap((b, i) => (b === RECORDED[i] ? [] : [i]));
  if (c.offset !== 0) {
    const share = matchShare(RECORDED, c.bits, 0);
    const n = Math.round(share * RECORDED.length);
    return {
      line: `relocated · same profile ${-c.offset} cuts along · ${n}/${RECORDED.length} ≥ 80%`,
      status: share >= RELOCATE_THRESHOLD ? "relocated" : "broken",
    };
  }
  if (differing.length === 0) {
    return {
      line: `holds · Δ 0 at all ${RECORDED.length} cuts`,
      status: "holds",
    };
  }
  const [i] = differing;
  return {
    line: `drifted · cut ${i + 1} differs by ${Math.abs(c.bits[i] - RECORDED[i])} steps`,
    status: "drifted",
  };
};
