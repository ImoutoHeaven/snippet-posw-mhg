import { staticParentsOf, deriveDynamicParent2 } from "../../../lib/mhg/graph.js";

export const resolveParentsV4 = async ({ i, graphSeed, pageBytes, pages }) => {
  if (i === 1) return { p0: 0, p1: 0, p2: 0 };
  if (i === 2) return { p0: 1, p1: 0, p2: 0 };

  const { p0, p1 } = await staticParentsOf(i, graphSeed);
  const p2 = await deriveDynamicParent2({
    i,
    seed: graphSeed,
    pageBytes,
    p0,
    p1,
    p0Page: pages[p0],
    p1Page: pages[p1],
  });
  return { p0, p1, p2 };
};
