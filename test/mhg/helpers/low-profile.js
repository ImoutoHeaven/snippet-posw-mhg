export const LOW_PROFILE = Object.freeze({
  maxSteps: 128,
  maxPageBytes: 1024,
  hashcashX: 1,
  defaults: Object.freeze({
    steps: 64,
    pageBytes: 240,
    mixRounds: 3,
  }),
});

export function assertLowProfileFixture({ steps, pageBytes, hashcashX }) {
  if (!(steps <= LOW_PROFILE.maxSteps)) {
    throw new Error("steps out of low-profile bounds");
  }
  if (!(pageBytes <= LOW_PROFILE.maxPageBytes)) {
    throw new Error("pageBytes out of low-profile bounds");
  }
  if (hashcashX !== LOW_PROFILE.hashcashX) {
    throw new Error("hashcashX must be 1 (disabled) in CI guardrails");
  }
}
