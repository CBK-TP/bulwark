# Community Rules

The community rules engine is planned, but it is not active in the current Free release.

The direction is:

- rules are data, not code;
- no scripts, no remote jars and no automatic downloads;
- broken rules fail open and are reported as diagnostics;
- rule findings start conservative to avoid noisy grades;
- every accepted rule needs evidence and a fixture.

Rule pull requests are not open yet. The first step is to land a validator and fixture runner, then accept a small set of high-confidence rules.
