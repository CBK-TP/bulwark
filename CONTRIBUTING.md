# Contributing

Small, well-tested fixes are easiest to review.

Before sending a pull request:

- build with `mvn test package`;
- keep the Free edition read-only from public commands;
- do not add runtime dependencies without a strong reason;
- do not add remote code loading, auto-updates or scripts;
- include a test or fixture for scanner behavior changes;
- keep wording specific and calm, especially for security findings.

Community rule contributions are not open yet. The rules area is reserved until the validator, fixtures and false-positive process are ready.

For false positives, open an issue with:

- the finding ID;
- server platform and Minecraft version;
- relevant config snippet with secrets removed;
- why the finding is wrong for that setup.

Do not include license keys, webhook URLs, passwords, private IP lists or customer data in issues.

## Continuous integration

The build/leak-check workflow lives in `docs/ci/build.yml`. To enable it, copy it to `.github/workflows/build.yml` (adding workflows requires a token with the `workflow` scope, or the GitHub web editor).
