# Test fixtures

`digest-golden.json` is what the Python scanner's digest rendered, before the
TypeScript replaced it, for the runs in `digest-scenarios.json`.
`tests/parity.test.ts` checks the digest still renders them byte for byte, so
the email doesn't change by accident.

After a deliberate change to the digest's output, rewrite the file from the
current digest and review its diff as part of the change:

```sh
UPDATE_GOLDEN=1 npm test -- tests/parity.test.ts
git diff tests/fixtures/digest-golden.json
```
