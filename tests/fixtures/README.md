# Test fixtures

`digest-golden.json` is what the Python digest (`src/sectest/digest.py`)
rendered for the runs in `digest-scenarios.json`. `tests/parity.test.ts`
checks the TypeScript digest renders them byte for byte, so the port changes
nothing a reader of the email sees.

After a deliberate change to the digest's output, change both digests the
same way and regenerate it from the Python while it is still here, from the
repository root:

```sh
uv run python - <<'PY'
import json
from sectest import digest

out = {}
for s in json.load(open("tests/fixtures/digest-scenarios.json")):
    mk = lambda r: digest.build_run(r["prefix"], r["summary"], r["reports"])
    d = digest.compare(mk(s["current"]), [mk(r) for r in s["earlier"]])
    out[s["name"]] = {"subject": digest.subject(d), "text": digest.render_text(d),
                      "html": digest.render_html(d), "open": d.total_open()}
with open("tests/fixtures/digest-golden.json", "w") as f:
    json.dump(out, f, indent=2, sort_keys=True)
    f.write("\n")
PY
```
