# clj-seclint

A static security checker for **Clojure** source code. It parses your code into
real forms (no regex-over-lines guessing), applies a table of detection rules,
and reports unsafe patterns with file, line, CWE, severity and a suggested fix.

- Zero dependencies: just Clojure 1.10+.
- Safe on untrusted code: it has its own reader and **never evaluates, resolves
  or loads** anything it scans.
- Rules are plain data: adding a detection is usually one more map.
- CI friendly: text / EDN / JSON output and a non-zero exit code on findings.

```
$ sh scripts/clj -m seclint.core examples/vulnerable_app.clj
examples/vulnerable_app.clj:18:19  HIGH  sql-string-building  [CWE-89, confidence: high]
  SQL query assembled with str/format from non-literal values
  > (jdbc/query db [(str "SELECT * FROM users WHERE id = " (:id params))]))
  fix: Use parameterized queries, e.g. ["SELECT * FROM users WHERE id = ?" id], or a builder such as HoneySQL.
...
9 findings (6 high, 3 medium, 0 low) in 1 file scanned
```

`examples/fixed_app.clj` is the same app with every issue fixed, and scans clean.

## Install and run

You need Java and Clojure. Any of these works:

```sh
# Official Clojure CLI (uses deps.edn)
clojure -M:run src/

# Any Clojure install, via the helper script (no deps.edn support needed)
sh scripts/clj -m seclint.core src/

# Debian/Ubuntu/Codespaces if you have no Clojure yet
sudo apt-get update && sudo apt-get install -y clojure
```

Run the tests: `clojure -M:test` or `sh scripts/clj -m seclint.test-runner`.

## Options

| Option | Meaning |
|---|---|
| `-f, --format text\|edn\|json` | Output format (default `text`) |
| `--min-severity low\|medium\|high` | Hide findings below this level (default `medium`) |
| `--fail-on low\|medium\|high\|none` | Exit 1 if a shown finding is at least this severe (default `high`) |
| `--engine forms\|regex` | `forms` is the parser-based engine (default); `regex` is the simple line baseline |
| `--include-comments` | Also scan inside `(comment ...)` forms (skipped by default) |

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or path error.
Scans `.clj .cljs .cljc .cljx .bb .edn`, skipping `.git`, `target`, `node_modules` and similar.

### Suppressing a finding

Put a comment on the same line, or on a comment-only line directly above:

```clojure
;; seclint:ignore                 ; all rules
;; seclint:ignore eval, ssrf      ; named rules
```

## What it detects

| Rule | Severity | CWE | Catches |
|---|---|---|---|
| `unsafe-read-string` | high | 502 | `read-string` (executes `#=`); use `clojure.edn/read-string` |
| `unsafe-read` | medium | 502 | `read` without `*read-eval*` false |
| `eval` | high | 95 | `eval` on non-literal input |
| `load-code` | high | 95 | `load-string`, `load-file` |
| `reader-eval` | high | 95 | `#=` in source |
| `dynamic-resolve` | medium | 470 | `requiring-resolve` / `resolve` on computed symbols |
| `sql-string-building` | high | 89 | SQL assembled with `str`/`format` from non-literals |
| `shell-exec` | high | 78 | `sh`, `ProcessBuilder`, `Runtime.exec` with non-literal args |
| `unsafe-deserialization` | high | 502 | `ObjectInputStream`, `.readObject`, `XMLDecoder` |
| `xxe` | medium | 611 | `clojure.xml/parse` (default SAX settings) |
| `weak-hash` | medium | 328 | MD5 / SHA-1 |
| `weak-cipher` | medium | 327 | DES, RC4, AES/ECB (and bare `"AES"`) |
| `hardcoded-secret` | high | 798 | secret-looking `def`s and map entries with string literals |
| `insecure-tls` | medium | 295 | `:insecure? true` |
| `xss-raw-html` | medium | 79 | hiccup `raw-string` / `raw` |
| `xss-dangerous-html` | medium | 79 | `dangerouslySetInnerHTML`, `(set! (.-innerHTML el) ...)` |
| `path-traversal` | high | 22 | `io/file`, `slurp`, `spit`, streams fed from request-looking values |
| `ssrf` | medium | 918 | clj-http / http-kit / hato / `URL.` fed from request-looking values |
| `open-redirect` | medium | 601 | `ring.util.response/redirect` fed from request-looking values |

## How it works

1. **`seclint.parse`**: a small tolerant reader producing a tree of plain maps
   with line/column positions. Skips comments and `#_`, understands strings,
   regexes, char literals, reader conditionals and tagged literals, and never
   throws on malformed input. Its top-level form counts are tested against
   Clojure's own reader on `clojure.core` and this project's sources.
2. **`seclint.resolve`**: reads `ns` / `require` forms so `edn/read-string`,
   `clojure.core/read-string` and `(:refer [read-string])` are told apart.
3. **`seclint.scan`**: walks the forms, skipping `(comment ...)` and quoted
   data, desugars `->` / `->>` so rules see the real argument, and applies the
   rules. **Literal arguments are downgraded to `low`**, e.g. `(read-string "42")`.
   Confidence is raised when an argument mentions things like `params`,
   `request` or `body`.
4. **`seclint.rules`**: the rules, as data. A rule says which call heads to
   watch and which argument to inspect:

```clojure
{:id       :eval
 :severity :high
 :cwe      "CWE-95"
 :title    "eval executes arbitrary code"
 :advice   "Never pass user-influenced data to eval."
 :match    {:call {"clojure.core/eval" 0}}}
```

`seclint.regex` is the v1 line-based baseline, kept as `--engine regex`. The
tests show where it goes wrong (it flags commented-out code and all-literal
SQL, which the form-aware engine does not).

## Limitations (read these)

This is a pattern-based linter, not a taint-tracking analyzer. Expect both
false positives and false negatives.

- No data-flow analysis. "Looks request-derived" is a naming heuristic, so a
  value that was validated earlier can still be flagged, and a tainted value
  with an innocent name can be missed. That is why a few rules (path traversal,
  SSRF, open redirect) only fire when an argument looks request-derived.
- Macros are not expanded, and aliases come only from top-level `ns` / `require`.
- Threading is handled for `->`, `->>`, `some->`, `some->>`; other macros are not.
- Quoted data and `(comment ...)` forms are skipped by design.
- Findings are leads for review, not proof of exploitability.

## Project layout

```
src/seclint/parse.clj    tolerant reader (never evals)
src/seclint/resolve.clj  alias / refer resolution
src/seclint/rules.clj    detection rules as data
src/seclint/scan.clj     matchers, tree walk, file discovery
src/seclint/regex.clj    v1 line-regex baseline
src/seclint/report.clj   text / EDN / JSON output
src/seclint/core.clj     CLI
test/                    clojure.test suite + fixtures
examples/                vulnerable_app.clj and its fixed twin
```

`test/fixtures/vulnerable.clj` is deliberately insecure test data. Never load or run it.

## Adding a rule

1. Add a map to `rules` in `src/seclint/rules.clj`.
2. Add a line to `test/fixtures/vulnerable.clj` ending in `; EXPECT your-rule-id`.
3. Run the tests. They fail on any missing or unexpected finding.

