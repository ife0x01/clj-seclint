(ns seclint.regex
  "v1 baseline: fast, line-oriented regex checks.

  It is kept as a simple fallback (`--engine regex`) and as a yardstick for the
  form-aware engine in seclint.scan. Its weaknesses are exactly why v2 exists:
  it flags commented-out code and string contents, cannot see across lines,
  and cannot tell a literal argument from a variable."
  (:require [clojure.string :as str]))

(def line-rules
  [{:id :unsafe-read-string :severity :high :cwe "CWE-502"
    :pattern #"\((?:clojure\.core/)?read-string\b"
    :title "read-string can execute code through the #= reader macro"
    :advice "Use clojure.edn/read-string for untrusted input."}
   {:id :eval :severity :high :cwe "CWE-95"
    :pattern #"\((?:clojure\.core/)?eval\b"
    :title "eval executes arbitrary code"
    :advice "Never pass user-influenced data to eval."}
   {:id :load-code :severity :high :cwe "CWE-95"
    :pattern #"\((?:clojure\.core/)?load-(?:string|file)\b"
    :title "load-string / load-file executes Clojure source"
    :advice "Load only fixed, trusted files."}
   {:id :sql-string-building :severity :high :cwe "CWE-89"
    :pattern #"(?i)\((?:str|format)\s+\"[^\"]*\b(?:select|insert|update|delete)\b"
    :title "SQL query assembled with str/format"
    :advice "Use parameterized queries."}
   {:id :weak-hash :severity :medium :cwe "CWE-328"
    :pattern #"(?i)MessageDigest/getInstance\s+\"(?:md5|sha-?1)\""
    :title "Weak hash algorithm (MD5 / SHA-1)"
    :advice "Use SHA-256 or stronger."}
   {:id :shell-exec :severity :high :cwe "CWE-78"
    :pattern #"\((?:clojure\.java\.shell/|shell/|sh/)?sh\s"
    :title "OS command execution"
    :advice "Do not build commands from user input."}])

(defn- match-col [pattern line]
  (let [m (re-matcher pattern line)]
    (when (.find m) (inc (.start m)))))

(defn scan-source
  "Scan source text line by line. Findings use the same shape as seclint.scan."
  [^String src {:keys [file] :or {file "<string>"}}]
  (vec (for [[i line] (map-indexed vector (str/split-lines src))
             rule     line-rules
             :let     [col (match-col (:pattern rule) line)]
             :when    col]
         {:rule       (:id rule)
          :severity   (:severity rule)
          :confidence :low
          :cwe        (:cwe rule)
          :title      (:title rule)
          :advice     (:advice rule)
          :file       file
          :line       (inc i)
          :col        col
          :code       (str/trim line)})))
