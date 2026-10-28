(ns seclint.rules
  "Detection rules, as plain data.

  A rule is a map:
    :id        keyword, used in output and in `seclint:ignore` comments
    :severity  :low | :medium | :high   (severity when the input is not a literal)
    :cwe       CWE identifier string
    :title     one-line description of the problem
    :advice    how to fix it
    :match     a matcher spec (or a vector of them), interpreted by seclint.scan

  Matcher specs:
    {:call {\"clojure.core/eval\" 0 ...}}     call heads -> argument to inspect
                                              (an index, or :any for all args)
        optional :literal-arg <regex>         only match when that arg is a string literal matching
        optional :require-hint true           only match when an arg looks request-derived
    {:node-type :reader-eval}                 any node of this type
    {:keyword #{\"name\"}}                      keywords by name
    {:map-pair {:key re :not-key re :value :string|:true}}
    {:def-string {:name re :not-name re}}     (def name \"literal\")
    {:sql-string-building true}               str/format building SQL from non-literals
    {:set-inner-html true}                    (set! (.-innerHTML el) dynamic)

  Adding a detection is usually one more map in `rules`.")

(def severity-rank {:low 1 :medium 2 :high 3})

(def hint-re
  "Symbols/keywords that suggest an expression carries request-derived data.
  Used only to raise confidence and to gate noisy rules (path traversal, SSRF)."
  #"(?i)param|request|\breq\b|body|input|payload|untrusted|upload|filename|cookie|header|query|\bform\b|form[-_]")

(def ^:private secret-re
  #"(?i)(secret|passw(?:or)?d|passwd|pwd|api[-_]?key|private[-_]?key|access[-_]?key|auth[-_]?token|token|credential)")

(def ^:private not-secret-re
  #"(?i)(url|uri|endpoint|path|header|name|field|type|expir|ttl|length|file|param|label|prompt|message|msg|regex|pattern|format)")

(defn- heads
  "{\"ns/fn\" idx ...} for every combination of namespaces and function names."
  [nses fns idx]
  (into {} (for [n nses f fns] [(str n "/" f) idx])))

(def rules
  [{:id       :unsafe-read-string
    :severity :high
    :cwe      "CWE-502"
    :title    "read-string can execute code through the #= reader macro"
    :advice   "Use clojure.edn/read-string for untrusted input. If you must use read-string, bind *read-eval* to false."
    :match    {:call {"clojure.core/read-string" :any}}}

   {:id       :unsafe-read
    :severity :medium
    :cwe      "CWE-502"
    :title    "read on a stream evaluates #= unless *read-eval* is false"
    :advice   "Use clojure.edn/read, or bind *read-eval* to false around the call."
    :match    {:call {"clojure.core/read" :any}}}

   {:id       :eval
    :severity :high
    :cwe      "CWE-95"
    :title    "eval executes arbitrary code"
    :advice   "Never pass user-influenced data to eval. Dispatch through an explicit allowlist of functions instead."
    :match    {:call {"clojure.core/eval" 0}}}

   {:id       :load-code
    :severity :high
    :cwe      "CWE-95"
    :title    "load-string / load-file executes Clojure source"
    :advice   "Do not load code from user-influenced strings or paths. Load only fixed, trusted files."
    :match    {:call {"clojure.core/load-string" 0
                      "clojure.core/load-file"   0}}}

   {:id       :reader-eval
    :severity :high
    :cwe      "CWE-95"
    :title    "#= reader macro evaluates code at read time"
    :advice   "Remove #=. It runs code while the file or data is being read."
    :match    {:node-type :reader-eval}}

   {:id       :dynamic-resolve
    :severity :medium
    :cwe      "CWE-470"
    :title    "Function selected from a computed symbol"
    :advice   "Map user input to functions through an explicit allowlist (a map of known keys to fns), not (resolve (symbol input))."
    :match    {:call {"clojure.core/requiring-resolve" 0
                      "clojure.core/resolve"           0
                      "clojure.core/ns-resolve"        1}}}

   {:id       :sql-string-building
    :severity :high
    :cwe      "CWE-89"
    :title    "SQL query assembled with str/format from non-literal values"
    :advice   "Use parameterized queries, e.g. [\"SELECT * FROM users WHERE id = ?\" id], or a builder such as HoneySQL."
    :match    {:sql-string-building true}}

   {:id       :shell-exec
    :severity :high
    :cwe      "CWE-78"
    :title    "OS command execution"
    :advice   "Do not build commands from user input. Pass arguments as separate elements, avoid sh -c, and validate against an allowlist."
    :match    {:call {"clojure.java.shell/sh"      :any
                      "clojure.java.process/exec"  :any
                      "clojure.java.process/start" :any
                      "ProcessBuilder."            :any
                      ".exec"                      1}}}

   {:id       :unsafe-deserialization
    :severity :high
    :cwe      "CWE-502"
    :title    "Java native deserialization"
    :advice   "Do not deserialize untrusted bytes with Java serialization or XMLDecoder. Use a data format (EDN via clojure.edn, JSON) and validate the result."
    :match    {:call {"ObjectInputStream." :any
                      ".readObject"        :any
                      "XMLDecoder."        :any}}}

   {:id       :xxe
    :severity :medium
    :cwe      "CWE-611"
    :title    "clojure.xml/parse uses the JDK's default SAX settings, which may resolve external entities"
    :advice   "Parse untrusted XML with a parser configured to disable DTDs and external entities (e.g. clojure.data.xml with secure options, or a hardened SAXParserFactory)."
    :match    {:call {"clojure.xml/parse" :any}}}

   {:id       :weak-hash
    :severity :medium
    :cwe      "CWE-328"
    :title    "Weak hash algorithm (MD5 / SHA-1)"
    :advice   "Use SHA-256 or stronger for integrity, and bcrypt/scrypt/argon2 for passwords. MD5/SHA-1 are only acceptable for non-security checksums."
    :match    [{:call        {"MessageDigest/getInstance" 0}
                :literal-arg #"(?i)^(?:md2|md5|sha-?1)$"}
               {:call {"buddy.core.hash/md5"  :any
                       "buddy.core.hash/sha1" :any}}]}

   {:id       :weak-cipher
    :severity :medium
    :cwe      "CWE-327"
    :title    "Weak cipher or unsafe mode (DES, RC4, AES/ECB)"
    :advice   "Use AES/GCM/NoPadding with a unique random IV, or a high-level library instead of raw Cipher."
    :match    {:call        {"Cipher/getInstance" 0}
               :literal-arg #"(?i)^(?:des|desede|rc2|rc4|arcfour|blowfish|aes)$|^(?:des|desede|rc2|rc4|blowfish)/|/ecb(?:/|$)"}}

   {:id       :hardcoded-secret
    :severity :high
    :cwe      "CWE-798"
    :title    "Hardcoded credential or secret"
    :advice   "Load secrets from the environment or a secrets manager, and rotate anything that was already committed."
    :match    [{:def-string {:name secret-re :not-name not-secret-re}}
               {:map-pair   {:key secret-re :not-key not-secret-re :value :string}}]}

   {:id       :insecure-tls
    :severity :medium
    :cwe      "CWE-295"
    :title    "TLS certificate verification disabled"
    :advice   "Remove :insecure? true and fix the trust store instead of disabling verification."
    :match    {:map-pair {:key #"^insecure\??$" :value :true}}}

   {:id       :xss-raw-html
    :severity :medium
    :cwe      "CWE-79"
    :title    "HTML escaping bypassed with raw / raw-string"
    :advice   "Escape untrusted values (hiccup2 escapes by default) and sanitize any HTML you must render as-is."
    :match    {:call {"hiccup.util/raw-string" 0
                      "hiccup2.core/raw"       0}}}

   {:id       :xss-dangerous-html
    :severity :medium
    :cwe      "CWE-79"
    :title    "Unescaped HTML sink (innerHTML / dangerouslySetInnerHTML)"
    :advice   "Render text, not HTML (textContent, normal hiccup/React children), or sanitize the HTML first."
    :match    [{:keyword #{"dangerouslySetInnerHTML"}}
               {:set-inner-html true}]}

   {:id       :path-traversal
    :severity :high
    :cwe      "CWE-22"
    :title    "File path built from request-derived input"
    :advice   "Resolve against a fixed base directory and reject paths whose canonical form escapes it, or generate filenames server-side."
    :match    {:call (merge {"clojure.java.io/file"                    :any
                             "File."                                   :any
                             "clojure.core/slurp"                      0
                             "clojure.core/spit"                       0
                             "ring.util.response/file-response"        0
                             "ring.util.response/resource-response"    0}
                            (heads ["clojure.java.io"]
                                   ["input-stream" "reader" "output-stream" "writer"] 0))
               :require-hint true}}

   {:id       :ssrf
    :severity :medium
    :cwe      "CWE-918"
    :title    "Outbound request to a URL derived from request input"
    :advice   "Validate user-supplied URLs against an allowlist of hosts and schemes, and block internal address ranges, before fetching."
    :match    {:call (merge {"URL." 0}
                            (heads ["clj-http.client" "org.httpkit.client" "hato.client"]
                                   ["get" "post" "put" "patch" "delete" "head" "request"] 0))
               :require-hint true}}

   {:id       :open-redirect
    :severity :medium
    :cwe      "CWE-601"
    :title    "Redirect to a location derived from request input"
    :advice   "Only redirect to relative paths or to hosts on an allowlist."
    :match    {:call {"ring.util.response/redirect"            0
                      "ring.util.response/redirect-after-post" 0}
               :require-hint true}}])
