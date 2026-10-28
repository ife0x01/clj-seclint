(ns seclint.scan-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [seclint.regex :as regex]
            [seclint.scan :as scan]))

(defn- findings
  ([src] (findings src {}))
  ([src opts] (scan/scan-source src (merge {:file "t.clj"} opts))))

(defn- rules-of [src & [opts]] (set (map :rule (findings src (or opts {})))))
(defn- resource-text [path] (slurp (io/resource path)))

(defn- expected
  "Parse `; EXPECT rule rule` markers into #{[line rule]}."
  [^String src]
  (set (for [[i l] (map-indexed vector (str/split-lines src))
             :let  [m (re-find #"; EXPECT ([\w\- ]+)\s*$" l)]
             :when m
             r     (str/split (str/trim (second m)) #"\s+")]
         [(inc i) (keyword r)])))

(deftest vulnerable-fixture-matches-markers-exactly
  (let [src (resource-text "fixtures/vulnerable.clj")]
    (is (= (expected src)
           (set (map (juxt :line :rule) (findings src)))))))

(deftest safe-fixture-is-clean
  (is (empty? (findings (resource-text "fixtures/safe.clj")))))

(deftest examples
  (let [bad  (resource-text "vulnerable_app.clj")
        good (resource-text "fixed_app.clj")]
    (is (= #{:hardcoded-secret :weak-hash :sql-string-building :path-traversal
             :eval :unsafe-read-string :shell-exec :ssrf :open-redirect}
           (rules-of bad)))
    (is (empty? (findings good)))))

(deftest static-arguments-are-downgraded
  (is (= :low (:severity (first (findings "(read-string \"42\")")))))
  (is (= :low (:severity (first (findings "(eval '(+ 1 2))")))))
  (is (= :high (:severity (first (findings "(eval x)"))))))

(deftest confidence-uses-request-hints
  (is (= :high   (:confidence (first (findings "(eval (:expr params))")))))
  (is (= :medium (:confidence (first (findings "(eval x)"))))))

(deftest aliases-and-refers
  (testing "safe: edn alias / refer"
    (is (empty? (findings "(ns a (:require [clojure.edn :as edn]))\n(edn/read-string x)")))
    (is (empty? (findings "(ns a (:refer-clojure :exclude [read-string]) (:require [clojure.edn :refer [read-string]]))\n(read-string x)"))))
  (testing "unsafe: core by alias or full name"
    (is (= #{:unsafe-read-string} (rules-of "(ns a (:require [clojure.core :as c]))\n(c/read-string x)")))
    (is (= #{:unsafe-read-string} (rules-of "(clojure.core/read-string x)"))))
  (testing "prefix lists and top-level require"
    (is (= #{:shell-exec} (rules-of "(ns a (:require [clojure.java [shell :as sh]]))\n(sh/sh \"ls\" x)")))
    (is (= #{:shell-exec} (rules-of "(require '[clojure.java.shell :as sh])\n(sh/sh \"ls\" x)")))
    (is (= #{:shell-exec} (rules-of "(ns a (:require [clojure.java.shell :refer [sh]]))\n(sh \"ls\" x)")))))

(deftest ignores-comments-quotes-strings-and-discards
  (is (empty? (findings "; (eval x)")))
  (is (empty? (findings "(comment (eval x))")))
  (is (empty? (findings "'(eval x)")))
  (is (empty? (findings "(quote (eval x))")))
  (is (empty? (findings "(def s \"(eval x)\")")))
  (is (empty? (findings "#_(eval x)")))
  (testing "unless asked"
    (is (= #{:eval} (rules-of "(comment (eval x))" {:include-comments? true})))))

(deftest regex-baseline-vs-forms
  (let [commented "; (eval x)\n"
        literal   "(str \"SELECT * FROM t \" \"WHERE a = 1\")"]
    (is (seq (regex/scan-source commented {})))
    (is (empty? (findings commented)))
    (is (seq (regex/scan-source literal {})))
    (is (empty? (findings literal)))))

(deftest multi-line-forms
  (let [src "(defn q [id]\n  (str \"SELECT *\"\n       \" FROM users WHERE id = \"\n       id))"
        fs  (findings src)]
    (is (= [:sql-string-building] (map :rule fs)))
    (is (= 2 (:line (first fs))))))

(deftest threading-macros
  (is (contains? (rules-of "(-> raw-text read-string)") :unsafe-read-string))
  (let [fs (findings "(ns a (:require [clojure.java.shell :as sh]))\n(->> user-cmd (sh/sh \"bash\" \"-c\"))")]
    (is (= 1 (count fs)))
    (is (= :high (:severity (first fs)))))
  (testing "a fully literal threaded call is only low severity"
    (is (= [:low] (map :severity (findings "(-> \"42\" read-string)"))))))

(deftest suppression
  (is (empty? (findings ";; seclint:ignore\n(eval x)")))
  (is (empty? (findings "(eval x) ;; seclint:ignore eval")))
  (is (empty? (findings ";; seclint:ignore eval, ssrf\n(eval x)")))
  (is (= #{:eval} (rules-of "(eval x) ;; seclint:ignore sql-string-building")))
  (testing "only a comment line above counts"
    (is (= #{:eval} (rules-of "(def y 1) ;; seclint:ignore\n(eval x)")))))

(deftest secrets
  (is (= #{:hardcoded-secret} (rules-of "(def jwt-secret \"abcd1234efgh\")")))
  (is (= #{:hardcoded-secret} (rules-of "{:api-key \"abcd1234efgh\"}")))
  (is (empty? (findings "(def password \"\")")))
  (is (empty? (findings "(def token-url \"abc12345\")")))
  (is (empty? (findings "{:password \"has spaces in it\"}")))
  (is (empty? (findings "{:password \"$DB_PASSWORD\"}")))
  (is (empty? (findings "{:password (System/getenv \"DB_PASSWORD\")}"))))

(deftest hint-gated-rules-need-hints
  (is (empty? (findings "(ns a (:require [clojure.java.io :as io]))\n(slurp (io/file base rel))")))
  (is (= #{:path-traversal}
         (rules-of "(ns a (:require [clojure.java.io :as io]))\n(slurp (io/file base (:filename params)))"))))

(deftest findings-carry-positions-and-source
  (let [f (first (findings "(defn f [x]\n  (eval x))"))]
    (is (= [2 3] ((juxt :line :col) f)))
    (is (= "(eval x))" (:code f)))
    (is (= "CWE-95" (:cwe f)))))
