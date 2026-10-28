(ns seclint.cli-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [seclint.core :as cli]))

(defn- path [res] (.getPath (io/file (io/resource res))))

(defn- run [& args]
  (let [code (atom nil)
        err  (java.io.StringWriter.)
        out  (binding [*err* err]
               (with-out-str (reset! code (cli/run args))))]
    {:code @code :out out :err (str err)}))

(deftest clean-file-exits-zero
  (let [{:keys [code out]} (run (path "fixtures/safe.clj"))]
    (is (= 0 code))
    (is (str/includes? out "0 findings"))))

(deftest vulnerable-file-exits-one
  (let [{:keys [code out]} (run (path "fixtures/vulnerable.clj"))]
    (is (= 1 code))
    (is (str/includes? out "sql-string-building"))
    (is (str/includes? out "CWE-89"))))

(deftest fail-on-and-min-severity
  (is (= 0 (:code (run "--fail-on" "none" (path "fixtures/vulnerable.clj")))))
  (let [{:keys [out]} (run "--min-severity" "high" (path "fixtures/vulnerable.clj"))]
    (is (not (str/includes? out "weak-hash")))
    (is (str/includes? out "eval"))))

(deftest json-and-edn-output
  (let [{:keys [out]} (run "-f" "json" (path "fixtures/vulnerable.clj"))]
    (is (str/starts-with? out "{\"summary\""))
    (is (str/includes? out "\"rule\":\"eval\"")))
  (let [{:keys [out]} (run "--format" "edn" (path "fixtures/vulnerable.clj"))
        data (edn/read-string out)]
    (is (pos? (get-in data [:summary :total])))
    (is (every? :rule (:findings data)))))

(deftest regex-engine-flag
  (let [{:keys [code out]} (run "--engine" "regex" (path "fixtures/vulnerable.clj"))]
    (is (= 1 code))
    (is (str/includes? out "unsafe-read-string"))))

(deftest usage-errors-exit-two
  (is (= 2 (:code (run))))
  (is (= 2 (:code (run "--nope" "x"))))
  (is (= 2 (:code (run "--format" "xml" "x"))))
  (is (= 2 (:code (run "/definitely/not/a/path"))))
  (is (= 0 (:code (run "--help")))))

(deftest directory-scan
  (let [{:keys [code out]} (run (.getParent (io/file (path "fixtures/safe.clj"))))]
    (is (= 1 code))
    (is (str/includes? out "scanned"))))
