(ns seclint.parse-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [seclint.parse :as p]))

(defn- kids [src] (:children (first (p/parse src))))

(deftest positions
  (let [[top] (p/parse "(a\n  (b c))")
        inner (second (:children top))]
    (is (= [1 1] ((juxt :line :col) top)))
    (is (= [2 3] ((juxt :line :col) inner)))))

(deftest strings-hide-delimiters
  (let [[top] (p/parse "(foo \"a ) ; b\")")]
    (is (= 1 (count (p/parse "(foo \"a ) ; b\")"))))
    (is (= [:symbol :string] (map :type (:children top))))
    (is (= "a ) ; b" (:value (second (:children top)))))))

(deftest comments-are-skipped
  (is (= 1 (count (p/parse "; (x)\n(a) ; (y)\n")))))

(deftest char-literals
  (is (= 4 (count (kids "(f \\( \\) \\space)")))))

(deftest discard
  (is (= ["a" "c" "f"]
         (map :value (kids "(a #_b c #_#_ d e f)")))))

(deftest reader-conditionals
  (let [[n] (p/parse "#?(:clj (a) :cljs (b))")]
    (is (= :reader-cond (:type n)))
    (is (= 4 (count (:children n))))))

(deftest metadata-and-tagged-literals
  (is (= 3 (count (kids "(def ^:private ^String x #inst \"2020-01-01\")")))))

(deftest fn-literal-and-regex
  (is (= :fn (:type (first (p/parse "#(inc %)")))))
  (is (= [:symbol :regex :symbol]
         (map :type (kids "(re-find #\"\\d+(\" s)")))))

(deftest reader-eval-node
  (is (= :reader-eval (:type (first (p/parse "#=(+ 1 2)"))))))

(deftest never-throws-on-bad-input
  (is (vector? (p/parse "(a (b")))
  (is (= [] (p/parse ")))")))
  (is (vector? (p/parse "#")))
  (is (vector? (p/parse "\"unterminated")))
  (is (vector? (p/parse "'")))
  (is (vector? (p/parse "#_"))))

(defn- clojure-form-count [^String s]
  (binding [*read-eval* false
            *ns*        (create-ns 'seclint.parity)]
    (let [r (java.io.PushbackReader. (java.io.StringReader. s))]
      (loop [n 0]
        (let [f (read {:eof ::eof} r)]
          (if (= f ::eof) n (recur (inc n))))))))

(deftest parity-with-clojure-reader
  (testing "top-level form counts match clojure.core/read on real code"
    (doseq [res ["seclint/parse.clj" "seclint/scan.clj" "seclint/rules.clj"
                 "seclint/core.clj" "clojure/core.clj" "clojure/string.clj"
                 "clojure/test.clj" "clojure/java/io.clj"]]
      (when-let [u (io/resource res)]
        (let [s (slurp u)]
          (is (= (clojure-form-count s) (count (p/parse s))) res))))))
