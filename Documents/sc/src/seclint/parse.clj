(ns seclint.parse
  "A tiny, tolerant Clojure reader.

  It produces a tree of plain maps, e.g.
    {:type :list :line 3 :col 1 :children [...]}
  without ever evaluating anything, resolving symbols, or loading namespaces.
  That makes it safe to point at untrusted source (unlike clojure.core/read,
  where #= can execute code) and lets us report exact line/column positions.

  It is deliberately forgiving: unbalanced or odd input never throws, the
  parser just returns the best tree it can."
  (:require [clojure.string :as str]))

(def ^:private terminators
  #{\" \; \@ \^ \` \~ \( \) \[ \] \{ \} \\})

(defn- terminator? [c]
  (or (Character/isWhitespace (char c))
      (= c \,)
      (contains? terminators c)))

(defn- classify [^String tok]
  (cond
    (str/starts-with? tok ":") :keyword
    (re-find #"^[+-]?\d" tok)  :number
    :else                      :symbol))

(defn parse
  "Parse Clojure source text into a vector of top-level nodes.

  Node types:
    leaves   :symbol :keyword :number :char :string :regex   (have :value)
    seqs     :list :vector :map :set :fn :reader-cond        (have :children)
    wrappers :quote :syntax-quote :unquote :unquote-splicing :deref
             :var-quote :reader-eval                         (one child)
  Every node has :line and :col (1-based). Metadata, #_ discards and tagged
  literal tags are dropped; comments are skipped."
  [^String src]
  (let [n          (.length src)
        pos        (volatile! 0)
        line       (volatile! 1)
        line-start (volatile! 0)]
    (letfn [(eof? [] (>= @pos n))
            (peek-ch [] (when (< @pos n) (.charAt src (int @pos))))
            (peek-at [k] (let [i (+ @pos k)] (when (< i n) (.charAt src (int i)))))
            (advance! []
              (let [c (.charAt src (int @pos))]
                (vswap! pos inc)
                (when (= c \newline)
                  (vswap! line inc)
                  (vreset! line-start @pos))
                c))
            (here [] {:line @line :col (inc (- @pos @line-start))})
            (closer? [c] (contains? #{\) \] \}} c))
            (skip-line! []
              (while (and (peek-ch) (not= (peek-ch) \newline))
                (advance!)))
            (skip-ws! []
              (loop []
                (when-let [c (peek-ch)]
                  (cond
                    (or (Character/isWhitespace (char c)) (= c \,)) (do (advance!) (recur))
                    (= c \;) (do (skip-line!) (recur))))))
            (read-token! []
              (let [sb (StringBuilder.)]
                (loop []
                  (let [c (peek-ch)]
                    (when (and c (not (terminator? c)))
                      (.append sb (char (advance!)))
                      (recur))))
                (str sb)))
            (read-str! []
              ;; opening quote already consumed
              (let [sb (StringBuilder.)]
                (loop []
                  (when-not (eof?)
                    (let [c (advance!)]
                      (cond
                        (= c \") nil
                        (= c \\) (let [e (when-not (eof?) (advance!))]
                                   (if (contains? #{\" \\} e)
                                     (.append sb (char e))
                                     (do (.append sb \\)
                                         (when e (.append sb (char e)))))
                                   (recur))
                        :else (do (.append sb (char c)) (recur))))))
                (str sb)))
            (read-char! [start]
              (advance!)
              (let [sb (StringBuilder.)]
                (when-not (eof?) (.append sb (char (advance!))))
                (loop []
                  (let [c (peek-ch)]
                    (when (and c (not (terminator? c)))
                      (.append sb (char (advance!)))
                      (recur))))
                (assoc start :type :char :value (str sb))))
            (read-atom! [start]
              (let [tok (read-token!)]
                (if (str/blank? tok)
                  (do (when-not (eof?) (advance!)) ::skip)
                  (assoc start :type (classify tok) :value tok))))
            (read-seq! []
              ;; opener already consumed; returns a vector of child nodes
              (loop [acc []]
                (skip-ws!)
                (let [c (peek-ch)]
                  (cond
                    (nil? c)     acc
                    (closer? c)  (do (advance!) acc)
                    :else (let [f (read-form!)]
                            (recur (if (or (nil? f) (= f ::skip)) acc (conj acc f))))))))
            (wrap [start type]
              (let [f (read-form!)]
                (assoc start :type type
                       :children (if (and f (not= f ::skip)) [f] []))))
            (read-dispatch! [start]
              (let [c (peek-at 1)]
                (cond
                  (= c \{) (do (advance!) (advance!)
                               (assoc start :type :set :children (read-seq!)))
                  (= c \() (do (advance!) (advance!)
                               (assoc start :type :fn :children (read-seq!)))
                  (= c \") (do (advance!) (advance!)
                               (assoc start :type :regex :value (read-str!)))
                  (= c \') (do (advance!) (advance!) (wrap start :var-quote))
                  (= c \=) (do (advance!) (advance!) (wrap start :reader-eval))
                  (= c \_) (do (advance!) (advance!)
                               (loop [] (when (= ::skip (read-form!)) (recur)))
                               ::skip)
                  (= c \!) (do (skip-line!) ::skip)
                  (= c \?) (do (advance!) (advance!)
                               (when (= (peek-ch) \@) (advance!))
                               (let [f (read-form!)]
                                 (assoc start :type :reader-cond
                                        :children (if (and (map? f) (:children f)) (:children f) []))))
                  (= c \:) (do (advance!) (read-token!) (read-form!)) ; #:ns{...}
                  (= c \#) (do (advance!) (advance!) (read-atom! start)) ; ##Inf
                  (nil? c) (do (advance!) nil)
                  :else    (do (advance!) (read-token!) (read-form!)))))   ; #inst "..." / #js {...}
            (read-form! []
              (skip-ws!)
              (let [start (here)
                    c     (peek-ch)]
                (cond
                  (nil? c)    nil
                  (closer? c) nil
                  (= c \()    (do (advance!) (assoc start :type :list :children (read-seq!)))
                  (= c \[)    (do (advance!) (assoc start :type :vector :children (read-seq!)))
                  (= c \{)    (do (advance!) (assoc start :type :map :children (read-seq!)))
                  (= c \")    (do (advance!) (assoc start :type :string :value (read-str!)))
                  (= c \')    (do (advance!) (wrap start :quote))
                  (= c \`)    (do (advance!) (wrap start :syntax-quote))
                  (= c \~)    (do (advance!)
                                  (if (= (peek-ch) \@)
                                    (do (advance!) (wrap start :unquote-splicing))
                                    (wrap start :unquote)))
                  (= c \@)    (do (advance!) (wrap start :deref))
                  (= c \^)    (do (advance!) (read-form!) (read-form!)) ; drop metadata
                  (= c \\)    (read-char! start)
                  (= c \#)    (read-dispatch! start)
                  :else       (read-atom! start))))]
      (loop [acc []]
        (skip-ws!)
        (let [c (peek-ch)]
          (cond
            (nil? c)    acc
            (closer? c) (do (advance!) (recur acc))   ; stray closer: ignore
            :else (let [f (read-form!)]
                    (recur (if (or (nil? f) (= f ::skip)) acc (conj acc f))))))))))

;; ---------------------------------------------------------------------------
;; Small helpers for walking the tree

(defn branch?
  "True if node has children (possibly empty)."
  [node]
  (contains? node :children))

(defn node-seq
  "Depth-first seq of node and all its descendants."
  [node]
  (tree-seq branch? :children node))

(defn head
  "The head symbol's text of a list-like node, e.g. \"sh/sh\"; nil otherwise."
  [node]
  (let [h (first (:children node))]
    (when (and h (= :symbol (:type h)))
      (:value h))))
