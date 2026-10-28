(ns seclint.scan
  "The form-aware engine: parse source into forms, walk the tree, and apply
  the data rules from seclint.rules."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [seclint.parse :as p]
            [seclint.regex :as regex]
            [seclint.resolve :as res]
            [seclint.rules :as rules])
  (:import (java.io File)))

;; ---------------------------------------------------------------------------
;; Helpers: literal-ness and "looks request-derived" heuristics

(def ^:private literal-syms #{"nil" "true" "false"})
(def ^:private str-heads #{"str" "format" "clojure.core/str" "clojure.core/format"})

(defn- static?
  "True if the node is a compile-time constant: a literal, quoted data, or
  str/format over constants. Static arguments cannot carry attacker input."
  [node]
  (case (:type node)
    (:string :number :keyword :char :regex) true
    :symbol (contains? literal-syms (:value node))
    :quote true
    :syntax-quote (not-any? #(#{:unquote :unquote-splicing} (:type %)) (p/node-seq node))
    (:vector :set :map) (every? static? (:children node))
    :list (let [[h & args] (:children node)]
            (boolean (and h
                          (= :symbol (:type h))
                          (str-heads (:value h))
                          (every? static? args))))
    false))

(defn- hint?
  "Does any symbol/keyword inside the node look request-derived?"
  [node]
  (boolean (some (fn [n]
                   (and (#{:symbol :keyword} (:type n))
                        (re-find rules/hint-re (:value n))))
                 (p/node-seq node))))

(defn- call-info [node]
  (when (#{:list :fn} (:type node))
    (let [[h & args] (:children node)]
      (when (and h (= :symbol (:type h)))
        {:head (:value h) :args (vec args)}))))

(defn- select-args [args idx]
  (cond
    (= idx :any)        args
    (< idx (count args)) [(nth args idx)]
    :else               args))

;; ---------------------------------------------------------------------------
;; Matchers. Each takes (spec node ctx) and returns a seq of match results:
;;   {:node n :static? bool :hint? bool :severity kw :confidence kw}

(defn- match-call [{:keys [call literal-arg require-hint]} node ctx]
  (when-let [{:keys [head args]} (call-info node)]
    (let [idx (some #(get call %) (res/head-keys ctx head))]
      (when (some? idx)
        (let [sel (select-args args idx)]
          (cond
            literal-arg
            (let [a (first sel)]
              (when (and a (= :string (:type a)) (re-find literal-arg (:value a)))
                [{:node node :static? false :confidence :high}]))

            (empty? sel) nil

            require-hint
            (when (some hint? (remove static? sel))
              [{:node node :hint? true}])

            :else
            [{:node node
              :static? (every? static? sel)
              :hint? (boolean (some hint? sel))}]))))))

(defn- match-node-type [{t :node-type} node _ctx]
  (when (= t (:type node))
    [{:node node :hint? (hint? node)}]))

(defn- kw-name [^String v] (str/replace v #"^::?" ""))

(defn- match-keyword [{names :keyword} node _ctx]
  (when (and (= :keyword (:type node))
             (contains? names (kw-name (:value node))))
    [{:node node}]))

(defn- secret-like-value? [^String s]
  (and (>= (count s) 4)
       (not (re-find #"\s" s))
       (not (re-find #"^\$\{?[A-Za-z_]+\}?$" s))))

(defn- pair-value-ok? [vtype v]
  (case vtype
    :string (and (= :string (:type v)) (secret-like-value? (:value v)))
    :true   (and (= :symbol (:type v)) (= "true" (:value v)))
    false))

(defn- match-map-pair [{{k-re :key nk-re :not-key vtype :value} :map-pair} node _ctx]
  (when (= :map (:type node))
    (for [[k v] (partition 2 (:children node))
          :when (and (= :keyword (:type k))
                     (let [nm (kw-name (:value k))]
                       (and (re-find k-re nm)
                            (not (and nk-re (re-find nk-re nm)))))
                     (pair-value-ok? vtype v))]
      {:node k})))

(defn- match-def-string [{{n-re :name nn-re :not-name} :def-string} node _ctx]
  (when (= :list (:type node))
    (let [[h nm & more] (:children node)]
      (when (and h nm
                 (= :symbol (:type h))
                 (#{"def" "defonce"} (:value h))
                 (= :symbol (:type nm))
                 (seq more))
        (let [v (last more)]
          (when (and (= :string (:type v))
                     (secret-like-value? (:value v))
                     (re-find n-re (:value nm))
                     (not (and nn-re (re-find nn-re (:value nm)))))
            [{:node node}]))))))

(def ^:private sql-re
  #"(?is)\b(?:select\b.+\bfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|drop\s+table\b|union\s+select\b)")

(defn- match-sql [_spec node ctx]
  (when-let [{:keys [head args]} (call-info node)]
    (when (some #{"clojure.core/str" "clojure.core/format"} (res/head-keys ctx head))
      (let [literal-text (str/join " " (map :value (filter #(= :string (:type %)) args)))]
        (when (and (re-find sql-re literal-text)
                   (not (every? static? args)))
          [{:node node :hint? (hint? node)}])))))

(defn- match-inner-html [_spec node ctx]
  (when-let [{:keys [head args]} (call-info node)]
    (when (= "clojure.core/set!" (first (res/head-keys ctx head)))
      (let [[target value] args
            t-head (when (and target (= :list (:type target))) (p/head target))]
        (when (and t-head
                   (re-find #"^\.-(?:inner|outer)HTML$" t-head)
                   value
                   (not (static? value)))
          [{:node node :hint? (hint? value)}])))))

(def ^:private matchers
  [[:call              match-call]
   [:node-type         match-node-type]
   [:keyword           match-keyword]
   [:map-pair          match-map-pair]
   [:def-string        match-def-string]
   [:sql-string-building match-sql]
   [:set-inner-html    match-inner-html]])

(defn- run-spec [spec node ctx]
  (some (fn [[k f]] (when (contains? spec k) (f spec node ctx))) matchers))

(defn- rule-matches [rule node ctx]
  (let [m     (:match rule)
        specs (if (map? m) [m] m)]
    (mapcat #(run-spec % node ctx) specs)))

;; ---------------------------------------------------------------------------
;; Walking the tree

(def ^:private threading
  {"clojure.core/->"      :first
   "clojure.core/some->"  :first
   "clojure.core/->>"     :last
   "clojure.core/some->>" :last})

(defn- virtual-call [at children]
  {:type :list :line (:line at) :col (:col at) :virtual true :children (vec children)})

(defn- thread-calls
  "Desugar (-> x f (g a)) into the calls (f x) and (g (f x) a) so that
  rules see the real argument. Returns a vector of synthetic call nodes."
  [pos node]
  (let [[_ x & steps] (:children node)]
    (if-not x
      []
      (loop [prev x, steps steps, acc []]
        (if-let [step (first steps)]
          (let [call (case (:type step)
                       :symbol (virtual-call step [step prev])
                       :list   (let [[h & more] (:children step)]
                                 (when h
                                   (virtual-call step (if (= pos :last)
                                                        (concat [h] more [prev])
                                                        (concat [h prev] more)))))
                       nil)]
            (recur (or call prev) (rest steps) (cond-> acc call (conj call))))
          acc)))))

(declare walk)

(defn- walk-threaded [ctx opts node pos]
  (let [[_ x & steps] (:children node)]
    (concat [node]
            (when x (walk ctx opts x))
            (thread-calls pos node)
            (mapcat (fn [step]
                      (case (:type step)
                        :list   (mapcat #(walk ctx opts %) (rest (:children step)))
                        :symbol nil
                        (walk ctx opts step)))
                    steps))))

(defn- walk
  "Seq of nodes to check. Skips (comment ...) forms and quoted data."
  [ctx opts node]
  (case (:type node)
    (:string :symbol :keyword :number :char :regex) [node]
    :quote []
    (let [hd (when (= :list (:type node)) (p/head node))]
      (cond
        (and hd (#{"quote" "clojure.core/quote"} hd))
        []

        (and hd (not (:include-comments? opts)) (#{"comment" "clojure.core/comment"} hd))
        []

        (and hd (threading (res/qualify ctx hd)))
        (walk-threaded ctx opts node (threading (res/qualify ctx hd)))

        :else
        (cons node (mapcat #(walk ctx opts %) (:children node)))))))

;; ---------------------------------------------------------------------------
;; Findings

(defn- ->finding [rule m lines file]
  (let [node (:node m)
        line (:line node)
        sev  (or (:severity m)
                 (if (:static? m) :low (:severity rule)))
        conf (or (:confidence m)
                 (cond (:static? m) :low
                       (:hint? m)   :high
                       :else        :medium))]
    {:rule       (:id rule)
     :severity   sev
     :confidence conf
     :cwe        (:cwe rule)
     :title      (:title rule)
     :advice     (:advice rule)
     :file       file
     :line       line
     :col        (:col node)
     :code       (some-> (get lines (dec line)) str/trim)}))

(defn- ignore-ids
  "If the line has a seclint:ignore marker, returns :all or a set of rule names."
  [^String l]
  (when-let [[_ ids] (re-find #"seclint:ignore(?:\s+([\w:\-, ]+))?" l)]
    (if (str/blank? ids)
      :all
      (set (str/split (str/trim ids) #"[\s,]+")))))

(defn- suppressed?
  "A finding is suppressed by `seclint:ignore [rule-id ...]` on its own line,
  or on a comment-only line directly above."
  [lines line rule-id]
  (let [applies? (fn [l]
                   (let [ids (ignore-ids l)]
                     (or (= :all ids)
                         (and (set? ids) (contains? ids (name rule-id))))))
        same     (get lines (dec line))
        above    (get lines (- line 2))]
    (boolean (or (and same (applies? same))
                 (and above
                      (str/starts-with? (str/triml above) ";")
                      (applies? above))))))

(defn sort-findings [findings]
  (sort-by (juxt (comp - rules/severity-rank :severity) :file :line :col) findings))

(defn- one-per-site
  "Nested sinks such as (slurp (io/file ...)) trigger the same rule twice on a
  line; keep the first (leftmost) one."
  [findings]
  (map first (vals (group-by (juxt :rule :file :line) findings))))

(defn scan-source
  "Scan Clojure source text. Options: :file (label) and :include-comments?.
  Returns a vector of findings, most severe first."
  ([src] (scan-source src {}))
  ([^String src {:keys [file include-comments?] :or {file "<string>"}}]
   (let [forms (p/parse src)
         ctx   (res/context forms)
         lines (vec (str/split-lines src))
         opts  {:include-comments? include-comments?}]
     (->> (for [form  forms
                node  (walk ctx opts form)
                rule  rules/rules
                m     (rule-matches rule node ctx)
                :let  [f (->finding rule m lines file)]
                :when (not (suppressed? lines (:line f) (:rule f)))]
            f)
          sort-findings
          one-per-site
          sort-findings
          vec))))

;; ---------------------------------------------------------------------------
;; Files

(def ^:private source-ext #{"clj" "cljs" "cljc" "cljx" "bb" "edn"})
(def ^:private skip-dirs #{".git" "node_modules" "target" ".cpcache" ".shadow-cljs" ".clj-kondo" ".lsp" "out"})

(defn- ext [^File f]
  (let [n (.getName f) i (str/last-index-of n ".")]
    (when (and i (pos? i)) (subs n (inc i)))))

(defn- walk-dir [^File dir]
  (mapcat (fn [^File c]
            (cond
              (.isDirectory c) (if (skip-dirs (.getName c)) [] (walk-dir c))
              (and (.isFile c) (source-ext (ext c))) [c]
              :else []))
          (sort (.listFiles dir))))

(defn find-files
  "Expand paths (files or directories) into source files.
  Returns {:files [File ...] :missing [path ...]}."
  [paths]
  (reduce (fn [acc path]
            (let [f (io/file path)]
              (cond
                (.isFile f)      (update acc :files conj f)
                (.isDirectory f) (update acc :files into (walk-dir f))
                :else            (update acc :missing conj path))))
          {:files [] :missing []}
          paths))

(defn scan-file [^File f {:keys [engine] :as opts}]
  (let [src  (slurp f)
        opts (assoc opts :file (.getPath f))]
    (case engine
      :regex (regex/scan-source src opts)
      (scan-source src opts))))

(defn scan-paths
  "Scan files/directories. Returns {:files n :findings [...] :missing [...]}."
  [paths opts]
  (let [{:keys [files missing]} (find-files paths)
        findings (mapcat (fn [f]
                           (try (scan-file f opts)
                                (catch Exception e
                                  (binding [*out* *err*]
                                    (println (str "seclint: could not scan " (.getPath ^File f) ": " (.getMessage e))))
                                  [])))
                         files)]
    {:files    (count files)
     :missing  missing
     :findings (vec (sort-findings findings))}))
