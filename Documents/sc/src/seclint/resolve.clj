(ns seclint.resolve
  "Purely syntactic name resolution.

  We never load namespaces. Instead we read a file's ns / require forms to
  learn its aliases and :refer'd names, so that `edn/read-string` and
  `clojure.core/read-string` are told apart, and `sh/sh` is understood
  as clojure.java.shell/sh."
  (:require [clojure.string :as str]))

(defn- sym-value [node]
  (when (= :symbol (:type node)) (:value node)))

(defn- libspec-entries
  "Turn a libspec node into a seq of {:lib \"ns\" :as \"alias\" :refers [..]}."
  ([spec] (libspec-entries spec nil))
  ([spec prefix]
   (case (:type spec)
     :symbol [{:lib (str prefix (:value spec))}]
     :quote  (mapcat #(libspec-entries % prefix) (:children spec))
     :vector (let [[lib & opts] (:children spec)
                   lib-name     (sym-value lib)]
               (cond
                 (nil? lib-name) []
                 ;; prefix list: [clojure.java [shell :as sh] [io :as io]]
                 (and (seq opts) (not= :keyword (:type (first opts))))
                 (mapcat #(libspec-entries % (str prefix lib-name ".")) opts)
                 :else
                 (let [pairs  (partition 2 2 nil opts)
                       as     (some (fn [[k v]] (when (and (= ":as" (:value k)) v) (sym-value v))) pairs)
                       refers (some (fn [[k v]] (when (= ":refer" (:value k)) (keep sym-value (:children v)))) pairs)]
                   [{:lib (str prefix lib-name) :as as :refers refers}])))
     [])))

(defn- form-entries
  "Libspec entries declared by a top-level (ns ...) or (require ...) form."
  [form]
  (when (= :list (:type form))
    (let [[hd & more] (:children form)]
      (case (:value hd)
        "ns"      (for [clause more
                        :when (and (= :list (:type clause))
                                   (#{":require" ":require-macros"} (:value (first (:children clause)))))
                        spec  (rest (:children clause))
                        entry (libspec-entries spec)]
                    entry)
        "require" (mapcat libspec-entries more)
        nil))))

(defn context
  "Build {:aliases {\"edn\" \"clojure.edn\"} :refers {\"sh\" \"clojure.java.shell/sh\"}}
  from a file's top-level forms."
  [forms]
  (let [entries (mapcat form-entries forms)]
    {:aliases (into {} (keep (fn [{:keys [lib as]}] (when as [as lib]))) entries)
     :refers  (into {} (mapcat (fn [{:keys [lib refers]}]
                                 (map (fn [r] [r (str lib "/" r)]) refers)))
                    entries)}))

(defn qualify
  "Best-effort fully-qualified name for a symbol's text."
  [{:keys [aliases refers]} ^String s]
  (let [i (str/index-of s "/")]
    (cond
      ;; (.method obj) interop
      (str/starts-with? s ".")
      s

      ;; alias/name or full.ns/name or Class/staticMethod
      (and i (pos? i) (< i (dec (count s))))
      (let [prefix (subs s 0 i)]
        (str (get aliases prefix prefix) "/" (subs s (inc i))))

      (contains? refers s)
      (get refers s)

      ;; Constructors (Foo.) and bare class names
      (or (str/ends-with? s ".") (Character/isUpperCase (.charAt s 0)))
      s

      :else
      (str "clojure.core/" s))))

(defn- simple-name
  "Drop a lowercase package prefix: java.security.MessageDigest/getInstance
  becomes MessageDigest/getInstance."
  [s]
  (str/replace s #"^(?:[a-z0-9_]+\.)+(?=[A-Z])" ""))

(defn head-keys
  "Names a call head may be matched under: the qualified name, plus the
  package-less form for Java classes."
  [ctx s]
  (let [q (qualify ctx s)]
    (distinct [q (simple-name q)])))
