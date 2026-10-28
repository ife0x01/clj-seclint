(ns seclint.core
  "Command-line entry point."
  (:require [clojure.string :as str]
            [seclint.report :as report]
            [seclint.rules :as rules]
            [seclint.scan :as scan]))

(def usage
  "clj-seclint: static checker for unsafe patterns in Clojure code

usage: seclint [options] <file-or-dir>...

options:
  -f, --format <text|edn|json>       output format (default: text)
      --min-severity <low|medium|high>
                                     hide findings below this level (default: medium)
      --fail-on <low|medium|high|none>
                                     exit 1 if a shown finding is at least this severe
                                     (default: high)
      --engine <forms|regex>         forms = parser-based (default), regex = line baseline
      --include-comments             also scan inside (comment ...) forms
  -h, --help                         show this help

Suppress a finding with a comment on the same line or the line above:
  ;; seclint:ignore                  (all rules)
  ;; seclint:ignore eval, ssrf       (named rules)

exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or path error")

(def ^:private severities #{:low :medium :high})
(def ^:private formats #{:text :edn :json})
(def ^:private engines #{:forms :regex})

(defn- option-value [opts k flag allowed more]
  (let [v (some-> (first more) keyword)]
    (cond
      (nil? v)                   [(assoc opts :error (str flag " needs a value")) more]
      (not (contains? allowed v)) [(assoc opts :error (str "invalid value for " flag ": " (name v))) more]
      :else                      [(assoc opts k v) (rest more)])))

(defn parse-args [args]
  (loop [args (seq args)
         opts {:paths [] :format :text :min-severity :medium :fail-on :high :engine :forms}]
    (cond
      (nil? args)   opts
      (:error opts) opts
      :else
      (let [[a & more] args]
        (case a
          ("-h" "--help")    (assoc opts :help true)
          ("-f" "--format")  (let [[o r] (option-value opts :format a formats more)] (recur (seq r) o))
          "--min-severity"   (let [[o r] (option-value opts :min-severity a severities more)] (recur (seq r) o))
          "--fail-on"        (let [[o r] (option-value opts :fail-on a (conj severities :none) more)] (recur (seq r) o))
          "--engine"         (let [[o r] (option-value opts :engine a engines more)] (recur (seq r) o))
          "--include-comments" (recur (seq more) (assoc opts :include-comments? true))
          (if (str/starts-with? a "-")
            (assoc opts :error (str "unknown option: " a))
            (recur (seq more) (update opts :paths conj a))))))))

(defn- err-println [& xs]
  (binding [*out* *err*] (apply println xs)))

(defn run
  "Run the CLI with an arg vector. Prints results and returns an exit code."
  [args]
  (let [{:keys [help error paths min-severity fail-on engine include-comments?] fmt :format} (parse-args args)]
    (cond
      help
      (do (println usage) 0)

      error
      (do (err-println (str "seclint: " error)) (err-println) (err-println usage) 2)

      (empty? paths)
      (do (err-println usage) 2)

      :else
      (let [{:keys [files findings missing]} (scan/scan-paths paths {:engine engine
                                                                    :include-comments? include-comments?})]
        (if (seq missing)
          (do (doseq [m missing] (err-println (str "seclint: no such file or directory: " m))) 2)
          (let [rank    #(rules/severity-rank (:severity %))
                shown   (filterv #(>= (rank %) (rules/severity-rank min-severity)) findings)
                summary (report/summary shown files)]
            (print (case fmt
                     :text (report/text shown summary)
                     :edn  (report/edn shown summary)
                     :json (report/json shown summary)))
            (flush)
            (if (and (not= fail-on :none)
                     (some #(>= (rank %) (rules/severity-rank fail-on)) shown))
              1
              0)))))))

(defn -main [& args]
  (let [code (run args)]
    (flush)
    (System/exit code)))
