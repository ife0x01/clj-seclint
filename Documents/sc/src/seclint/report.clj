(ns seclint.report
  "Output formatters: human text, EDN and JSON (no dependencies)."
  (:require [clojure.pprint :as pp]
            [clojure.string :as str]))

(defn summary [findings files]
  (let [by (frequencies (map :severity findings))]
    {:files  files
     :total  (count findings)
     :high   (get by :high 0)
     :medium (get by :medium 0)
     :low    (get by :low 0)}))

(defn summary-line [{:keys [files total high medium low]}]
  (format "%d finding%s (%d high, %d medium, %d low) in %d file%s scanned"
          total (if (= 1 total) "" "s") high medium low files (if (= 1 files) "" "s")))

(defn- finding-text [{:keys [file line col severity confidence rule cwe title advice code]}]
  (str file ":" line ":" col "  " (str/upper-case (name severity)) "  " (name rule)
       "  [" cwe ", confidence: " (name confidence) "]\n"
       "  " title "\n"
       (when code (str "  > " code "\n"))
       "  fix: " advice "\n"))

(defn text [findings summary]
  (str (str/join "\n" (map finding-text findings))
       (when (seq findings) "\n")
       (summary-line summary)
       "\n"))

(defn edn [findings summary]
  (with-out-str (pp/pprint {:summary summary :findings (vec findings)})))

(defn- json-str [s]
  (str "\""
       (str/replace s #"[\u0000-\u001f\"\\]"
                    (fn [^String m]
                      (case m
                        "\"" "\\\""
                        "\\" "\\\\"
                        "\n" "\\n"
                        "\r" "\\r"
                        "\t" "\\t"
                        (format "\\u%04x" (int (.charAt m 0))))))
       "\""))

(defn- ->json [x]
  (cond
    (nil? x)        "null"
    (string? x)     (json-str x)
    (keyword? x)    (json-str (name x))
    (number? x)     (str x)
    (boolean? x)    (str x)
    (map? x)        (str "{" (str/join "," (map (fn [[k v]] (str (json-str (name k)) ":" (->json v))) x)) "}")
    (sequential? x) (str "[" (str/join "," (map ->json x)) "]")
    :else           (json-str (str x))))

(defn json [findings summary]
  (str (->json {:summary summary :findings (vec findings)}) "\n"))
