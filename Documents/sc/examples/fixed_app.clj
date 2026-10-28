(ns fixed-app
  "The same app as vulnerable_app.clj with each issue fixed.
  clj-seclint should report nothing here."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.jdbc :as jdbc]
            [clj-http.client :as http]
            [ring.util.response :as resp])
  (:import (java.net InetAddress)
           (java.security MessageDigest)))

(def jwt-secret (System/getenv "JWT_SECRET"))

(defn file-digest [bytes]
  (.digest (MessageDigest/getInstance "SHA-256") bytes))

(defn get-user [db {:keys [params]}]
  (jdbc/query db ["SELECT * FROM users WHERE id = ?" (parse-long (str (:id params)))]))

(defn- resolve-under
  "Resolve rel under base, or nil if it would escape base."
  [base rel]
  (let [root (.getCanonicalFile (io/file base))
        f    (.getCanonicalFile (io/file root rel))]
    (when (.startsWith (.getPath f) (str (.getPath root) java.io.File/separator))
      f)))

(defn download [{:keys [params]}]
  (if-let [f (resolve-under "/srv/files" (:file params))]
    {:body (slurp f)}
    {:status 404}))

(def ops {'+ + '- - '* *})

(defn calc [{:keys [params]}]
  (let [[op a b] (edn/read-string (:expr params))]
    (if-let [f (and (number? a) (number? b) (ops op))]
      {:body (str (f a b))}
      {:status 400})))

(defn valid-host [h]
  (when (re-matches #"[a-z0-9.-]{1,253}" (str h)) h))

(defn ping [{:keys [params]}]
  (if-let [host (valid-host (:host params))]
    {:body (str (.isReachable (InetAddress/getByName host) 1000))}
    {:status 400}))

(def status-urls {"api" "https://status.example.com/api"})

(defn fetch-status [{:keys [params]}]
  (if-let [url (get status-urls (:service params))]
    {:body (:body (http/get url))}
    {:status 404}))

(defn safe-target [t]
  (if (and (string? t) (re-matches #"/[A-Za-z0-9/_-]*" t)) t "/"))

(defn go [{:keys [params]}]
  (let [target (safe-target (:next params))]
    (resp/redirect target)))
