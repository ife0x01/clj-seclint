(ns vulnerable-app
  "A small, deliberately insecure Ring-style app. DO NOT deploy it.
  Scan it:   sh scripts/clj -m seclint.core examples/vulnerable_app.clj
  Fixed twin: examples/fixed_app.clj"
  (:require [clojure.java.io :as io]
            [clojure.java.jdbc :as jdbc]
            [clojure.java.shell :as sh]
            [clj-http.client :as http]
            [ring.util.response :as resp])
  (:import (java.security MessageDigest)))

(def jwt-secret "my-super-secret-signing-key")

(defn password-hash [pw]
  (.digest (MessageDigest/getInstance "MD5") (.getBytes ^String pw)))

(defn get-user [db {:keys [params]}]
  (jdbc/query db [(str "SELECT * FROM users WHERE id = " (:id params))]))

(defn download [{:keys [params]}]
  {:body (slurp (io/file "/srv/files" (:file params)))})

(defn calc [{:keys [params]}]
  {:body (str (eval (read-string (:expr params))))})

(defn ping [{:keys [params]}]
  {:body (:out (sh/sh "ping" "-c" "1" (:host params)))})

(defn fetch-url [{:keys [params]}]
  {:body (:body (http/get (:url params)))})

(defn go [{:keys [params]}]
  (resp/redirect (:next params)))
