;; Deliberately vulnerable code used as a test fixture. NEVER load or run this.
;; Each "; EXPECT rule-id" marker lists the rules that must fire on that line;
;; the test fails on any missing OR unexpected finding.
(ns fixtures.vulnerable
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.java.shell :as sh]
            [clojure.java.io :as io]
            [clj-http.client :as http]
            [hiccup.util :as hu]
            [ring.util.response :as resp])
  (:import (java.security MessageDigest)
           (javax.crypto Cipher)
           (java.io ObjectInputStream)))

(def api-secret "s3cr3t-do-not-use")                          ; EXPECT hardcoded-secret

(def db-config {:user "app" :password "hunter2-example"})     ; EXPECT hardcoded-secret

(def http-opts {:insecure? true})                             ; EXPECT insecure-tls

(defn parse-body [body]
  (read-string body))                                         ; EXPECT unsafe-read-string

(defn run-expr [params]
  (eval (read-string (:expr params))))                        ; EXPECT eval unsafe-read-string

(defn run-file [params]
  (load-file (:path params)))                                 ; EXPECT load-code

(defn handler-by-name [params]
  ((requiring-resolve (symbol (:handler params))) params))    ; EXPECT dynamic-resolve

(def evil #=(+ 1 2))                                          ; EXPECT reader-eval

(defn find-user [db id]
  (jdbc/query db [(str "SELECT * FROM users WHERE id = " id)])) ; EXPECT sql-string-building

(defn find-by-name [db n]
  (jdbc/query db [(format "select * from users where name = '%s'" n)])) ; EXPECT sql-string-building

(defn ping [params]
  (sh/sh "ping" "-c" "1" (:host params)))                     ; EXPECT shell-exec

(defn run-cmd [cmd]
  (.exec (Runtime/getRuntime) cmd))                           ; EXPECT shell-exec

(defn load-blob [in]
  (.readObject (ObjectInputStream. in)))                      ; EXPECT unsafe-deserialization

(defn parse-xml [s]
  (clojure.xml/parse (java.io.ByteArrayInputStream. (.getBytes s)))) ; EXPECT xxe

(defn md5-hex [s]
  (.digest (MessageDigest/getInstance "MD5") (.getBytes s)))  ; EXPECT weak-hash

(defn encrypt-ecb []
  (Cipher/getInstance "AES/ECB/PKCS5Padding"))                ; EXPECT weak-cipher

(defn render-bio [params]
  [:div (hu/raw-string (:bio params))])                       ; EXPECT xss-raw-html

(defn show [el params]
  (set! (.-innerHTML el) (:bio params)))                      ; EXPECT xss-dangerous-html

(defn react-bio [params]
  [:div {:dangerouslySetInnerHTML {:__html (:bio params)}}])  ; EXPECT xss-dangerous-html

(defn read-upload [params]
  (slurp (io/file "/srv/uploads" (:filename params))))        ; EXPECT path-traversal

(defn fetch [params]
  (http/get (:url params)))                                   ; EXPECT ssrf

(defn go-next [params]
  (resp/redirect (:next params)))                             ; EXPECT open-redirect

(defn threaded [raw-text]
  (-> raw-text read-string))                                  ; EXPECT unsafe-read-string

(defn threaded-shell [user-cmd]
  (->> user-cmd (sh/sh "bash" "-c")))                         ; EXPECT shell-exec
