;; Code that must produce ZERO findings (at any severity).
(ns fixtures.safe
  (:require [clojure.edn :as edn]
            [clojure.java.jdbc :as jdbc]
            [clojure.string :as str])
  (:import (java.security MessageDigest)))

(defn parse-body [body]
  (edn/read-string body))

(defn find-user [db id]
  (jdbc/query db ["SELECT * FROM users WHERE id = ?" id]))

(defn sha256 [s]
  (.digest (MessageDigest/getInstance "SHA-256") (.getBytes s)))

(def db-config {:user "app" :password (System/getenv "DB_PASSWORD")})

(def password-field "password")

(def token-url "https://auth.example.com/token")

(defn greet [name]
  (str "Hello, " name))

(defn static-sql []
  (str "SELECT * FROM users " "WHERE active = true"))

(defn quoted []
  '(eval user-input))

(defn doc []
  "(read-string \"inside a string\") (eval x)")

;; (eval (read-string "commented out"))

#_(eval (read-string "discarded"))

(comment
  (eval (read-string "repl experiment"))
  (clojure.java.shell/sh "rm" "-rf" "/tmp/x"))
