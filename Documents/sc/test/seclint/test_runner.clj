(ns seclint.test-runner
  (:require [clojure.test :as t]
            [seclint.cli-test]
            [seclint.parse-test]
            [seclint.scan-test]))

(defn -main [& _]
  (let [{:keys [fail error]} (t/run-tests 'seclint.parse-test
                                          'seclint.scan-test
                                          'seclint.cli-test)]
    (flush)
    (System/exit (if (zero? (+ fail error)) 0 1))))
