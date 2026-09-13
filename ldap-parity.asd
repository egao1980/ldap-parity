(defsystem "ldap-parity"
  :version "0.1.0"
  :description "Interop canary: ldap-protocol vs dockerized OpenLDAP"
  :author "egao1980"
  :license "MIT"
  :depends-on ("ldap-protocol"
               "usocket"
               "uiop")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "probe")
               (:file "ber")
               (:file "session")
               (:file "report"))
  :in-order-to ((test-op (test-op "ldap-parity/tests"))))

(defsystem "ldap-parity/tests"
  :depends-on ("ldap-parity" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "live"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "ldap-parity tests failed"))))
