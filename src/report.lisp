(in-package #:ldap-parity)

(defun print-matrix ()
  (format t "~&ldap-parity matrix~%")
  (format t "  bind / search / add vs OpenLDAP at ~a:~a (skip if unreachable)~%"
          *ldap-host* *ldap-port*)
  (format t "  AD-schema fixture: optional; skip when sAMAccountName is absent~%")
  (format t "  PARITY=0 or LDAP_PARITY=0 forces skip~%"))
