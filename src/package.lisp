(defpackage #:ldap-parity
  (:use #:cl)
  (:export #:*ldap-host*
           #:*ldap-port*
           #:env-off-p
           #:live-requested-p
           #:tcp-reachable-p
           #:ldap-reachable-p
           #:read-ldap-pdu
           #:decode-ldap-message
           #:encode-ldap-add-request
           #:call-with-ldap-connection
           #:ldap-bind-search-add
           #:print-matrix))

(in-package #:ldap-parity)
