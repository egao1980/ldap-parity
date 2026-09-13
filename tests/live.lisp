(in-package #:ldap-parity/tests)

(deftest probe-returns-boolean
  (ok (member (tcp-reachable-p *ldap-host* *ldap-port*) '(t nil))))

(deftest openldap-bind-search-add
  (cond
    ((not (live-requested-p "LDAP_PARITY"))
     (skip "PARITY=0 or LDAP_PARITY=0 — live LDAP canary skipped"))
    ((not (tcp-reachable-p *ldap-host* *ldap-port*))
     (skip (format nil "OpenLDAP unreachable at ~a:~a — live canary skipped"
                   *ldap-host* *ldap-port*)))
    (t
     (let ((result (ldap-bind-search-add)))
       (ok (consp (getf result :entries)))
       (ok (search "cn=canary-" (getf result :added)))))))

(deftest openldap-ad-schema-optional
  (cond
    ((not (live-requested-p "LDAP_PARITY"))
     (skip "PARITY=0 or LDAP_PARITY=0 — AD fixture skipped"))
    ((not (tcp-reachable-p *ldap-host* *ldap-port*))
     (skip "OpenLDAP unreachable — AD fixture skipped"))
    ((not (or (uiop:getenv "LDAP_PARITY_AD")
              (live-requested-p "LDAP_PARITY_AD")))
     ;; Probe the tree; skip when the optional schema was not loaded.
     (let ((hits (ignore-errors (ldap-parity::search-samaccountname))))
       (if (and hits (plusp (length hits)))
           (ok (stringp (getf (first hits) :dn)))
           (skip "optional AD-schema fixture not loaded (sAMAccountName absent)"))))
    (t
     (let ((hits (ldap-parity::search-samaccountname)))
       (if (plusp (length hits))
           (ok (stringp (getf (first hits) :dn)))
           (skip "LDAP_PARITY_AD set but no sAMAccountName entries"))))))
