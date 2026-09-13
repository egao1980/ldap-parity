(in-package #:ldap-parity)

(defun encode-ldap-add-request (&key (message-id 1) dn attributes)
  "AddRequest (APPLICATION 8) using ldap-protocol BER writers."
  (flet ((vals-of (pair)
           (let ((v (cdr pair)))
             (cond
               ((null v) nil)
               ((and (consp v) (consp (car v))) (car v))
               ((listp v) v)
               (t (list v))))))
    (ldap-protocol::encode-ldap-message
     message-id
     (ldap-protocol::ber-encode-application
      8
      (ldap-protocol::concatenate-octets
       (ldap-protocol:ber-encode-octet-string dn)
       (apply #'ldap-protocol:ber-encode-sequence
              (mapcar
               (lambda (pair)
                 (ldap-protocol:ber-encode-sequence
                  (ldap-protocol:ber-encode-octet-string (string (car pair)))
                  (apply #'ldap-protocol:ber-encode-set
                         (mapcar (lambda (val)
                                   (ldap-protocol:ber-encode-octet-string
                                    (princ-to-string val)))
                                 (vals-of pair)))))
               attributes)))))))

(defun %raise-result (plist)
  (let ((code (or (getf plist :result-code) 80)))
    (unless (zerop code)
      (ldap-protocol:signal-ldap-error
       :result-code code
       :matched-dn (getf plist :matched-dn)
       :diagnostic (getf plist :diagnostic)
       :message (or (getf plist :diagnostic)
                    (format nil "LDAP result ~a" code))))
    plist))

(defun call-with-ldap-connection (fn &key (host *ldap-host*)
                                       (port *ldap-port*))
  (let ((sock (usocket:socket-connect host port
                                      :timeout 2
                                      :element-type '(unsigned-byte 8))))
    (unwind-protect
         (let* ((stream (usocket:socket-stream sock))
                (conn (ldap-protocol:make-ldap-connection
                       :host host :port port :stream stream)))
           (funcall fn conn stream))
      (ignore-errors (usocket:socket-close sock)))))

(defun ldap-bind-search-add (&key (host *ldap-host*)
                               (port *ldap-port*)
                               (dn nil)
                               (password nil)
                               (base nil))
  "Bind + subtree search + add via ldap-protocol request GFs / BER add.
   → plist (:entries … :added dn)."
  (let ((dn (or dn (%env "LDAP_PARITY_BIND_DN" "cn=admin,dc=example,dc=com")))
        (password (or password (%env "LDAP_PARITY_PASSWORD" "admin")))
        (base (or base (%env "LDAP_PARITY_BASE" "dc=example,dc=com"))))
    (call-with-ldap-connection
     (lambda (conn stream)
       (ldap-protocol:ldap-bind conn :dn dn :password password)
       (%raise-result (decode-ldap-message (read-ldap-pdu stream)))
       (ldap-protocol:ldap-search conn
                                  :base base
                                  :scope :sub
                                  :filter '(* "objectClass"))
       (let ((entries nil))
         (loop
           (let ((msg (decode-ldap-message (read-ldap-pdu stream))))
             (case (getf msg :op)
               (:search-entry (push msg entries))
               (:search-done
                (%raise-result msg)
                (return))
               (t (error 'ldap-protocol:ldap-protocol-error
                         :message (format nil "unexpected search PDU ~s"
                                          (getf msg :op)))))))
         (let* ((ou (%env "LDAP_PARITY_PEOPLE" "dc=example,dc=com"))
                (new-dn (format nil "cn=canary-~d,~a" (get-universal-time) ou))
                (add (encode-ldap-add-request
                      :message-id (1+ (ldap-protocol::ldap-connection-message-id conn))
                      :dn new-dn
                      :attributes '(("objectClass" "inetOrgPerson")
                                    ("cn" "canary")
                                    ("sn" "Parity")))))
           (incf (ldap-protocol::ldap-connection-message-id conn))
           (write-sequence add stream)
           (force-output stream)
           (%raise-result (decode-ldap-message (read-ldap-pdu stream)))
           (ldap-protocol:ldap-unbind conn)
           (list :entries (nreverse entries) :added new-dn))))
     :host host :port port)))

(defun search-samaccountname (&key (host *ldap-host*)
                                (port *ldap-port*)
                                (base nil))
  "Optional AD-schema fixture: search for sAMAccountName. Empty → skip."
  (let ((dn (%env "LDAP_PARITY_BIND_DN" "cn=admin,dc=example,dc=com"))
        (password (%env "LDAP_PARITY_PASSWORD" "admin"))
        (base (or base (%env "LDAP_PARITY_BASE" "dc=example,dc=com"))))
    (call-with-ldap-connection
     (lambda (conn stream)
       (ldap-protocol:ldap-bind conn :dn dn :password password)
       (%raise-result (decode-ldap-message (read-ldap-pdu stream)))
       (ldap-protocol:ldap-search conn
                                  :base base
                                  :scope :sub
                                  :filter '(* "sAMAccountName"))
       (let ((hits nil))
         (loop
           (let ((msg (decode-ldap-message (read-ldap-pdu stream))))
             (case (getf msg :op)
               (:search-entry (push msg hits))
               (:search-done (return))
               (t (return)))))
         (nreverse hits)))
     :host host :port port)))
