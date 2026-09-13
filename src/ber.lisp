(in-package #:ldap-parity)

;;; Minimal BER reader for LDAPMessage responses (bind / search / add).
;;; Request encoding is reused from ldap-protocol.

(defun %read-exact (stream n)
  (let ((buf (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
    (let ((got (read-sequence buf stream)))
      (unless (= got n)
        (error 'ldap-protocol:ldap-unavailable
               :message (format nil "unexpected EOF (got ~d of ~d)" got n)))
      buf)))

(defun read-ldap-pdu (stream)
  "Read one definite-length BER PDU (LDAPMessage SEQUENCE)."
  (let ((tag (read-byte stream))
        (len-first (read-byte stream)))
    (multiple-value-bind (length length-octets)
        (if (< len-first 128)
            (values len-first (vector len-first))
            (let* ((n (logand len-first #x7F))
                   (raw (%read-exact stream n))
                   (len 0))
              (loop for b across raw do (setf len (+ (ash len 8) b)))
              (values len (concatenate '(vector (unsigned-byte 8))
                                       (vector len-first) raw))))
      (let ((content (%read-exact stream length)))
        (concatenate '(simple-array (unsigned-byte 8) (*))
                     (vector tag) length-octets content)))))

(defstruct ber-cur octets pos end)

(defun %make-cur (octets &optional (start 0) (end (length octets)))
  (make-ber-cur :octets octets :pos start :end end))

(defun %ber-int (octets)
  (when (zerop (length octets))
    (return-from %ber-int 0))
  (let ((v 0))
    (loop for b across octets do (setf v (+ (ash v 8) b)))
    (if (>= (aref octets 0) #x80)
        (- v (ash 1 (* 8 (length octets))))
        v)))

(defun %ber-string (octets)
  (map 'string #'code-char octets))

(defun ber-take-tlv (cur)
  "→ (values tag constructed-p content). Advances CUR."
  (when (>= (ber-cur-pos cur) (ber-cur-end cur))
    (error 'ldap-protocol:ldap-protocol-error
           :message "BER underrun"))
  (let* ((octets (ber-cur-octets cur))
         (pos (ber-cur-pos cur))
         (tag (aref octets pos))
         (constructed (logbitp 5 tag))
         (len-first (aref octets (1+ pos)))
         (len 0)
         (hdr-end 0))
    (if (< len-first 128)
        (setf len len-first
              hdr-end (+ pos 2))
        (let ((n (logand len-first #x7F))
              (v 0)
              (p (+ pos 2)))
          (dotimes (i n)
            (setf v (+ (ash v 8) (aref octets (+ p i)))))
          (setf len v
                hdr-end (+ p n))))
    (let ((content-end (+ hdr-end len)))
      (unless (<= content-end (ber-cur-end cur))
        (error 'ldap-protocol:ldap-protocol-error
               :message "BER length exceeds PDU"))
      (setf (ber-cur-pos cur) content-end)
      (values (logand tag #x1F)
              constructed
              (subseq octets hdr-end content-end)
              tag))))

(defun %op-name (universal-tag)
  (case universal-tag
    (#x61 :bind-response)
    (#x64 :search-entry)
    (#x65 :search-done)
    (#x69 :add-response)
    (t :unknown)))

(defun %decode-ldap-result (content)
  (let ((cur (%make-cur content)))
    (multiple-value-bind (tag c code-octets)
        (ber-take-tlv cur)
      (declare (ignore c))
      (unless (or (= tag 10) (= tag 2))
        (error 'ldap-protocol:ldap-protocol-error
               :message (format nil "expected resultCode, tag ~d" tag)))
      (multiple-value-bind (dn-tag dn-c dn-octets)
          (ber-take-tlv cur)
        (declare (ignore dn-c))
        (unless (= dn-tag 4)
          (error 'ldap-protocol:ldap-protocol-error
                 :message (format nil "expected matchedDN, tag ~d" dn-tag)))
        (multiple-value-bind (diag-tag diag-c diag-octets)
            (ber-take-tlv cur)
          (declare (ignore diag-c))
          (unless (= diag-tag 4)
            (error 'ldap-protocol:ldap-protocol-error
                   :message (format nil "expected diagnostic, tag ~d" diag-tag)))
          (list :result-code (%ber-int code-octets)
                :matched-dn (%ber-string dn-octets)
                :diagnostic (%ber-string diag-octets)))))))

(defun %decode-attributes (content)
  (let ((cur (%make-cur content))
        (attrs nil))
    (loop while (< (ber-cur-pos cur) (ber-cur-end cur))
          do (multiple-value-bind (tag c attr-octets)
                 (ber-take-tlv cur)
               (declare (ignore c))
               (unless (= tag #x10) ; SEQUENCE low 5 bits of 0x30
                 ;; 0x30 & 0x1F = 0x10
                 tag)
               (let* ((acur (%make-cur attr-octets))
                      (type (multiple-value-bind (tt tc to)
                                (ber-take-tlv acur)
                              (declare (ignore tt tc))
                              (%ber-string to)))
                      (vals (multiple-value-bind (vt vc vo)
                                (ber-take-tlv acur)
                              (declare (ignore vt vc))
                              (let ((vcur (%make-cur vo))
                                    (out nil))
                                (loop while (< (ber-cur-pos vcur) (ber-cur-end vcur))
                                      do (multiple-value-bind (xt xc xo)
                                             (ber-take-tlv vcur)
                                           (declare (ignore xt xc))
                                           (push (%ber-string xo) out)))
                                (nreverse out)))))
                 (push (cons type vals) attrs))))
    (nreverse attrs)))

(defun decode-ldap-message (octets)
  "Parse an LDAPMessage PDU into a plist (:message-id :op …)."
  (let ((cur (%make-cur octets)))
    (multiple-value-bind (tag constructed content universal)
        (ber-take-tlv cur)
      (declare (ignore constructed))
      (unless (and (= tag #x10) (= universal #x30))
        (error 'ldap-protocol:ldap-protocol-error
               :message (format nil "expected LDAPMessage SEQUENCE, tag 0x~2,'0x"
                                universal)))
      (let ((inner (%make-cur content)))
        (multiple-value-bind (id-tag id-c id-octets)
            (ber-take-tlv inner)
          (declare (ignore id-c))
          (unless (= id-tag 2)
            (error 'ldap-protocol:ldap-protocol-error
                   :message "LDAPMessage missing messageID"))
          (multiple-value-bind (op-tag op-c op-content op-universal)
              (ber-take-tlv inner)
            (declare (ignore op-tag op-c))
            (let ((op (%op-name op-universal))
                  (mid (%ber-int id-octets)))
              (case op
                (:search-entry
                 (let ((ecur (%make-cur op-content)))
                   (multiple-value-bind (dn-tag dn-c dn-octets)
                       (ber-take-tlv ecur)
                     (declare (ignore dn-tag dn-c))
                     (multiple-value-bind (at-tag at-c at-octets)
                         (ber-take-tlv ecur)
                       (declare (ignore at-tag at-c))
                       (list :message-id mid :op op
                             :dn (%ber-string dn-octets)
                             :attributes (%decode-attributes at-octets))))))
                ((:bind-response :search-done :add-response)
                 (append (list :message-id mid :op op)
                         (%decode-ldap-result op-content)))
                (t (list :message-id mid :op op))))))))))
