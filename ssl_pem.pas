unit ssl_pem;

interface
uses ssl_types;

var
   PEM_read_bio_PrivateKey: function(bp: PBIO; var x: PEVP_PKEY; cb: pem_password_cb; u: pointer): PEVP_PKEY; cdecl = nil;
   PEM_read_PrivateKey: function(var fp: FILE; var x: PEVP_PKEY; cb: pem_password_cb; u: pointer): PEVP_PKEY; cdecl = nil;
   PEM_write_bio_PrivateKey: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
   PEM_write_PrivateKey: function(var fp: FILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: Pointer): TC_INT; cdecl = nil;

   PEM_write_bio_PKCS8PrivateKey: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
   PEM_write_PKCS8PrivateKey: function(var fp: FILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: Pointer): TC_INT; cdecl = nil;

   PEM_write_bio_PKCS8PrivateKey_nid: function (bp: PBIO; x: PEVP_PKEY; nid: TC_INT; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
   PEM_write_PKCS8PrivateKey_nid: function(var fp: FILE; x: PEVP_PKEY; nid: TC_INT; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: Pointer): TC_INT; cdecl = nil;

  PEM_read_bio_PUBKEY: function(bp: PBIO; var x: PEVP_PKEY; cb: pem_password_cb; u: pointer): PEVP_PKEY; cdecl = nil;
  PEM_read_PUBKEY: function (var fp: FILE; var x: PEVP_PKEY; cb: pem_password_cb; u: pointer): PEVP_PKEY; cdecl = nil;
  PEM_write_bio_PUBKEY: function (bp: PBIO; x: PEVP_PKEY): TC_INT; cdecl = nil;
  PEM_write_PUBKEY: function(var fp: FILE; x: PEVP_PKEY): TC_INT; cdecl = nil;

{$REGION 'RSA'}
  PEM_read_bio_RSAPrivateKey: function(bp: PBIO; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_read_RSAPrivateKey: function(var fp: FILE; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPrivateKey: function(bp: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
  PEM_write_RSAPrivateKey: function(var fp: FILE; x: PRSA; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
  PEM_read_bio_RSAPublicKey:function(bp: PBIO; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_read_RSAPublicKey: function(var fp: FILE; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSAPublicKey: function(bp: PBIO; x: PRSA): TC_INT; cdecl = nil;
  PEM_write_RSAPublicKey: function(var fp: FILE; x: PRSA): TC_INT; cdecl = nil;
  PEM_read_bio_RSA_PUBKEY:function(bp: PBIO; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_read_RSA_PUBKEY: function(var fp: FILE; var x: PRSA; cb: pem_password_cb; u: pointer): PRSA; cdecl = nil;
  PEM_write_bio_RSA_PUBKEY: function(bp: PBIO; x: PRSA): TC_INT; cdecl = nil;
  PEM_write_RSA_PUBKEY: function(var fp: FILE; x: PRSA): TC_INT; cdecl = nil;
{$ENDREGION}

{$REGION 'DSA'}
 PEM_read_bio_DSAPrivateKey: function(bp: PBIO; var x: PDSA; cb: pem_password_cb; u: pointer): PDSA; cdecl = nil;
 PEM_read_DSAPrivateKey: function(var fp: FILE; var x: PDSA; cb: pem_password_cb; u: pointer): PDSA; cdecl = nil;
 PEM_write_bio_DSAPrivateKey:function(bp: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
 PEM_write_DSAPrivateKey: function(var fp: FILE; x: PDSA; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
 PEM_read_bio_DSA_PUBKEY: function(bp: PBIO; var x: PDSA; cb: pem_password_cb; u: pointer): PDSA; cdecl = nil;
 PEM_read_DSA_PUBKEY: function(var fp: FILE; var x: PDSA; cb: pem_password_cb; u: pointer): PDSA; cdecl = nil;
 PEM_write_bio_DSA_PUBKEY: function(bp: PBIO; x: PDSA): TC_INT; cdecl = nil;
 PEM_write_DSA_PUBKEY: function(var fp: FILE; x: PDSA): TC_INT; cdecl = nil;
 PEM_read_bio_DSAparams: function(bp: PBIO; var x: PDSA; cb: pem_password_cb; u: Pointer): PDSA; cdecl = nil;
 PEM_read_DSAparams: function(var fp: FILE; var x: PDSA; cb: pem_password_cb; u: pointer): PDSA; cdecl = nil;
 PEM_write_bio_DSAparams: function(bp: PBIO; x: PDSA): TC_INT; cdecl = nil;
 PEM_write_DSAparams: function(var fp: FILE; x: PDSA): TC_INT; cdecl = nil;
{$ENDREGION}

{$REGION 'DH'}
 PEM_read_bio_DHparams: function(bp: PBIO; var x: PDH; cb: pem_password_cb; u: pointer): PDH; cdecl = nil;
 PEM_read_DHparams: function(var fp: FILE; var x: PDH; cb: pem_password_cb; u: pointer): PDH; cdecl = nil;
 PEM_write_bio_DHparams: function(bp: PBIO; x: PDH): TC_INT; cdecl = nil;
 PEM_write_DHparams: function(var fp: FILE; x: PDH): TC_INT; cdecl = nil;
{$ENDREGION}


 PEM_read_bio_X509: function(bp: PBIO; var x: PX509; cb: pem_password_cb; u: pointer): PX509; cdecl = nil;
 PEM_read_X509: function(var fp: FILE; var x: PX509; cb: pem_password_cb; u: pointer): PX509; cdecl = nil;
 PEM_write_bio_X509: function(bp: PBIO; x: PX509): TC_INT; cdecl = nil;
 PEM_write_X509: function(var fp: FILE; x: PX509): TC_INT; cdecl = nil;

 PEM_read_bio_X509_AUX: function(bp: PBIO; var x: PX509; cb: pem_password_cb; u: pointer): PX509; cdecl = nil;
 PEM_read_X509_AUX: function(var fp: FILE; var x: PX509; cb: pem_password_cb; u: pointer): PX509; cdecl = nil;

 PEM_write_bio_X509_AUX: function(bp: PBIO; x: PX509): TC_INT; cdecl = nil;
 PEM_write_X509_AUX: function(var fp: FILE; x: PX509): TC_INT; cdecl = nil;

 PEM_read_bio_X509_REQ: function(bp: PBIO; var x: PX509_REQ; cb: pem_password_cb; u: pointer): PX509_REQ; cdecl = nil;
 PEM_read_X509_REQ: function(var fp: FILE; var x: PX509_REQ; cb: pem_password_cb; u: pointer): PX509_REQ; cdecl = nil;

 PEM_write_bio_X509_REQ: function(bp: PBIO; x: PX509_REQ): TC_INT; cdecl = nil;
 PEM_write_X509_REQ: function(var fp: FILE; x: PX509_REQ): TC_INT; cdecl = nil;

 PEM_write_bio_X509_REQ_NEW: function(bp: PBIO; x: PX509_REQ): TC_INT; cdecl = nil;
 PEM_write_X509_REQ_NEW: function(var fp: FILE; x: PX509_REQ): TC_INT; cdecl = nil;

 PEM_read_bio_X509_CRL: function(bp: PBIO; var x: PX509_CRL; cb: pem_password_cb; u: pointer): PX509_CRL; cdecl = nil;
 PEM_read_X509_CRL: function(var fp: FILE; var x: PX509_CRL; cb: pem_password_cb; u: pointer): PX509_CRL; cdecl = nil;

 PEM_write_bio_X509_CRL: function(bp: PBIO; x: PX509_CRL): TC_INT; cdecl = nil;
 PEM_write_X509_CRL: function(var fp: FILE; x: PX509_CRL): TC_INT; cdecl = nil;

{
 PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u);

 PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u);

 int PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x);

 int PEM_write_PKCS7(FILE *fp, PKCS7 *x);
}
 PEM_read_bio_NETSCAPE_CERT_SEQUENCE: function(bp: PBIO; var x: PNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
 PEM_read_NETSCAPE_CERT_SEQUENCE: function(fp: FILE; var x: PNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;

 PEM_write_bio_NETSCAPE_CERT_SEQUENCE: function(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TC_INT; cdecl = nil;
 PEM_write_NETSCAPE_CERT_SEQUENCE: function(fp: FILE; x: PNETSCAPE_CERT_SEQUENCE): TC_INT; cdecl = nil;



implementation

end.
