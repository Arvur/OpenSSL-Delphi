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

{$REGION 'X509'}
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
{$ENDREGION}

{$REGION 'PKCS7}
 PEM_read_bio_PKCS7: function(bp: PBIO; var x: PPKCS7; cb: pem_password_cb; u: pointer): PPKCS7; cdecl = nil;
 PEM_read_PKCS7: function(var fp: FILE; var x: PPKCS7; cb: pem_password_cb; u: pointer): PPKCS7; cdecl = nil;
 PEM_write_bio_PKCS7: function(bp: PBIO; x: PPKCS7): TC_INT; cdecl = nil;
 PEM_write_PKCS7: function(var fp: FILE; x: PPKCS7): TC_INT; cdecl = nil;
{$ENDREGION}

{$REGION 'NETSCAPE'}
 PEM_read_bio_NETSCAPE_CERT_SEQUENCE: function(bp: PBIO; var x: PNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
 PEM_read_NETSCAPE_CERT_SEQUENCE: function(var fp: FILE; var x: PNETSCAPE_CERT_SEQUENCE; cb: pem_password_cb; u: pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
 PEM_write_bio_NETSCAPE_CERT_SEQUENCE: function(bp: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TC_INT; cdecl = nil;
 PEM_write_NETSCAPE_CERT_SEQUENCE: function(var fp: FILE; x: PNETSCAPE_CERT_SEQUENCE): TC_INT; cdecl = nil;
{$ENDREGION}

 PEM_write_ECPrivateKey: function(var fp: FILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;
 PEM_write_bio_ECPrivateKey: function(bp: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;

 i2d_PKCS8PrivateKey_bio: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PAnsiChar;
            klen: TC_INT; cb: pem_password_cb; u: pointer): TC_INT; cdecl = nil;


procedure SSL_InitPEM;

implementation
uses ssl_lib;

procedure SSL_InitPEM;
begin
 if @PEM_read_bio_PrivateKey = nil then
  begin
   @PEM_read_bio_PrivateKey:= LoadFunctionCLib('PEM_read_bio_PrivateKey');
   @PEM_read_PrivateKey:= LoadFunctionCLib('PEM_read_PrivateKey');
   @PEM_write_bio_PrivateKey := LoadFunctionCLib('PEM_write_bio_PrivateKey');
   @PEM_write_PrivateKey:= LoadFunctionCLib('PEM_write_PrivateKey');
   @PEM_write_bio_PKCS8PrivateKey:= LoadFunctionCLib('PEM_write_bio_PKCS8PrivateKey');
   @PEM_write_PKCS8PrivateKey:= LoadFunctionCLib('PEM_write_PKCS8PrivateKey');
   @PEM_write_bio_PKCS8PrivateKey_nid:= LoadFunctionCLib('PEM_write_bio_PKCS8PrivateKey_nid');
   @PEM_write_PKCS8PrivateKey_nid:= LoadFunctionCLib('PEM_write_PKCS8PrivateKey_nid');
   @PEM_read_bio_PUBKEY:= LoadFunctionCLib('PEM_read_bio_PUBKEY');
   @PEM_read_PUBKEY:= LoadFunctionCLib('PEM_read_PUBKEY');
   @PEM_write_bio_PUBKEY:= LoadFunctionCLib('PEM_write_bio_PUBKEY');
   @PEM_write_PUBKEY:= LoadFunctionCLib('PEM_write_PUBKEY');

{$REGION 'RSA'}
   @PEM_read_bio_RSAPrivateKey:= LoadFunctionCLib('PEM_read_bio_RSAPrivateKey');
   @PEM_read_RSAPrivateKey:= LoadFunctionCLib('PEM_read_RSAPrivateKey');
   @PEM_write_bio_RSAPrivateKey:= LoadFunctionCLib('PEM_write_bio_RSAPrivateKey');
   @PEM_write_RSAPrivateKey:= LoadFunctionCLib('PEM_write_RSAPrivateKey');
   @PEM_read_bio_RSAPublicKey:= LoadFunctionCLib('PEM_read_bio_RSAPublicKey');
   @PEM_read_RSAPublicKey:=LoadFunctionCLib('PEM_read_RSAPublicKey');
   @PEM_write_bio_RSAPublicKey:= LoadFunctionCLib('PEM_write_bio_RSAPublicKey');
   @PEM_write_RSAPublicKey:= LoadFunctionCLib('PEM_write_RSAPublicKey');
   @PEM_read_bio_RSA_PUBKEY:= LoadFunctionCLib('PEM_read_bio_RSA_PUBKEY');
   @PEM_read_RSA_PUBKEY:= LoadFunctionCLib('PEM_read_RSA_PUBKEY');
   @PEM_write_bio_RSA_PUBKEY:= LoadFunctionCLib('PEM_write_bio_RSA_PUBKEY');
   @PEM_write_RSA_PUBKEY:= LoadFunctionCLib('PEM_write_RSA_PUBKEY');
{$ENDREGION}

{$REGION 'DSA'}
   @PEM_read_bio_DSAPrivateKey:= LoadFunctionCLib('PEM_write_RSA_PUBKEY');
   @PEM_read_DSAPrivateKey:=LoadFunctionCLib('PEM_read_DSAPrivateKey');
   @PEM_write_bio_DSAPrivateKey:= LoadFunctionCLib('PEM_write_bio_DSAPrivateKey');
   @PEM_write_DSAPrivateKey:= LoadFunctionCLib('PEM_write_DSAPrivateKey');
   @PEM_read_bio_DSA_PUBKEY:= LoadFunctionCLib('PEM_read_bio_DSA_PUBKEY');
   @PEM_read_DSA_PUBKEY:= LoadFunctionCLib('PEM_read_DSA_PUBKEY');
   @PEM_write_bio_DSA_PUBKEY:= LoadFunctionCLib('PEM_write_bio_DSA_PUBKEY');
   @PEM_write_DSA_PUBKEY:= LoadFunctionCLib('PEM_write_DSA_PUBKEY');
   @PEM_read_bio_DSAparams:= LoadFunctionCLib('PEM_read_bio_DSAparams');
   @PEM_read_DSAparams := LoadFunctionCLib('PEM_read_DSAparams');
   @PEM_write_bio_DSAparams:= LoadFunctionCLib('PEM_write_bio_DSAparams');
   @PEM_write_DSAparams:= LoadFunctionCLib('PEM_write_DSAparams');
{$ENDREGION}

{$REGION 'DH'}
   @PEM_read_bio_DHparams:= LoadFunctionCLib('PEM_read_bio_DHparams');
   @PEM_read_DHparams:= LoadFunctionCLib('PEM_read_DHparams');
   @PEM_write_bio_DHparams:=LoadFunctionCLib('PEM_write_bio_DHparams');
   @PEM_write_DHparams:= LoadFunctionCLib('PEM_write_DHparams');
{$ENDREGION}

{$REGION 'X509'}
   @PEM_read_bio_X509:= LoadFunctionCLib('PEM_read_bio_X509');
   @PEM_read_X509:= LoadFunctionCLib('PEM_read_X509');
   @PEM_write_bio_X509:= LoadFunctionCLib('PEM_write_bio_X509');
   @PEM_write_X509:=LoadFunctionCLib('PEM_write_X509');
   @PEM_read_bio_X509_AUX:= LoadFunctionCLib('PEM_read_bio_X509_AUX');
   @PEM_read_X509_AUX:= LoadFunctionCLib('PEM_read_X509_AUX');
   @PEM_write_bio_X509_AUX:= LoadFunctionCLib('PEM_write_bio_X509_AUX');
   @PEM_write_X509_AUX:= LoadFunctionCLib('PEM_write_X509_AUX');
   @PEM_read_bio_X509_REQ:= LoadFunctionCLib('PEM_read_bio_X509_REQ');
   @PEM_read_X509_REQ:= LoadFunctionCLib('PEM_read_X509_REQ');
   @PEM_write_bio_X509_REQ:= LoadFunctionCLib('PEM_write_bio_X509_REQ');
   @PEM_write_X509_REQ:= LoadFunctionCLib('PEM_write_X509_REQ');
   @PEM_write_bio_X509_REQ_NEW:= LoadFunctionCLib('PEM_write_bio_X509_REQ_NEW');
   @PEM_write_X509_REQ_NEW:= LoadFunctionCLib('PEM_write_X509_REQ_NEW');
   @PEM_read_bio_X509_CRL:= LoadFunctionCLib('PEM_read_bio_X509_CRL');
   @PEM_read_X509_CRL:=  LoadFunctionCLib('PEM_read_X509_CRL');
   @PEM_write_bio_X509_CRL:= LoadFunctionCLib('PEM_write_bio_X509_CRL');
   @PEM_write_X509_CRL:= LoadFunctionCLib('PEM_write_X509_CRL');
{$ENDREGION}

{$REGION 'PKCS7}
   @PEM_read_bio_PKCS7:= LoadFunctionCLib('PEM_read_bio_PKCS7');
   @PEM_read_PKCS7:= LoadFunctionCLib('PEM_read_PKCS7');
   @PEM_write_bio_PKCS7:= LoadFunctionCLib('PEM_write_bio_PKCS7');
   @PEM_write_PKCS7:= LoadFunctionCLib('PEM_write_PKCS7');
{$ENDREGION}

{$REGION 'NETSCAPE'}
   @PEM_read_bio_NETSCAPE_CERT_SEQUENCE:= LoadFunctionCLib('PEM_read_bio_NETSCAPE_CERT_SEQUENCE');
   @PEM_read_NETSCAPE_CERT_SEQUENCE:= LoadFunctionCLib('PEM_read_NETSCAPE_CERT_SEQUENCE');
   @PEM_write_bio_NETSCAPE_CERT_SEQUENCE:= LoadFunctionCLib('PEM_write_bio_NETSCAPE_CERT_SEQUENCE');
   @PEM_write_NETSCAPE_CERT_SEQUENCE:= LoadFunctionCLib('PEM_write_NETSCAPE_CERT_SEQUENCE');
{$ENDREGION}


  @PEM_write_ECPrivateKey := LoadFunctionCLib('PEM_write_ECPrivateKey');
  @PEM_write_bio_ECPrivateKey := LoadFunctionCLib('PEM_write_bio_ECPrivateKey');
  @i2d_PKCS8PrivateKey_bio := LoadFunctionCLib('i2d_PKCS8PrivateKey_bio');
  end;
end;

end.
