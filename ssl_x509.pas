unit ssl_x509;

interface
uses ssl_types;

var
  X509_new : function: PPX509 cdecl = nil;
  X509_free : procedure(x: PX509) cdecl = nil;
  X509_NAME_new : function :PX509_NAME cdecl = nil;
  X509_NAME_free : procedure(x:PX509_NAME) cdecl = nil;
  X509_REQ_new : function :PX509_REQ cdecl = nil;
  X509_REQ_free : procedure(x:PX509_REQ) cdecl = nil;
  X509_to_X509_REQ : function(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ cdecl = nil;
  X509_NAME_add_entry_by_txt : function(name: PX509_NAME; const field: PAnsiChar; _type: TC_Int;
    const bytes: PAnsiChar; len, loc, _set: TC_Int): TC_Int cdecl = nil;
  X509_INFO_free : procedure (a : PX509_INFO) cdecl = nil;
  X509_set_version : function(x: PX509; version: TC_LONG): TC_Int cdecl = nil;
  X509_get_serialNumber : function(x: PX509): PASN1_INTEGER cdecl = nil;
  X509_gmtime_adj : function(s: PASN1_TIME; adj: TC_LONG): PASN1_TIME cdecl = nil;
  X509_set_notBefore : function(x: PX509; tm: PASN1_TIME): TC_Int cdecl = nil;
  X509_set_notAfter : function(x: PX509; tm: PASN1_TIME): TC_Int cdecl = nil;
  X509_set_pubkey : function(x: PX509; pkey: PEVP_PKEY): TC_Int cdecl = nil;
  X509_REQ_set_pubkey : function(x: PX509_REQ; pkey: PEVP_PKEY): TC_Int cdecl = nil;
  X509_sign : function(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TC_Int cdecl = nil;
  X509_REQ_sign : function(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TC_Int cdecl = nil;
  X509_REQ_add_extensions : function(req: PX509_REQ; exts: PSTACK_OF_X509_EXTENSION): TC_Int cdecl = nil;
  X509V3_EXT_conf_nid : function(conf: PLHASH; ctx: PX509V3_CTX; ext_nid: TC_Int; value: PAnsiChar): PX509_EXTENSION cdecl = nil;
  X509_EXTENSION_create_by_NID : function(ex: PPX509_EXTENSION; nid: TC_Int;
    crit: TC_Int; data: PASN1_OCTET_STRING): PX509_EXTENSION cdecl = nil;
  X509V3_set_ctx : procedure(ctx: PX509V3_CTX; issuer, subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TC_Int) cdecl = nil;
  X509_EXTENSION_free : procedure(ex: PX509_EXTENSION) cdecl = nil;
  X509_add_ext : function(cert: PX509; ext: PX509_EXTENSION; loc: TC_Int): TC_Int cdecl = nil;
  X509_print : function(bp : PBIO; x : PX509) : TC_Int cdecl = nil;
  X509_STORE_add_lookup : function (v : PX509_STORE; m : PX509_LOOKUP_METHOD) : PX509_LOOKUP cdecl = nil;
  X509_STORE_load_locations : function ( ctx : PX509_STORE; const _file, path : PAnsiChar) : TC_Int cdecl = nil;

  i2d_PUBKEY_bio: function(bp: PBIO; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  d2i_PUBKEY_bio: function(bp: PBIO; var a: PEVP_PKEY): PEVP_PKEY; cdecl = nil;
  i2d_PrivateKey_bio: function(bp: PBIO; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  d2i_PrivateKey_bio: function(bp: PBIO; var a: PEVP_PKEY): PEVP_PKEY; cdecl = nil;


(*
X509_CRL_METHOD *X509_CRL_METHOD_new: function(
    int (*crl_init)(X509_CRL *crl),
    int (*crl_free)(X509_CRL *crl),
    int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret,
                ASN1_INTEGER *ser, X509_NAME *issuer),
    int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk));
*)

  X509_CRL_set_default_method: procedure(meth: PX509_CRL_METHOD); cdecl = nil;

  X509_CRL_METHOD_free: procedure(m: PX509_CRL_METHOD); cdecl = nil;

  X509_CRL_set_meth_data: procedure(crl: PX509_CRL; dat: Pointer); cdecl = nil;
  X509_CRL_get_meth_data: function(crl: PX509_CRL): Pointer; cdecl = nil;
  X509_verify_cert_error_string: function(n: TC_LONG): PAnsiChar; cdecl = nil;


  X509_verify: function(a: PX509; r: PEVP_PKEY): TC_INT; cdecl = nil;

  X509_REQ_verify: function(a: PX509_REQ; r: PEVP_PKEY): TC_INT; cdecl = nil;
  X509_CRL_verify: function(a: PX509_CRL; r: PEVP_PKEY): TC_INT; cdecl = nil;
  NETSCAPE_SPKI_verify: function(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TC_INT; cdecl = nil;

  NETSCAPE_SPKI_b64_decode: function(str: PAnsiChar; len: TC_INT): PNETSCAPE_SPKI; cdecl = nil;
  NETSCAPE_SPKI_b64_encode: function(x: PNETSCAPE_SPKI): PAnsiChar; cdecl = nil;
  NETSCAPE_SPKI_get_pubkey: function(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl = nil;
  NETSCAPE_SPKI_set_pubkey: function(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

  NETSCAPE_SPKI_print: function(_out: PBIO; spki: PNETSCAPE_SPKI): TC_INT; cdecl = nil;

  X509_signature_dump: function(bp: PBIO;const sig: PASN1_STRING; indent: TC_INT): TC_INT; cdecl = nil;
  X509_signature_print: function(bp: PBIO;alg: PX509_ALGOR; sig: PASN1_STRING): TC_INT; cdecl = nil;

  X509_sign_ctx: function(x: PX509; ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
  X509_REQ_sign_ctx: function(x: PX509_REQ; ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
  X509_CRL_sign: function(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TC_INT; cdecl = nil;
  X509_CRL_sign_ctx: function(x: PX509_CRL; ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
  NETSCAPE_SPKI_sign: function(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TC_INT; cdecl = nil;

  X509_pubkey_digest: function(const data: PX509;const _type: PEVP_MD; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;
  X509_digest: function(const data: PX509;const _type: PEVP_MD; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;
  X509_CRL_digest: function(const data: PX509_CRL;const _type: PEVP_MD; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;
  X509_REQ_digest: function(const data: PX509_REQ;const _type: PEVP_MD; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;
  X509_NAME_digest: function(const data: PX509_NAME; const _type: PEVP_MD; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;

  d2i_X509_bio: function(bp: PBIO;var _x509: PX509): PX509; cdecl = nil;
  i2d_X509_bio: function(bp: PBIO;_x509: PX509): TC_INT; cdecl = nil;
  d2i_X509_CRL_bio: function(bp: PBIO;var crl: PX509_CRL): PX509_CRL; cdecl = nil;
  i2d_X509_CRL_bio: function(bp: PBIO;crl :PX509_CRL): TC_INT; cdecl = nil;
  d2i_X509_REQ_bio: function(bp: PBIO;var req: PX509_REQ): PX509_REQ; cdecl = nil;
  i2d_X509_REQ_bio: function(bp: PBIO;req: PX509_REQ): TC_INT; cdecl = nil;

  d2i_RSAPrivateKey_bio: function(bp: PBIO;var _rsa: PRSA): PRSA; cdecl = nil;
  i2d_RSAPrivateKey_bio: function(bp: PBIO;_rsa: PRSA): TC_INT; cdecl = nil;
  d2i_RSAPublicKey_bio: function(bp: PBIO;var _rsa: PRSA): PRSA; cdecl = nil;
  i2d_RSAPublicKey_bio: function(bp: PBIO;_rsa: PRSA): TC_INT; cdecl = nil;
  d2i_RSA_PUBKEY_bio: function(bp: PBIO;var _rsa: PRSA): PRSA; cdecl = nil;
  i2d_RSA_PUBKEY_bio: function(bp: PBIO;_rsa: PRSA): TC_INT; cdecl = nil;

  d2i_DSA_PUBKEY_bio: function(bp: PBIO; var _dsa: DSA): PDSA; cdecl = nil;
  i2d_DSA_PUBKEY_bio: function(bp: PBIO; _dsa: DSA): TC_INT; cdecl = nil;
  d2i_DSAPrivateKey_bio: function(bp: PBIO; var _dsa: DSA): PDSA; cdecl = nil;
  i2d_DSAPrivateKey_bio: function(bp: PBIO; _dsa: DSA): TC_INT; cdecl = nil;

  d2i_EC_PUBKEY_bio: function(bp: PBIO; var _eckey: PEC_KEY): PEC_KEY; cdecl = nil;
  i2d_EC_PUBKEY_bio: function(bp: PBIO; _eckey: PEC_KEY): TC_INT; cdecl = nil;
  d2i_ECPrivateKey_bio: function(bp: PBIO; var _eckey: PEC_KEY):PEC_KEY; cdecl = nil;
  i2d_ECPrivateKey_bio: function(bp: PBIO; _eckey: PEC_KEY): TC_INT; cdecl = nil;

  d2i_PKCS8_bio: function(bp: PBIO; var p8: PX509_SIG): PX509_SIG;
  i2d_PKCS8_bio: function(bp: PBIO;p8: PX509_SIG): TC_INT; cdecl = nil;
  d2i_PKCS8_PRIV_KEY_INFO_bio: function(bp: PBIO; var p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  i2d_PKCS8_PRIV_KEY_INFO_bio: function(bp: PBIO;p8inf: PPKCS8_PRIV_KEY_INFO): TC_INT; cdecl = nil;
  i2d_PKCS8PrivateKeyInfo_bio: function(bp: PBIO; key: PEVP_PKEY): TC_INT; cdecl = nil;


procedure SSL_InitX509;

implementation
uses ssl_lib;

procedure SSL_InitX509;
begin
 if @X509_new = nil then
  begin
    @X509_new := LoadFunctionCLib('X509_new');
    @X509_free := LoadFunctionCLib('X509_free');
    @X509_NAME_new := LoadFunctionCLib('X509_NAME_new');
    @X509_NAME_free := LoadFunctionCLib('X509_NAME_free');
    @X509_REQ_new := LoadFunctionCLib('X509_REQ_new');
    @X509_REQ_free := LoadFunctionCLib('X509_REQ_free');
    @X509_to_X509_REQ := LoadFunctionCLib('X509_to_X509_REQ');
    @X509_NAME_add_entry_by_txt := LoadFunctionCLib('X509_NAME_add_entry_by_txt');
    @X509_INFO_free := LoadFunctionCLib('X509_INFO_free');
    @X509_set_version := LoadFunctionCLib('X509_set_version');
    @X509_get_serialNumber := LoadFunctionCLib('X509_get_serialNumber');
    @X509_gmtime_adj := LoadFunctionCLib('X509_gmtime_adj');
    @X509_set_notBefore := LoadFunctionCLib('X509_set_notBefore');
    @X509_set_notAfter := LoadFunctionCLib('X509_set_notAfter');
    @X509_set_pubkey := LoadFunctionCLib('X509_set_pubkey');
    @X509_REQ_set_pubkey := LoadFunctionCLib('X509_REQ_set_pubkey');
    @X509_sign := LoadFunctionCLib('X509_sign');
    @X509_REQ_sign := LoadFunctionCLib('X509_REQ_sign');
    @X509_REQ_add_extensions := LoadFunctionCLib('X509_REQ_add_extensions');
    @X509V3_EXT_conf_nid := LoadFunctionCLib('X509V3_EXT_conf_nid');
    @X509_EXTENSION_create_by_NID := LoadFunctionCLib('X509_EXTENSION_create_by_NID');
    @X509V3_set_ctx := LoadFunctionCLib('X509V3_set_ctx');
    @X509_EXTENSION_free := LoadFunctionCLib('X509_EXTENSION_free');
    @X509_add_ext := LoadFunctionCLib('X509_add_ext');
    @X509_print := LoadFunctionCLib('X509_print');
    @X509_STORE_add_lookup := LoadFunctionCLib('X509_STORE_add_lookup');
    @X509_STORE_load_locations := LoadFunctionCLib('X509_STORE_load_locations');

    @i2d_PUBKEY_bio:= LoadFunctionCLib('i2d_PUBKEY_bio');
    @d2i_PUBKEY_bio:= LoadFunctionCLib('d2i_PUBKEY_bio');
    @i2d_PrivateKey_bio:= LoadFunctionCLib('i2d_PrivateKey_bio');
    @d2i_PrivateKey_bio:= LoadFunctionCLib('d2i_PrivateKey_bio');
        
    @X509_CRL_set_default_method:= LoadFunctionCLib('X509_CRL_set_default_method');
    @X509_CRL_METHOD_free:= LoadFunctionCLib('X509_CRL_METHOD_free');
    @X509_CRL_set_meth_data:= LoadFunctionCLib('X509_CRL_set_meth_data');
    @X509_CRL_get_meth_data:= LoadFunctionCLib('X509_CRL_get_meth_data');
    @X509_verify_cert_error_string:= LoadFunctionCLib('X509_verify_cert_error_string');
    @X509_verify:= LoadFunctionCLib('X509_verify');
    @X509_REQ_verify:= LoadFunctionCLib('X509_REQ_verify');
    @X509_CRL_verify:= LoadFunctionCLib('X509_CRL_verify');
    @NETSCAPE_SPKI_verify:= LoadFunctionCLib('NETSCAPE_SPKI_verify');
    @NETSCAPE_SPKI_b64_decode:= LoadFunctionCLib('NETSCAPE_SPKI_b64_decode');
    @NETSCAPE_SPKI_b64_encode:= LoadFunctionCLib('NETSCAPE_SPKI_b64_encode');
    @NETSCAPE_SPKI_get_pubkey:= LoadFunctionCLib('NETSCAPE_SPKI_get_pubkey');
    @NETSCAPE_SPKI_set_pubkey:= LoadFunctionCLib('NETSCAPE_SPKI_set_pubkey');
    @NETSCAPE_SPKI_print:= LoadFunctionCLib('NETSCAPE_SPKI_print');
    @X509_signature_dump:= LoadFunctionCLib('X509_signature_dump');
    @X509_signature_print:= LoadFunctionCLib('X509_signature_print');
    @X509_sign_ctx:= LoadFunctionCLib('X509_sign_ctx');
    @X509_REQ_sign_ctx:= LoadFunctionCLib('X509_REQ_sign_ctx');
    @X509_CRL_sign:= LoadFunctionCLib('X509_CRL_sign');
    @X509_CRL_sign_ctx:= LoadFunctionCLib('X509_CRL_sign_ctx');
    @NETSCAPE_SPKI_sign:= LoadFunctionCLib('NETSCAPE_SPKI_sign');
    @X509_pubkey_digest:= LoadFunctionCLib('X509_pubkey_digest');
    @X509_digest:= LoadFunctionCLib('X509_digest');
    @X509_CRL_digest:= LoadFunctionCLib('X509_CRL_digest');
    @X509_REQ_digest:= LoadFunctionCLib('X509_REQ_digest');
    @X509_NAME_digest:= LoadFunctionCLib('X509_NAME_digest');
    @d2i_X509_bio:= LoadFunctionCLib('d2i_X509_bio');
    @i2d_X509_bio:= LoadFunctionCLib('i2d_X509_bio');
    @d2i_X509_CRL_bio:= LoadFunctionCLib('d2i_X509_CRL_bio');
    @i2d_X509_CRL_bio:= LoadFunctionCLib('i2d_X509_CRL_bio');
    @d2i_X509_REQ_bio:= LoadFunctionCLib('d2i_X509_REQ_bio');
    @i2d_X509_REQ_bio:= LoadFunctionCLib('i2d_X509_REQ_bio');
    @d2i_RSAPrivateKey_bio:= LoadFunctionCLib('d2i_RSAPrivateKey_bio');
    @i2d_RSAPrivateKey_bio:= LoadFunctionCLib('i2d_RSAPrivateKey_bio');
    @d2i_RSAPublicKey_bio:= LoadFunctionCLib('d2i_RSAPublicKey_bio');
    @i2d_RSAPublicKey_bio:= LoadFunctionCLib('i2d_RSAPublicKey_bio');
    @d2i_RSA_PUBKEY_bio:= LoadFunctionCLib('d2i_RSA_PUBKEY_bio');
    @i2d_RSA_PUBKEY_bio:= LoadFunctionCLib('i2d_RSA_PUBKEY_bio');
    @d2i_DSA_PUBKEY_bio:= LoadFunctionCLib('d2i_DSA_PUBKEY_bio');
    @i2d_DSA_PUBKEY_bio:= LoadFunctionCLib('i2d_DSA_PUBKEY_bio');
    @d2i_DSAPrivateKey_bio:= LoadFunctionCLib('d2i_DSAPrivateKey_bio');
    @i2d_DSAPrivateKey_bio:= LoadFunctionCLib('i2d_DSAPrivateKey_bio');
    @d2i_EC_PUBKEY_bio:= LoadFunctionCLib('d2i_EC_PUBKEY_bio');
    @i2d_EC_PUBKEY_bio:= LoadFunctionCLib('i2d_EC_PUBKEY_bio');
    @d2i_ECPrivateKey_bio:= LoadFunctionCLib('d2i_ECPrivateKey_bio');
    @i2d_ECPrivateKey_bio:= LoadFunctionCLib('i2d_ECPrivateKey_bio');
    @d2i_PKCS8_bio:= LoadFunctionCLib('d2i_PKCS8_bio');
    @i2d_PKCS8_bio:= LoadFunctionCLib('i2d_PKCS8_bio');
    @d2i_PKCS8_PRIV_KEY_INFO_bio:= LoadFunctionCLib('d2i_PKCS8_PRIV_KEY_INFO_bio');
    @i2d_PKCS8_PRIV_KEY_INFO_bio:= LoadFunctionCLib('i2d_PKCS8_PRIV_KEY_INFO_bio');
    @i2d_PKCS8PrivateKeyInfo_bio:= LoadFunctionCLib('i2d_PKCS8PrivateKeyInfo_bio');


  end;
end;
end.
