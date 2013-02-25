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
	
int (*X509_TRUST_set_default(int (*trust)(int , X509 *, int)))(int, X509 *, int);	
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

	X509_dup: function(X509 *x509): PX509; cdecl = nil;
	X509_ATTRIBUTE_dup: function(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = nil;
	X509_EXTENSION_dup: function(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl = nil;
	X509_CRL_dup: function(crl: PX509_CRL): PX509_CRL; cdecl = nil;
	X509_REQ_dup: function(req: PX509_REQ): PX509_REQ; cdecl = nil;
	X509_ALGOR_dup: function(xn: PX509_ALGOR): PX509_ALGOR; cdecl = nil;
	X509_ALGOR_set0: function(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TC_INT; pval: Pointer): TC_INT; cdecl = nil;
	X509_ALGOR_get0: procedure(var paobj: PASN1_OBJECT; var pptype: TC_INT; var ppval: Pointer; algor: PX509_ALGOR; cdecl = nil;
	X509_ALGOR_set_md: procedure(alg: PX509_ALGOR; const md: PEVP_MD); cdecl = nil;
	X509_NAME_dup: function(xn: PX509_NAME): PX509_NAME; cdecl = nil;
	X509_NAME_ENTRY_dup: function(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = nil;
	X509_cmp_time(const ASN1_TIME *s, time_t *t): TC_INT; cdecl = nil;
	X509_cmp_current_time(const ASN1_TIME *s): TC_INT; cdecl = nil;
	X509_time_adj: function(s: PASN1_TIME; adj: TC_LONG; var t: TC_TIME_T): PASN1_TIME; cdecl = nil;
	X509_time_adj_ex: function(s: PASN1_TIME; offset_day: TC_INT; offset_sec: TC_LONG; var t: TC_TIME_T): PASN1_TIME; cdecl = nil;
	X509_gmtime_adj: function(s: PASN1_TIME; adj: TC_LONG): PASN1_TIME; cdecl = nil;
	X509_get_default_cert_area: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_dir: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_file: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_dir_env: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_file_env: function: PAnsiChar; cdecl = nil;
	X509_get_default_private_dir: function: PAnsiChar; cdecl = nil;
	X509_to_X509_REQ: function(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl = nil;
	X509_REQ_to_X509: function(r: PX509_REQ; days: TC_INT; pkey: PEVP_PKEY): PX509; cdecl = nil;
	X509_PUBKEY_set: function(var x: PX509_PUBKEY; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
	X509_PUBKEY_get: function(key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
	X509_get_pubkey_parameters: function(pkey: PEVP_PKEY; chain: PSTACK_OF_X509): TC_INT; cdecl = nil;
	i2d_PUBKEY: function(a: PEVP_PKEY; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_PUBKEY: function(var a: PEVP_PKEY; var pp: PAnsiChar; _length: TC_LONG): PEVP_PKEY; cdecl = nil;
	i2d_RSA_PUBKEY: function(a: PRSA; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_RSA_PUBKEY: function(var a: PRSA; var pp: PAnsiChar; _length: TC_LONG): PRSA; cdecl = nil;
	i2d_DSA_PUBKEY: function(a: PDSA; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_DSA_PUBKEY: function(var a: PDSA; var pp: PAnsiChar; _length: TC_LONG): PDSA; cdecl = nil;
	i2d_EC_PUBKEY: function(a: PEC_KEY; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_EC_PUBKEY: function(var a: PEC_KEY;  var pp: PAnsiChar; _length: TC_LONG): PEC_KEY; cdecl = nil;
	X509_NAME_set: function(var x: PX509_NAME; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_get_ex_new_index: function(argl: TC_LONG; argp: Pointer; new_func: CRYPTO_EX_new; dup_func: CRYPTO_EX_dup; free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
	X509_set_ex_data: function(r: PX509; idx: TC_INT; arg: Pointer): TC_INT; cdecl = nil;
	X509_get_ex_data: function(r: PX509; idx: TC_INT): Pointer; cdecl = nil;
	i2d_X509_AUX: function(a: PX509; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_X509_AUX: function(var a: PX509; var pp: PAnsiChar; _length: TC_LONG): PX509; cdecl = nil;

	X509_alias_set1: function(x: PX509;  name: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
	X509_keyid_set1: function(x: PX509;  id: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
	X509_alias_get0: function(x: PX509;  var len: TC_INT): PAnsiChar; cdecl = nil;
	X509_keyid_get0: function(x: PX509;  var len: TC_INT): PAnsiChar; cdecl = nil;

	X509_TRUST_set: function(var T: TC_INT; trust: TC_INT): TC_INT; cdecl = nil;
	X509_add1_trust_object: function(x: PX509;  obj: PASN1_OBJECT): TC_INT; cdecl = nil;
	X509_add1_reject_object: function(x: PX509; obj: PASN1_OBJECT): TC_INT; cdecl = nil;
	X509_trust_clear: procedure(x: PX509); cdecl = nil;
	X509_reject_clear: procedure(x: PX509); cdecl = nil;
	X509_CRL_add0_revoked: function(crl: PX509_CRL; rev: PX509_REVOKED): TC_INT; cdecl = nil;
	X509_CRL_get0_by_serial: function(crl: PX509_CRL; var r: PX509_REVOKED; serial: PASN1_INTEGER): TC_INT; cdecl = nil;
	X509_CRL_get0_by_cert: function(crl: PX509_CRL; var r: PX509_REVOKED; x: PX509): TC_INT; cdecl = nil;

	X509_PKEY_new: function: PX509_PKEY; cdecl = nil;
	X509_PKEY_free: procedure(a: PX509_PKEY); cdecl = nil;
	i2d_X509_PKEY: function(a: PX509_PKEY; var pp: PAnsiChar): TC_INT; cdecl = nil;
	d2i_X509_PKEY: function(var a: PX509_PKEY; var pp: PAnsiChar; _length: TC_LONG): PX509_PKEY; cdecl = nil;

	X509_INFO_new: function: PX509_INFO; cdecl = nil;
	X509_INFO_free: procedure(a: PX509_INFO); cdecl = nil;
	X509_NAME_oneline: function(a: PX509_NAME; buf: PAnsiChar; size: TC_INT): PAnsiChar; cdecl = nil;

	ASN1_verify: function(i2d: i2d_of_void; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PAnsiChar; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	ASN1_digest: function(i2d: i2d_of_void; const _type: PEVP_MD; data: PAnsiChar; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;

	ASN1_sign: function(i2d: i2d_of_void;  algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PAnsiChar; pkey: PEVP_PKEY; const _type: PEVP_MD): TC_INT; cdecl = nil;

	ASN1_item_digest: function(const it: PASN1_ITEM; const _type: PEVP_MD; data: Pointer; md: PAnsiChar; var len: TC__UINT): TC_INT; cdecl = nil;

	ASN1_item_verify: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	ASN1_item_sign: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const _type: PEVP_MD): TC_INT; cdecl = nil;
	ASN1_item_sign_ctx: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
	X509_set_version: function(x: PX509; version: TC_LONG): TC_INT; cdecl = nil;
	X509_set_serialNumber: function(x: PX509; serial: PASN1_INTEGER): TC_INT; cdecl = nil;
	X509_get_serialNumber: function(x: PX509): PASN1_INTEGER; cdecl = nil;
	X509_set_issuer_name: function(x: PX509; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_get_issuer_name: function(a: PX509): PX509_NAME; cdecl = nil;
	X509_set_subject_name: function(x: PX509; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_get_subject_name: function(a: PX509): PX509_NAME; cdecl = nil;
	X509_set_notBefore: function(x: PX509; const tm: PASN1_TIME): TC_INT; cdecl = nil;
	X509_set_notAfter: function(x: PX509; const tm: PASN1_TIME): TC_INT; cdecl = nil;
	X509_set_pubkey: function(x: PX509; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
	X509_get_pubkey: function(x: PX509): PEVP_PKEY; cdecl = nil;
	X509_get0_pubkey_bitstr: function(const x: PX509): PASN1_BIT_STRING; cdecl = nil;
	X509_certificate_type: function(x: PX509; pubkey: PEVP_PKEY): TC_INT; cdecl = nil;
	
	X509_REQ_set_version: function(x: PX509_REQ; version: TC_LONG): TC_INT; cdecl = nil;
	X509_REQ_set_subject_name: function(req: PX509_REQ; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_REQ_set_pubkey: function(x: PX509_REQ; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
	X509_REQ_get_pubkey: function(req: PX509_REQ): PEVP_PKEY; cdecl = nil;
	X509_REQ_extension_nid: function(nid: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_extension_nids: function: PC_INT; cdecl = nil;
	X509_REQ_set_extension_nids: procedure(nids: PC_INT); cdecl = nil;
	X509_REQ_get_extensions: function(req: PX509_REQ): PSTACK_OF_X509_EXTENSION;
	X509_REQ_add_extensions_nid: function(req: PX509_REQ; exts: PSTAKC_OF_X509_EXTENSION; nid: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_add_extensions: function(req: PX509_REQ; exts: PSTAKC_OF_X509_EXTENSION): TC_INT; cdecl = nil;
	X509_REQ_get_attr_count: function(const req: PX509_REQ): TC_INT; cdecl = nil;
	X509_REQ_get_attr_by_NID: function(const req: PX509_REQ; nid: TC_INT; lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_attr_by_OBJ: function(const req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_attr: function(const req: PX509_REQ; loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_REQ_delete_attr: function(req: PX509_REQ; loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_REQ_add1_attr: function(req: PX509_REQ; attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	X509_REQ_add1_attr_by_OBJ: function(req: PX509_REQ; const obj: PASN1_OBJECT; _type: TC_INT; const bytes: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_add1_attr_by_NID: function(req: PX509_REQ; nid: TC_INT; _type: TC_INT;	const bytes: PAnsoChar; len: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_add1_attr_by_txt: function(req: PX509_REQ; attrname: PAnsiChar; _type: TC_INT; const bytes: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;

	X509_CRL_set_version: function(x: PX509_CRL; _version: TC_LONG): TC_INT; cdecl = nil;
	X509_CRL_set_issuer_name: function(x: PX509_CRL; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_CRL_set_lastUpdate: function(x: PX509_CRL; const tm: PASN1_TIME): TC_INT; cdecl = nil;
	X509_CRL_set_nextUpdate: function(x: PX509_CRL; const tm: PASN1_TIME): TC_INT; cdecl = nil;
	X509_CRL_sort: function(crl: PX509_CRL): TC_INT; cdecl = nil;

	X509_REVOKED_set_serialNumber: function(x: PX509_REVOKED; serial: PASN1_INTEGER): TC_INT; cdecl = nil;
	X509_REVOKED_set_revocationDate: function(r: PX509_REVOKED; tm: PASN1_TIME): TC_INT; cdecl = nil;

	X509_REQ_check_private_key: function(_x509: PX509_REQ; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	X509_check_private_key: function(_x509: PX509; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	X509_issuer_and_serial_cmp: function(const a: PX509; const b: PX509) : TC_INT; cdecl = nil;
	X509_issuer_and_serial_hash: function(a: PX509): TC_ULONG; cdecl = nil;

	X509_issuer_name_cmp: function(const a: PX509; const b: PX509): TC_INT; cdecl = nil;
	X509_issuer_name_hash: function(X509 *a): TC_ULONG; cdecl = nil;
	X509_subject_name_cmp: function(const a: PX509; const b: PX509): TC_INT; cdecl = nil;
	X509_subject_name_hash: function(x: PX509): TC_ULONG; cdecl = nil;
	
	X509_issuer_name_hash_old: function(a: PX509): TC_ULONG; cdecl = nil;
	X509_subject_name_hash_old: function(x: PX509): TC_ULONG; cdecl = nil;
	
	
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
