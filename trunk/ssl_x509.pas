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

int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
					char *name, int arg1, void *arg2);

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

	X509_dup: function(_x509: PX509): PX509; cdecl = nil;
	X509_ATTRIBUTE_dup: function(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = nil;
	X509_EXTENSION_dup: function(ex: PX509_EXTENSION): PX509_EXTENSION; cdecl = nil;
	X509_CRL_dup: function(crl: PX509_CRL): PX509_CRL; cdecl = nil;
	X509_REQ_dup: function(req: PX509_REQ): PX509_REQ; cdecl = nil;
	X509_ALGOR_dup: function(xn: PX509_ALGOR): PX509_ALGOR; cdecl = nil;
	X509_ALGOR_set0: function(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TC_INT; pval: Pointer): TC_INT; cdecl = nil;
	X509_ALGOR_get0: procedure(var paobj: PASN1_OBJECT; var pptype: TC_INT; var ppval: Pointer; algor: PX509_ALGOR); cdecl = nil;
	X509_ALGOR_set_md: procedure(alg: PX509_ALGOR; const md: PEVP_MD); cdecl = nil;
	X509_NAME_dup: function(xn: PX509_NAME): PX509_NAME; cdecl = nil;
	X509_NAME_ENTRY_dup: function(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = nil;
	X509_cmp_time:function(const s: PASN1_TIME; t: TC_TIME_T): TC_INT; cdecl = nil;
	X509_cmp_current_time: function(const s: PASN1_TIME): TC_INT; cdecl = nil;
	X509_time_adj: function(s: PASN1_TIME; adj: TC_LONG; var t: TC_TIME_T): PASN1_TIME; cdecl = nil;
	X509_time_adj_ex: function(s: PASN1_TIME; offset_day: TC_INT; offset_sec: TC_LONG; var t: TC_TIME_T): PASN1_TIME; cdecl = nil;
	X509_get_default_cert_area: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_dir: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_file: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_dir_env: function: PAnsiChar; cdecl = nil;
	X509_get_default_cert_file_env: function: PAnsiChar; cdecl = nil;
	X509_get_default_private_dir: function: PAnsiChar; cdecl = nil;
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
	X509_NAME_oneline: function(a: PX509_NAME; buf: PAnsiChar; size: TC_INT): PAnsiChar; cdecl = nil;

	ASN1_verify: function(i2d: i2d_of_void; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PAnsiChar; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	ASN1_digest: function(i2d: i2d_of_void; const _type: PEVP_MD; data: PAnsiChar; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;

	ASN1_sign: function(i2d: i2d_of_void;  algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PAnsiChar; pkey: PEVP_PKEY; const _type: PEVP_MD): TC_INT; cdecl = nil;

	ASN1_item_digest: function(const it: PASN1_ITEM; const _type: PEVP_MD; data: Pointer; md: PAnsiChar; var len: TC_UINT): TC_INT; cdecl = nil;

	ASN1_item_verify: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

	ASN1_item_sign: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const _type: PEVP_MD): TC_INT; cdecl = nil;
	ASN1_item_sign_ctx: function(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
	X509_set_serialNumber: function(x: PX509; serial: PASN1_INTEGER): TC_INT; cdecl = nil;
	X509_set_issuer_name: function(x: PX509; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_get_issuer_name: function(a: PX509): PX509_NAME; cdecl = nil;
	X509_set_subject_name: function(x: PX509; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_get_subject_name: function(a: PX509): PX509_NAME; cdecl = nil;
	X509_get_pubkey: function(x: PX509): PEVP_PKEY; cdecl = nil;
	X509_get0_pubkey_bitstr: function(const x: PX509): PASN1_BIT_STRING; cdecl = nil;
	X509_certificate_type: function(x: PX509; pubkey: PEVP_PKEY): TC_INT; cdecl = nil;

	X509_REQ_set_version: function(x: PX509_REQ; version: TC_LONG): TC_INT; cdecl = nil;
	X509_REQ_set_subject_name: function(req: PX509_REQ; name: PX509_NAME): TC_INT; cdecl = nil;
	X509_REQ_get_pubkey: function(req: PX509_REQ): PEVP_PKEY; cdecl = nil;
	X509_REQ_extension_nid: function(nid: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_extension_nids: function: PC_INT; cdecl = nil;
	X509_REQ_set_extension_nids: procedure(nids: PC_INT); cdecl = nil;
	X509_REQ_get_extensions: function(req: PX509_REQ): PSTACK_OF_X509_EXTENSION;
	X509_REQ_add_extensions_nid: function(req: PX509_REQ; exts: PSTACK_OF_X509_EXTENSION; nid: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_attr_count: function(const req: PX509_REQ): TC_INT; cdecl = nil;
	X509_REQ_get_attr_by_NID: function(const req: PX509_REQ; nid: TC_INT; lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_attr_by_OBJ: function(const req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_get_attr: function(const req: PX509_REQ; loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_REQ_delete_attr: function(req: PX509_REQ; loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_REQ_add1_attr: function(req: PX509_REQ; attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	X509_REQ_add1_attr_by_OBJ: function(req: PX509_REQ; const obj: PASN1_OBJECT; _type: TC_INT; const bytes: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
	X509_REQ_add1_attr_by_NID: function(req: PX509_REQ; nid: TC_INT; _type: TC_INT;	const bytes: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
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
	X509_issuer_name_hash: function(a: PX509): TC_ULONG; cdecl = nil;
	X509_subject_name_cmp: function(const a: PX509; const b: PX509): TC_INT; cdecl = nil;
	X509_subject_name_hash: function(x: PX509): TC_ULONG; cdecl = nil;

	X509_issuer_name_hash_old: function(a: PX509): TC_ULONG; cdecl = nil;
	X509_subject_name_hash_old: function(x: PX509): TC_ULONG; cdecl = nil;

	X509_cmp: function(const a: PX509; const b: PX509): TC_INT; cdecl = nil;
	X509_NAME_cmp: function(const a: PX509_NAME; const b: PX509_NAME): TC_INT; cdecl = nil;
	X509_NAME_hash: function(x: PX509_NAME): TC_ULONG; cdecl = nil;
	X509_NAME_hash_old: function(x: PX509_NAME): TC_ULONG; cdecl = nil;

	X509_CRL_cmp: function(const a: PX509_CRL; const b: PX509_CRL): TC_INT; cdecl = nil;
	X509_CRL_match: function(const a: PX509_CRL; const b: PX509_CRL): TC_INT; cdecl = nil;

	X509_NAME_print: function(bp: PBIO; name: PX509_NAME; obase: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_print_ex: function(_out: PBIO; nm: PX509_NAME; _indent: TC_INT; flags: TC_ULONG): TC_INT; cdecl = nil;
	X509_print_ex: function(bp: PBIO; x: PX509; nmflag: TC_ULONG; cflag: TC_ULONG): TC_INT; cdecl = nil;
	X509_ocspid_print: function(bp: PBIO; x: PX509): TC_INT; cdecl = nil;
	X509_CERT_AUX_print: function(bp: PBIO; x: PX509_CERT_AUX; _indent: TC_INT): TC_INT; cdecl = nil;
	X509_CRL_print: function(bp: PBIO; x: PX509_CRL): TC_INT; cdecl = nil;
	X509_REQ_print_ex: function(bp: PBIO; x: PX509_REQ; nmflag: TC_ULONG; cflag: TC_ULONG): TC_INT; cdecl = nil;
	X509_REQ_print: function(bp: PBIO; req: PX509_REQ): TC_INT; cdecl = nil;
	X509_NAME_entry_count: function(name: PX509_NAME): TC_INT; cdecl = nil;
	X509_NAME_get_text_by_NID: function(name: PX509_NAME; _nid: TC_INT;	buf: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_get_text_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; buf: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;

	X509_NAME_get_index_by_NID: function(name: PX509_NAME; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_get_index_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_get_entry: function(name: PX509_NAME; _loc: TC_INT): PX509_NAME_ENTRY; cdecl = nil;
	X509_NAME_delete_entry: function(name: PX509_NAME; _loc: TC_INT): PX509_NAME_ENTRY; cdecl = nil;
	X509_NAME_add_entry: function(name: PX509_NAME; ne: PX509_NAME_ENTRY; _loc: TC_INT; _set: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_add_entry_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; _type: TC_INT; bytes: PAnsiChar; _len: TC_INT; _loc: TC_INT; _set: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_add_entry_by_NID: function(name: PX509_NAME; _nid: TC_INT; _type: TC_INT; bytes: PAnsiChar; _len: TC_INT; _loc: TC_INT; _set: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_ENTRY_create_by_txt: function(var ne: PX509_NAME_ENTRY; field: PAnsiChar; _type: TC_INT; bytes: PAnsiChar; _len: TC_INT): PX509_NAME_ENTRY; cdecl = nil;
	X509_NAME_ENTRY_create_by_NID: function(var n: PX509_NAME_ENTRY; _nid: TC_INT; _type: TC_INT; bytes: PAnsiChar; _len: TC_INT): PX509_NAME_ENTRY; cdecl = nil;
	X509_NAME_ENTRY_create_by_OBJ: function(var n: PX509_NAME_ENTRY; obj: PASN1_OBJECT; _type: TC_INT; bytes: PAnsiChar; _len: TC_INT): PX509_NAME_ENTRY; cdecl = nil;
	X509_NAME_ENTRY_set_object: function(ne: PX509_NAME_ENTRY; obj: PASN1_OBJECT): TC_INT; cdecl = nil;
	X509_NAME_ENTRY_set_data: function(ne: PX509_NAME_ENTRY; _type: TC_INT; const bytes: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
	X509_NAME_ENTRY_get_object: function(ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl = nil;
	X509_NAME_ENTRY_get_data: function(ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl = nil;

	X509v3_get_ext_count: function(const x: PSTACK_OF_X509_EXTENSION): TC_INT; cdecl = nil;
	X509v3_get_ext_by_NID: function(const x: PSTACK_OF_X509_EXTENSION; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509v3_get_ext_by_OBJ: function(const x: PSTACK_OF_X509_EXTENSION; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509v3_get_ext_by_critical: function(const x: PSTACK_OF_X509_EXTENSION; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;

	X509v3_get_ext: function(const x: PSTACK_OF_X509_EXTENSION; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509v3_delete_ext: function(x: PSTACK_OF_X509_EXTENSION; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509v3_add_ext: function(var x: PSTACK_OF_X509_EXTENSION; ex: PX509_EXTENSION; _loc: TC_INT): PSTACK_OF_X509_EXTENSION; cdecl = nil;

	X509_get_ext_count: function(x: PX509): TC_INT; cdecl = nil;

	X509_get_ext_by_NID: function(x: PX509; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_get_ext_by_OBJ: function(x: PX509; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_get_ext_by_critical: function(x: PX509;  _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_get_ext: function(x: PX509;  _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_delete_ext: function(x: PX509;  _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_get_ext_d2i: function(x: PX509; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
	X509_add1_ext_i2d: function(x: PX509; _nid: TC_INT; value: Pointer; _crit: TC_INT; flags: TC_ULONG): TC_INT; cdecl = nil;

	X509_CRL_get_ext_count: function(x: PX509_CRL): TC_INT; cdecl = nil;
	X509_CRL_get_ext_by_NID: function(x: PX509_CRL; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_CRL_get_ext_by_OBJ: function(x: PX509_CRL; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_CRL_get_ext_by_critical: function(x: PX509_CRL; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_CRL_get_ext: function(x: PX509_CRL; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_CRL_delete_ext: function(x: PX509_CRL; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_CRL_add_ext: function(x: PX509_CRL; ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;
	X509_CRL_get_ext_d2i: function(x: PX509_CRL; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
	X509_CRL_add1_ext_i2d: function(x: PX509_CRL; _nid: TC_INT; value: Pointer; _crit: TC_INT; _flags: TC_ULONG): TC_INT; cdecl = nil;

	X509_REVOKED_get_ext_count: function(x: PX509_REVOKED): TC_INT; cdecl = nil;
	X509_REVOKED_get_ext_by_NID: function(x: PX509_REVOKED; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REVOKED_get_ext_by_OBJ: function(x: PX509_REVOKED; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REVOKED_get_ext_by_critical: function(x: PX509_REVOKED; _crit: TC_INT;_lastpos: TC_INT): TC_INT; cdecl = nil;
	X509_REVOKED_get_ext: function(x: PX509_REVOKED; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_REVOKED_delete_ext: function(x: PX509_REVOKED; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
	X509_REVOKED_add_ext: function(x: PX509_REVOKED; ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;
	X509_REVOKED_get_ext_d2i: function(x: PX509_REVOKED; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
	X509_REVOKED_add1_ext_i2d: function(x: PX509_REVOKED; _nid: TC_INT; value: Pointer; _crit: TC_INT;	_flags: TC_ULONG): TC_INT; cdecl = nil;

	X509_EXTENSION_create_by_OBJ: function(var e: PX509_EXTENSION; obj: PASN1_OBJECT; _crit: TC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
	X509_EXTENSION_set_object: function(ex: PX509_EXTENSION; obj: PASN1_OBJECT): TC_INT; cdecl = nil;
	X509_EXTENSION_set_critical: function(ex: PX509_EXTENSION; _crit: TC_INT): TC_INT; cdecl = nil;
	X509_EXTENSION_set_data: function(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TC_INT; cdecl = nil;
	X509_EXTENSION_get_object: function(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl = nil;
	X509_EXTENSION_get_data: function(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl = nil;
	X509_EXTENSION_get_critical: function(ex: PX509_EXTENSION): TC_INT; cdecl = nil;

	X509at_get_attr_count: function(const x: PSTACK_OF_X509_ATTRIBUTE): TC_INT; cdecl = nil;
	X509at_get_attr_by_NID: function(const x: PSTACK_OF_X509_ATTRIBUTE; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509at_get_attr_by_OBJ: function(const sk: PSTACK_OF_X509_ATTRIBUTE; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	X509at_get_attr: function(const x: PSTACK_OF_X509_ATTRIBUTE; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509at_delete_attr: function(x: PSTACK_OF_X509_ATTRIBUTE; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509at_add1_attr: function(var x: PSTACK_OF_X509_ATTRIBUTE; attr: PX509_ATTRIBUTE): PSTACK_OF_X509_ATTRIBUTE; cdecl = nil;
	X509at_add1_attr_by_OBJ: function(var x: PSTACK_OF_X509_ATTRIBUTE; const obj: PASN1_OBJECT; _type: TC_INT; bytes: PAnsiChar;_len: TC_INT): PSTACK_OF_X509_ATTRIBUTE; cdecl = nil;
	X509at_add1_attr_by_NID: function(x: PSTACK_OF_X509_ATTRIBUTE; _nid: TC_INT;_type: TC_INT;	bytes: PAnsiChar; _len: TC_INT): PSTACK_OF_X509_ATTRIBUTE; cdecl = nil;
	X509at_add1_attr_by_txt: function(var x: PSTACK_OF_X509_ATTRIBUTE; const attrname: PAnsiChar; _type: TC_INT;	const bytes: PAnsiChar; _len: TC_INT): PSTACK_OF_X509_ATTRIBUTE; cdecl = nil;
	X509at_get0_data_by_OBJ: function(x: PSTACK_OF_X509_ATTRIBUTE; obj: PASN1_OBJECT; _lastpos: TC_INT; _type: TC_INT): pointer; cdecl = nil;
	X509_ATTRIBUTE_create_by_NID: function(var a: PX509_ATTRIBUTE; _nid: TC_INT;_atrtype: TC_INT; const data: Pointer; _len: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_ATTRIBUTE_create_by_OBJ: function(var a: PX509_ATTRIBUTE; const obj: PASN1_OBJECT; _atrtype: TC_INT; const data: Pointer; _len: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_ATTRIBUTE_create_by_txt: function(var a: PX509_ATTRIBUTE; const atrname: PAnsiChar; _type: TC_INT; const bytes: PAnsiChar; _len: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	X509_ATTRIBUTE_set1_object: function(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TC_INT; cdecl = nil;
	X509_ATTRIBUTE_set1_data: function(attr: PX509_ATTRIBUTE; _attrtype: TC_INT; const data: Pointer; _len: TC_INT): TC_INT; cdecl = nil;
	X509_ATTRIBUTE_get0_data: function(attr: PX509_ATTRIBUTE; _idx: TC_INT; _atrtype: TC_INT; data: Pointer): Pointer; cdecl = nil;
	X509_ATTRIBUTE_count: function(attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	X509_ATTRIBUTE_get0_object: function(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl = nil;
	X509_ATTRIBUTE_get0_type: function(attr: PX509_ATTRIBUTE; _idx: TC_INT): PASN1_TYPE; cdecl = nil;

	EVP_PKEY_get_attr_count: function(const key: PEVP_PKEY): TC_INT; cdecl = nil;
	EVP_PKEY_get_attr_by_NID: function(const key: PEVP_PKEY; _nid: TC_INT;_lastpos: TC_INT): TC_INT; cdecl = nil;
	EVP_PKEY_get_attr_by_OBJ: function(const key: PEVP_PKEY; obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
	EVP_PKEY_get_attr: function(const key: PEVP_PKEY; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	EVP_PKEY_delete_attr: function(key: PEVP_PKEY; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	EVP_PKEY_add1_attr: function(key: PEVP_PKEY;  attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	EVP_PKEY_add1_attr_by_OBJ: function(key: PEVP_PKEY; const obj: PASN1_OBJECT; _type: TC_INT; const bytes: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
	EVP_PKEY_add1_attr_by_NID: function(key: PEVP_PKEY; _nid: TC_INT; _type: TC_INT; const bytes: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
	EVP_PKEY_add1_attr_by_txt: function(key: PEVP_PKEY; const attrname: PAnsiChar; _type: TC_INT; const bytes: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;

	X509_verify_cert: function(ctx: PX509_STORE_CTX): TC_INT; cdecl = nil;

	X509_find_by_issuer_and_serial: function(sk: PSTACK_OF_X509; name: PX509_NAME; serial: PASN1_INTEGER): PX509; cdecl = nil;
	X509_find_by_subject: function(sk: PSTACK_OF_X509; name: PX509_NAME): PX509; cdecl = nil;

	PKCS5_pbe_set0_algor: function(algor: PX509_ALGOR; _alg: TC_INT;_iter: TC_INT; const salt: PAnsiChar; _saltlen: TC_INT): TC_INT; cdecl = nil;

	PKCS5_pbe_set: function(_alg: TC_INT; _iter: TC_INT; const salt: PAnsiChar; _saltlen: TC_INT): PX509_ALGOR; cdecl = nil;
	PKCS5_pbe2_set: function(const cipher: PEVP_CIPHER; _iter: TC_INT; salt: PAnsiChar; _saltlen: TC_INT): PX509_ALGOR; cdecl = nil;
	PKCS5_pbe2_set_iv: function(const cipher: PEVP_CIPHER; _iter: TC_INT; salt: PAnsiChar; _saltlen: TC_INT; aiv: PAnsiChar; _prf_nid: TC_INT): PX509_ALGOR; cdecl = nil;

	PKCS5_pbkdf2_set: function(_iter: TC_INT; salt: PAnsiChar; _saltlen: TC_INT; _prf_nid: TC_INT;_keylen: TC_INT): PX509_ALGOR; cdecl = nil;

	EVP_PKCS82PKEY: function(p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl = nil;
	EVP_PKEY2PKCS8: function(pkey: PEVP_PKEY): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
	EVP_PKEY2PKCS8_broken: function(pkey: PEVP_PKEY; _broken: TC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
	PKCS8_set_broken: function(p8: PPKCS8_PRIV_KEY_INFO; _broken: TC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;

	PKCS8_pkey_set0: function(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; _version: TC_INT; _ptype: TC_INT; pval: Pointer; penc: PAnsiChar;_penclen: TC_INT): TC_INT; cdecl = nil;
	PKCS8_pkey_get0: function(var p: PASN1_OBJECT; var pk: PAnsiChar; var _ppklen: TC_INT; var palg: PX509_ALGOR; p8: PPKCS8_PRIV_KEY_INFO): TC_INT; cdecl = nil;

	X509_PUBKEY_set0_param: function(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; _ptype: TC_INT; pval: Pointer; penc: PAnsiChar; _penclen: TC_INT): TC_INT; cdecl = nil;
	X509_PUBKEY_get0_param: function(var p: PASN1_OBJECT; var pk: PAnsiChar; var _ppklen: TC_INT; var palg: PX509_ALGOR; pub: PX509_PUBKEY): TC_INT; cdecl = nil;

	X509_check_trust: function(x: PX509;  _id: TC_INT;_flags: TC_INT): TC_INT; cdecl = nil;
	X509_TRUST_get_count: function: TC_INT; cdecl = nil;
	X509_TRUST_get0: function(_idx: TC_INT): PX509_TRUST; cdecl = nil;
	X509_TRUST_get_by_id: function(_id: TC_INT): TC_INT; cdecl = nil;
	
	X509_TRUST_cleanup: procedure; cdecl= nil;
	X509_TRUST_get_flags: function(xp: PX509_TRUST): TC_INT; cdecl = nil;
	X509_TRUST_get0_name: function(xp: PX509_TRUST): PAnsiChar; cdecl = nil;
	X509_TRUST_get_trust: function(xp: PX509_TRUST): TC_INT; cdecl = nil;

	ERR_load_X509_strings: procedure; cdecl = nil;


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
		
	@X509_dup:= LoadFunctionCLib('X509_dup');
	@X509_ATTRIBUTE_dup:= LoadFunctionCLib('X509_ATTRIBUTE_dup');
	@X509_EXTENSION_dup:= LoadFunctionCLib('X509_EXTENSION_dup');
	@X509_CRL_dup:= LoadFunctionCLib('X509_CRL_dup');
	@X509_REQ_dup:= LoadFunctionCLib('X509_REQ_dup');
	@X509_ALGOR_dup:= LoadFunctionCLib('X509_ALGOR_dup');
	@X509_ALGOR_set0:= LoadFunctionCLib('X509_ALGOR_set0');
	@X509_ALGOR_get0:= LoadFunctionCLib('X509_ALGOR_get0');
	@X509_ALGOR_set_md:= LoadFunctionCLib('X509_ALGOR_set_md');
	@X509_NAME_dup:= LoadFunctionCLib('X509_NAME_dup');
	@X509_NAME_ENTRY_dup:= LoadFunctionCLib('X509_NAME_ENTRY_dup');
	@X509_cmp_time:= LoadFunctionCLib('X509_cmp_time');
	@X509_cmp_current_time:= LoadFunctionCLib('X509_cmp_current_time');
	@X509_time_adj:= LoadFunctionCLib('X509_time_adj');
	@X509_time_adj_ex:= LoadFunctionCLib('X509_time_adj_ex');
	@X509_gmtime_adj:= LoadFunctionCLib('X509_gmtime_adj');
	@X509_get_default_cert_area:= LoadFunctionCLib('X509_get_default_cert_area');
	@X509_get_default_cert_dir:= LoadFunctionCLib('X509_get_default_cert_dir');
	@X509_get_default_cert_file:= LoadFunctionCLib('X509_get_default_cert_file');
	@X509_get_default_cert_dir_env:= LoadFunctionCLib('X509_get_default_cert_dir_env');
	@X509_get_default_cert_file_env:= LoadFunctionCLib('X509_get_default_cert_file_env');
	@X509_get_default_private_dir:= LoadFunctionCLib('X509_get_default_private_dir');
	@X509_to_X509_REQ:= LoadFunctionCLib('X509_to_X509_REQ');
	@X509_REQ_to_X509:= LoadFunctionCLib('X509_REQ_to_X509');
	@X509_PUBKEY_set:= LoadFunctionCLib('X509_PUBKEY_set');
	@X509_PUBKEY_get:= LoadFunctionCLib('X509_PUBKEY_get');
	@X509_get_pubkey_parameters:= LoadFunctionCLib('X509_get_pubkey_parameters');
	@i2d_PUBKEY:= LoadFunctionCLib('i2d_PUBKEY');
	@d2i_PUBKEY:= LoadFunctionCLib('d2i_PUBKEY');
	@i2d_RSA_PUBKEY:= LoadFunctionCLib('i2d_RSA_PUBKEY');
	@d2i_RSA_PUBKEY:= LoadFunctionCLib('d2i_RSA_PUBKEY');
	@i2d_DSA_PUBKEY:= LoadFunctionCLib('i2d_DSA_PUBKEY');
	@d2i_DSA_PUBKEY:= LoadFunctionCLib('d2i_DSA_PUBKEY');
	@i2d_EC_PUBKEY:= LoadFunctionCLib('i2d_EC_PUBKEY');
	@d2i_EC_PUBKEY:= LoadFunctionCLib('d2i_EC_PUBKEY');
	@X509_NAME_set:= LoadFunctionCLib('X509_NAME_set');
	@X509_get_ex_new_index:= LoadFunctionCLib('X509_get_ex_new_index');
	@X509_set_ex_data:= LoadFunctionCLib('X509_set_ex_data');
	@X509_get_ex_data:= LoadFunctionCLib('X509_get_ex_data');
	@i2d_X509_AUX:= LoadFunctionCLib('i2d_X509_AUX');
	@d2i_X509_AUX:= LoadFunctionCLib('d2i_X509_AUX');
	@X509_alias_set1:= LoadFunctionCLib('X509_alias_set1');
	@X509_keyid_set1:= LoadFunctionCLib('X509_keyid_set1');
	@X509_alias_get0:= LoadFunctionCLib('X509_alias_get0');
	@X509_keyid_get0:= LoadFunctionCLib('X509_keyid_get0');
	@X509_TRUST_set:= LoadFunctionCLib('X509_TRUST_set');
	@X509_add1_trust_object:= LoadFunctionCLib('X509_add1_trust_object');
	@X509_add1_reject_object:= LoadFunctionCLib('X509_add1_reject_object');
	@X509_trust_clear:= LoadFunctionCLib('X509_trust_clear');
	@X509_reject_clear:= LoadFunctionCLib('X509_reject_clear');
	@X509_CRL_add0_revoked:= LoadFunctionCLib('X509_CRL_add0_revoked');
	@X509_CRL_get0_by_serial:= LoadFunctionCLib('X509_CRL_get0_by_serial');
	@X509_CRL_get0_by_cert:= LoadFunctionCLib('X509_CRL_get0_by_cert');
	@X509_PKEY_new:= LoadFunctionCLib('X509_PKEY_new');
	@X509_PKEY_free:= LoadFunctionCLib('X509_PKEY_free');
	@i2d_X509_PKEY:= LoadFunctionCLib('i2d_X509_PKEY');
	@d2i_X509_PKEY:= LoadFunctionCLib('d2i_X509_PKEY');
	@X509_INFO_new:= LoadFunctionCLib('X509_INFO_new');
	@X509_INFO_free:= LoadFunctionCLib('X509_INFO_free');
	@X509_NAME_oneline:= LoadFunctionCLib('X509_NAME_oneline');
	@ASN1_verify:= LoadFunctionCLib('ASN1_verify');
	@ASN1_digest:= LoadFunctionCLib('ASN1_digest');
	@ASN1_sign:= LoadFunctionCLib('ASN1_sign');
	@ASN1_item_digest:= LoadFunctionCLib('ASN1_item_digest');
	@ASN1_item_verify:= LoadFunctionCLib('ASN1_item_verify');
	@ASN1_item_sign:= LoadFunctionCLib('ASN1_item_sign');
	@ASN1_item_sign_ctx:= LoadFunctionCLib('ASN1_item_sign_ctx');
	@X509_set_version:= LoadFunctionCLib('X509_set_version');
	@X509_set_serialNumber:= LoadFunctionCLib('X509_set_serialNumber');
	@X509_get_serialNumber:= LoadFunctionCLib('X509_get_serialNumber');
	@X509_set_issuer_name:= LoadFunctionCLib('X509_set_issuer_name');
	@X509_get_issuer_name:= LoadFunctionCLib('X509_get_issuer_name');
	@X509_set_subject_name:= LoadFunctionCLib('X509_set_subject_name');
	@X509_get_subject_name:= LoadFunctionCLib('X509_get_subject_name');
	@X509_set_notBefore:= LoadFunctionCLib('X509_set_notBefore');
	@X509_set_notAfter:= LoadFunctionCLib('X509_set_notAfter');
	@X509_set_pubkey:= LoadFunctionCLib('X509_set_pubkey');
	@X509_get_pubkey:= LoadFunctionCLib('X509_get_pubkey');
	@X509_get0_pubkey_bitstr:= LoadFunctionCLib('X509_get0_pubkey_bitstr');
	@X509_certificate_type:= LoadFunctionCLib('X509_certificate_type');
	@X509_REQ_set_version:= LoadFunctionCLib('X509_REQ_set_version');
	@X509_REQ_set_subject_name:= LoadFunctionCLib('X509_REQ_set_subject_name');
	@X509_REQ_set_pubkey:= LoadFunctionCLib('X509_REQ_set_pubkey');
	@X509_REQ_get_pubkey:= LoadFunctionCLib('X509_REQ_get_pubkey');
	@X509_REQ_extension_nid:= LoadFunctionCLib('X509_REQ_extension_nid');
	@X509_REQ_get_extension_nids:= LoadFunctionCLib('X509_REQ_get_extension_nids');
	@X509_REQ_set_extension_nids:= LoadFunctionCLib('X509_REQ_set_extension_nids');
	@X509_REQ_get_extensions:= LoadFunctionCLib('X509_REQ_get_extensions');
	@X509_REQ_add_extensions_nid:= LoadFunctionCLib('X509_REQ_add_extensions_nid');
	@X509_REQ_add_extensions:= LoadFunctionCLib('X509_REQ_add_extensions');
	@X509_REQ_get_attr_count:= LoadFunctionCLib('X509_REQ_get_attr_count');
	@X509_REQ_get_attr_by_NID:= LoadFunctionCLib('X509_REQ_get_attr_by_NID');
	@X509_REQ_get_attr_by_OBJ:= LoadFunctionCLib('X509_REQ_get_attr_by_OBJ');
	@X509_REQ_get_attr:= LoadFunctionCLib('X509_REQ_get_attr');
	@X509_REQ_delete_attr:= LoadFunctionCLib('X509_REQ_delete_attr');
	@X509_REQ_add1_attr:= LoadFunctionCLib('X509_REQ_add1_attr');
	@X509_REQ_add1_attr_by_OBJ:= LoadFunctionCLib('X509_REQ_add1_attr_by_OBJ');
	@X509_REQ_add1_attr_by_NID:= LoadFunctionCLib('X509_REQ_add1_attr_by_NID');
	@X509_REQ_add1_attr_by_txt:= LoadFunctionCLib('X509_REQ_add1_attr_by_txt');
	@X509_CRL_set_version:= LoadFunctionCLib('X509_CRL_set_version');
	@X509_CRL_set_issuer_name:= LoadFunctionCLib('X509_CRL_set_issuer_name');
	@X509_CRL_set_lastUpdate:= LoadFunctionCLib('X509_CRL_set_lastUpdate');
	@X509_CRL_set_nextUpdate:= LoadFunctionCLib('X509_CRL_set_nextUpdate');
	@X509_CRL_sort:= LoadFunctionCLib('X509_CRL_sort');
	@X509_REVOKED_set_serialNumber:= LoadFunctionCLib('X509_REVOKED_set_serialNumber');
	@X509_REVOKED_set_revocationDate:= LoadFunctionCLib('X509_REVOKED_set_revocationDate');
	@X509_REQ_check_private_key:= LoadFunctionCLib('X509_REQ_check_private_key');
	@X509_check_private_key:= LoadFunctionCLib('X509_check_private_key');
	@X509_issuer_and_serial_cmp:= LoadFunctionCLib('X509_issuer_and_serial_cmp');
	@X509_issuer_and_serial_hash:= LoadFunctionCLib('X509_issuer_and_serial_hash');
	@X509_issuer_name_cmp:= LoadFunctionCLib('X509_issuer_name_cmp');
	@X509_issuer_name_hash:= LoadFunctionCLib('X509_issuer_name_hash');
	@X509_subject_name_cmp:= LoadFunctionCLib('X509_subject_name_cmp');
	@X509_subject_name_hash:= LoadFunctionCLib('X509_subject_name_hash');
	@X509_issuer_name_hash_old:= LoadFunctionCLib('X509_issuer_name_hash_old');
	@X509_subject_name_hash_old:= LoadFunctionCLib('X509_subject_name_hash_old');
	@X509_cmp:= LoadFunctionCLib('X509_cmp');
	@X509_NAME_cmp:= LoadFunctionCLib('X509_NAME_cmp');
	@X509_NAME_hash:= LoadFunctionCLib('X509_NAME_hash');
	@X509_NAME_hash_old:= LoadFunctionCLib('X509_NAME_hash_old');
	@X509_CRL_cmp:= LoadFunctionCLib('X509_CRL_cmp');
	@X509_CRL_match:= LoadFunctionCLib('X509_CRL_match');
	@X509_NAME_print:= LoadFunctionCLib('X509_NAME_print');
	@X509_NAME_print_ex:= LoadFunctionCLib('X509_NAME_print_ex');
	@X509_print_ex:= LoadFunctionCLib('X509_print_ex');
	@X509_print:= LoadFunctionCLib('X509_print');
	@X509_ocspid_print:= LoadFunctionCLib('X509_ocspid_print');
	@X509_CERT_AUX_print:= LoadFunctionCLib('X509_CERT_AUX_print');
	@X509_CRL_print:= LoadFunctionCLib('X509_CRL_print');
	@X509_REQ_print_ex:= LoadFunctionCLib('X509_REQ_print_ex');
	@X509_REQ_print:= LoadFunctionCLib('X509_REQ_print');
	@X509_NAME_entry_count:= LoadFunctionCLib('X509_NAME_entry_count');
	@X509_NAME_get_text_by_NID:= LoadFunctionCLib('X509_NAME_get_text_by_NID');
	@X509_NAME_get_text_by_OBJ:= LoadFunctionCLib('X509_NAME_get_text_by_OBJ');
	@X509_NAME_get_index_by_NID:= LoadFunctionCLib('X509_NAME_get_index_by_NID');
	@X509_NAME_get_index_by_OBJ:= LoadFunctionCLib('X509_NAME_get_index_by_OBJ');
	@X509_NAME_get_entry:= LoadFunctionCLib('X509_NAME_get_entry');
	@X509_NAME_delete_entry:= LoadFunctionCLib('X509_NAME_delete_entry');
	@X509_NAME_add_entry:= LoadFunctionCLib('X509_NAME_add_entry');
	@X509_NAME_add_entry_by_OBJ:= LoadFunctionCLib('X509_NAME_add_entry_by_OBJ');
	@X509_NAME_add_entry_by_NID:= LoadFunctionCLib('X509_NAME_add_entry_by_NID');
	@X509_NAME_ENTRY_create_by_txt:= LoadFunctionCLib('X509_NAME_ENTRY_create_by_txt');
	@X509_NAME_ENTRY_create_by_NID:= LoadFunctionCLib('X509_NAME_ENTRY_create_by_NID');
	@X509_NAME_add_entry_by_txt:= LoadFunctionCLib('X509_NAME_add_entry_by_txt');
	@X509_NAME_ENTRY_create_by_OBJ:= LoadFunctionCLib('X509_NAME_ENTRY_create_by_OBJ');
	@X509_NAME_ENTRY_set_object:= LoadFunctionCLib('X509_NAME_ENTRY_set_object');
	@X509_NAME_ENTRY_set_data:= LoadFunctionCLib('X509_NAME_ENTRY_set_data');
	@X509_NAME_ENTRY_get_object:= LoadFunctionCLib('X509_NAME_ENTRY_get_object');
	@X509_NAME_ENTRY_get_data:= LoadFunctionCLib('X509_NAME_ENTRY_get_data');
	@X509v3_get_ext_count:= LoadFunctionCLib('X509v3_get_ext_count');
	@X509v3_get_ext_by_NID:= LoadFunctionCLib('X509v3_get_ext_by_NID');
	@X509v3_get_ext_by_OBJ:= LoadFunctionCLib('X509v3_get_ext_by_OBJ');
	@X509v3_get_ext_by_critical:= LoadFunctionCLib('X509v3_get_ext_by_critical');
	@X509v3_get_ext:= LoadFunctionCLib('X509v3_get_ext');
	@X509v3_delete_ext:= LoadFunctionCLib('X509v3_delete_ext');
	@X509v3_add_ext:= LoadFunctionCLib('X509v3_add_ext');
	@X509_get_ext_count:= LoadFunctionCLib('X509_get_ext_count');
	@X509_get_ext_by_NID:= LoadFunctionCLib('X509_get_ext_by_NID');
	@X509_get_ext_by_OBJ:= LoadFunctionCLib('X509_get_ext_by_OBJ');
	@X509_get_ext_by_critical:= LoadFunctionCLib('X509_get_ext_by_critical');
	@X509_get_ext:= LoadFunctionCLib('X509_get_ext');
	@X509_delete_ext:= LoadFunctionCLib('X509_delete_ext');
	@X509_add_ext:= LoadFunctionCLib('X509_add_ext');
	@X509_get_ext_d2i:= LoadFunctionCLib('X509_get_ext_d2i');
	@X509_add1_ext_i2d:= LoadFunctionCLib('X509_add1_ext_i2d');
	@X509_CRL_get_ext_count:= LoadFunctionCLib('X509_CRL_get_ext_count');
	@X509_CRL_get_ext_by_NID:= LoadFunctionCLib('X509_CRL_get_ext_by_NID');
	@X509_CRL_get_ext_by_OBJ:= LoadFunctionCLib('X509_CRL_get_ext_by_OBJ');
	@X509_CRL_get_ext_by_critical:= LoadFunctionCLib('X509_CRL_get_ext_by_critical');
	@X509_CRL_get_ext:= LoadFunctionCLib('X509_CRL_get_ext');
	@X509_CRL_delete_ext:= LoadFunctionCLib('X509_CRL_delete_ext');
	@X509_CRL_add_ext:= LoadFunctionCLib('X509_CRL_add_ext');
	@X509_CRL_get_ext_d2i:= LoadFunctionCLib('X509_CRL_get_ext_d2i');
	@X509_CRL_add1_ext_i2d:= LoadFunctionCLib('X509_CRL_add1_ext_i2d');
	@X509_REVOKED_get_ext_count:= LoadFunctionCLib('X509_REVOKED_get_ext_count');
	@X509_REVOKED_get_ext_by_NID:= LoadFunctionCLib('X509_REVOKED_get_ext_by_NID');
	@X509_REVOKED_get_ext_by_OBJ:= LoadFunctionCLib('X509_REVOKED_get_ext_by_OBJ');
	@X509_REVOKED_get_ext_by_critical:= LoadFunctionCLib('X509_REVOKED_get_ext_by_critical');
	@X509_REVOKED_get_ext:= LoadFunctionCLib('X509_REVOKED_get_ext');
	@X509_REVOKED_delete_ext:= LoadFunctionCLib('X509_REVOKED_delete_ext');
	@X509_REVOKED_add_ext:= LoadFunctionCLib('X509_REVOKED_add_ext');
	@X509_REVOKED_get_ext_d2i:= LoadFunctionCLib('X509_REVOKED_get_ext_d2i');
	@X509_REVOKED_add1_ext_i2d:= LoadFunctionCLib('X509_REVOKED_add1_ext_i2d');
	@X509_EXTENSION_create_by_NID:= LoadFunctionCLib('X509_EXTENSION_create_by_NID');
	@X509_EXTENSION_create_by_OBJ:= LoadFunctionCLib('X509_EXTENSION_create_by_OBJ');
	@X509_EXTENSION_set_object:= LoadFunctionCLib('X509_EXTENSION_set_object');
	@X509_EXTENSION_set_critical:= LoadFunctionCLib('X509_EXTENSION_set_critical');
	@X509_EXTENSION_set_data:= LoadFunctionCLib('X509_EXTENSION_set_data');
	@X509_EXTENSION_get_object:= LoadFunctionCLib('X509_EXTENSION_get_object');
	@X509_EXTENSION_get_data:= LoadFunctionCLib('X509_EXTENSION_get_data');
	@X509_EXTENSION_get_critical:= LoadFunctionCLib('X509_EXTENSION_get_critical');
	@X509at_get_attr_count:= LoadFunctionCLib('X509at_get_attr_count');
	@X509at_get_attr_by_NID:= LoadFunctionCLib('X509at_get_attr_by_NID');
	@X509at_get_attr_by_OBJ:= LoadFunctionCLib('X509at_get_attr_by_OBJ');
	@X509at_get_attr:= LoadFunctionCLib('X509at_get_attr');
	@X509at_delete_attr:= LoadFunctionCLib('X509at_delete_attr');
	@X509at_add1_attr:= LoadFunctionCLib('X509at_add1_attr');
	@X509at_add1_attr_by_OBJ:= LoadFunctionCLib('X509at_add1_attr_by_OBJ');
	@X509at_add1_attr_by_NID:= LoadFunctionCLib('X509at_add1_attr_by_NID');
	@X509at_add1_attr_by_txt:= LoadFunctionCLib('X509at_add1_attr_by_txt');
	@X509at_get0_data_by_OBJ:= LoadFunctionCLib('X509at_get0_data_by_OBJ');
	@X509_ATTRIBUTE_create_by_NID:= LoadFunctionCLib('X509_ATTRIBUTE_create_by_NID');
	@X509_ATTRIBUTE_create_by_OBJ:= LoadFunctionCLib('X509_ATTRIBUTE_create_by_OBJ');
	@X509_ATTRIBUTE_create_by_txt:= LoadFunctionCLib('X509_ATTRIBUTE_create_by_txt');
	@X509_ATTRIBUTE_set1_object:= LoadFunctionCLib('X509_ATTRIBUTE_set1_object');
	@X509_ATTRIBUTE_set1_data:= LoadFunctionCLib('X509_ATTRIBUTE_set1_data');
	@X509_ATTRIBUTE_get0_data:= LoadFunctionCLib('X509_ATTRIBUTE_get0_data');
	@X509_ATTRIBUTE_count:= LoadFunctionCLib('X509_ATTRIBUTE_count');
	@X509_ATTRIBUTE_get0_object:= LoadFunctionCLib('X509_ATTRIBUTE_get0_object');
	@X509_ATTRIBUTE_get0_type:= LoadFunctionCLib('X509_ATTRIBUTE_get0_type');
	@EVP_PKEY_get_attr_count:= LoadFunctionCLib('EVP_PKEY_get_attr_count');
	@EVP_PKEY_get_attr_by_NID:= LoadFunctionCLib('EVP_PKEY_get_attr_by_NID');
	@EVP_PKEY_get_attr_by_OBJ:= LoadFunctionCLib('EVP_PKEY_get_attr_by_OBJ');
	@EVP_PKEY_get_attr:= LoadFunctionCLib('EVP_PKEY_get_attr');
	@EVP_PKEY_delete_attr:= LoadFunctionCLib('EVP_PKEY_delete_attr');
	@EVP_PKEY_add1_attr:= LoadFunctionCLib('EVP_PKEY_add1_attr');
	@EVP_PKEY_add1_attr_by_OBJ:= LoadFunctionCLib('EVP_PKEY_add1_attr_by_OBJ');
	@EVP_PKEY_add1_attr_by_NID:= LoadFunctionCLib('EVP_PKEY_add1_attr_by_NID');
	@EVP_PKEY_add1_attr_by_txt:= LoadFunctionCLib('EVP_PKEY_add1_attr_by_txt');
	@X509_verify_cert:= LoadFunctionCLib('X509_verify_cert');
	@X509_find_by_issuer_and_serial:= LoadFunctionCLib('X509_find_by_issuer_and_serial');
	@X509_find_by_subject:= LoadFunctionCLib('X509_find_by_subject');
	@PKCS5_pbe_set0_algor:= LoadFunctionCLib('PKCS5_pbe_set0_algor');
	@PKCS5_pbe_set:= LoadFunctionCLib('PKCS5_pbe_set');
	@PKCS5_pbe2_set:= LoadFunctionCLib('PKCS5_pbe2_set');
	@PKCS5_pbe2_set_iv:= LoadFunctionCLib('PKCS5_pbe2_set_iv');
	@PKCS5_pbkdf2_set:= LoadFunctionCLib('PKCS5_pbkdf2_set');
	@EVP_PKCS82PKEY:= LoadFunctionCLib('EVP_PKCS82PKEY');
	@EVP_PKEY2PKCS8:= LoadFunctionCLib('EVP_PKEY2PKCS8');
	@EVP_PKEY2PKCS8_broken:= LoadFunctionCLib('EVP_PKEY2PKCS8_broken');
	@PKCS8_set_broken:= LoadFunctionCLib('PKCS8_set_broken');
	@PKCS8_pkey_set0:= LoadFunctionCLib('PKCS8_pkey_set0');
	@PKCS8_pkey_get0:= LoadFunctionCLib('PKCS8_pkey_get0');
	@X509_PUBKEY_set0_param:= LoadFunctionCLib('X509_PUBKEY_set0_param');
	@X509_PUBKEY_get0_param:= LoadFunctionCLib('X509_PUBKEY_get0_param');
	@X509_check_trust:= LoadFunctionCLib('X509_check_trust');
	@X509_TRUST_get_count:= LoadFunctionCLib('X509_TRUST_get_count');
	@X509_TRUST_get0:= LoadFunctionCLib('X509_TRUST_get0');
	@X509_TRUST_get_by_id:= LoadFunctionCLib('X509_TRUST_get_by_id');
	@X509_TRUST_cleanup:= LoadFunctionCLib('X509_TRUST_cleanup');
	@X509_TRUST_get_flags:= LoadFunctionCLib('X509_TRUST_get_flags');
	@X509_TRUST_get0_name:= LoadFunctionCLib('X509_TRUST_get0_name');
	@X509_TRUST_get_trust:= LoadFunctionCLib('X509_TRUST_get_trust');	

  end;
end;
end.
