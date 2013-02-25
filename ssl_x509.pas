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

  end;
end;
end.
