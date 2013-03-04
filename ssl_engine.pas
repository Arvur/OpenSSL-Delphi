unit ssl_engine;

interface
uses ssl_types;

var
  ENGINE_get_first: function: PENGINE; cdecl = nil;
  ENGINE_get_last: function: PENGINE; cdecl = nil;
  ENGINE_get_next: function(e: PENGINE): PENGINE; cdecl = nil;
  ENGINE_get_prev: function(e: PENGINE): PENGINE; cdecl = nil;
  ENGINE_add: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_remove: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_by_id: function(id: PAnsiChar): PENGINE; cdecl = nil;

  ENGINE_load_openssl: procedure; cdecl = nil;
  ENGINE_load_dynamic: procedure; cdecl = nil;
  ENGINE_load_4758cca: procedure; cdecl = nil;
  ENGINE_load_aep: procedure; cdecl = nil;
  ENGINE_load_atalla: procedure; cdecl = nil;
  ENGINE_load_chil: procedure; cdecl = nil;
  ENGINE_load_cswift: procedure; cdecl = nil;
  ENGINE_load_nuron: procedure; cdecl = nil;
  ENGINE_load_sureware: procedure; cdecl = nil;
  ENGINE_load_ubsec: procedure; cdecl = nil;
  ENGINE_load_padlock: procedure; cdecl = nil;
  ENGINE_load_capi: procedure; cdecl = nil;
  ENGINE_load_gmp: procedure; cdecl = nil;
  ENGINE_load_gost: procedure; cdecl = nil;
  ENGINE_load_cryptodev: procedure; cdecl = nil;
  ENGINE_load_rsax: procedure; cdecl = nil;
  ENGINE_load_rdrand: procedure; cdecl = nil;
  ENGINE_load_builtin_engines: procedure; cdecl = nil;

  ENGINE_get_table_flags: function:TC_UINT; cdecl = nil;
  ENGINE_set_table_flags:procedure(flags: TC_UINT); cdecl = nil;

  ENGINE_register_RSA: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_RSA: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_RSA: procedure; cdecl = nil;

  ENGINE_register_DSA: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_DSA: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_DSA: procedure; cdecl = nil;

  ENGINE_register_ECDH: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_ECDH: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_ECDH: procedure; cdecl = nil;

  ENGINE_register_ECDSA: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_ECDSA: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_ECDSA: procedure; cdecl = nil;

  ENGINE_register_DH: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_DH: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_DH: procedure; cdecl = nil;

  ENGINE_register_RAND: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_RAND: procedure(e: PENGINE);
  ENGINE_register_all_RAND: procedure; cdecl = nil;

  ENGINE_register_STORE: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_STORE: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_STORE: procedure; cdecl = nil;

  ENGINE_register_ciphers: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_ciphers: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_ciphers: procedure; cdecl = nil;

  ENGINE_register_digests: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_digests: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_digests: procedure; cdecl = nil;

  ENGINE_register_pkey_meths: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_pkey_meths: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_pkey_meths: procedure; cdecl = nil;

  ENGINE_register_pkey_asn1_meths: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_unregister_pkey_asn1_meths: procedure(e: PENGINE); cdecl = nil;
  ENGINE_register_all_pkey_asn1_meths: procedure; cdecl = nil;

  ENGINE_register_complete: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_register_all_complete: procedure; cdecl = nil;

  ENGINE_ctrl: function(e: PENGINE; cmd: TC_INT; i: TC_LONG; p: Pointer; f: ENGINE_CB_FUNC): TC_INT; cdecl = nil;
  ENGINE_cmd_is_executable: function(e: PENGINE; cmd: TC_INT): TC_INT; cdecl = nil;
  ENGINE_ctrl_cmd: function(e: PENGINE; const cmd_name: PAnsiChar; i: TC_LONG; p: Pointer; f:ENGINE_CB_FUNC; cmd_optional: TC_INT): TC_INT; cdecl = nil;
  ENGINE_ctrl_cmd_string: function(e: PENGINE; const cmd_name: PAnsiChar; const arg: PAnsiChar;	cmd_optional: TC_INT): TC_INT; cdecl = nil;


  ENGINE_new: function: PENGINE;
  ENGINE_free: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_up_ref: function(e: PENGINE): TC_INT; cdecl = nil;
  ENGINE_set_id: function(e: PENGINE; id: PAnsiChar): TC_INT; cdecl = nil;
  ENGINE_set_name: function(e: PENGINE; name: PAnsiChar): TC_INT; cdecl = nil;
  ENGINE_set_RSA: function(e: PENGINE; rsa_meth: PRSA_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_DSA: function(e: PENGINE; dsa_meth: PDSA_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_ECDH: function(e: PENGINE; ecdh_meth: PECDH_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_ECDSA: function(e: PENGINE; ecdsa_meth: PECDSA_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_DH: function(e: PENGINE; dh_meth: PDH_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_RAND: function(e: PENGINE; rand_meth: PRAND_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_STORE: function(e: PENGINE; store_meth: PSTORE_METHOD): TC_INT; cdecl = nil;
  ENGINE_set_destroy_function: function(e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TC_INT; cdecl = nil;
  ENGINE_set_init_function: function(e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR ): TC_INT; cdecl = nil;
  ENGINE_set_finish_function: function(e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TC_INT; cdecl = nil;
  ENGINE_set_ctrl_function: function(e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TC_INT; cdecl = nil;
  ENGINE_set_load_privkey_function: function(e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TC_INT; cdecl = nil;
  ENGINE_set_load_pubkey_function: function(e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TC_INT; cdecl = nil;
  ENGINE_set_load_ssl_client_cert_function: function(e: PENGINE; loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR ): TC_INT; cdecl = nil;
  ENGINE_set_ciphers: function(e: PENGINE; f: ENGINE_CIPHERS_PTR): TC_INT; cdecl = nil;
  ENGINE_set_digests: function(e: PENGINE; f: ENGINE_DIGESTS_PTR): TC_INT; cdecl = nil;
  ENGINE_set_pkey_meths: function(e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TC_INT; cdecl = nil;
  ENGINE_set_pkey_asn1_meths: function(e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TC_INT; cdecl = nil;
  ENGINE_set_flags: function(e: PENGINE; flags: TC_INT): TC_INT; cdecl = nil;
  ENGINE_set_cmd_defns: function(e: PENGINE; defns: PENGINE_CMD_DEFN): TC_INT; cdecl = nil;
  ENGINE_get_ex_new_index: function(argl: TC_LONG; argp: Pointer; new_func: CRYPTO_EX_new; dup_func: CRYPTO_EX_dup; free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
  ENGINE_set_ex_data: function(e: PENGINE; idx: TC_INT; arg: Pointer): TC_INT; cdecl = nil;
  ENGINE_get_ex_data: function(const e: PENGINE; idx: TC_INT): Pointer; cdecl = nil;
  ENGINE_add_conf_module: procedure; cdecl = nil;
  ENGINE_get_pkey_asn1_meth_str: function(e: PENGINE; const str: PAnsiChar; len: TC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;

  ENGINE_cleanup: procedure; cdecl = nil;
  ENGINE_get_id: function(const E: PENGINE): PAnsiChar; cdecl = nil;
  ENGINE_get_name: function(const _e: PENGINE): PAnsiChar; cdecl = nil;
  ENGINE_get_RSA: function(const _e: PENGINE): PRSA_METHOD; cdecl = nil;
  ENGINE_get_DSA: function(const _e: PENGINE): PDSA_METHOD; cdecl = nil;
  ENGINE_get_ECDH: function(const _e: PENGINE): PECDH_METHOD; cdecl = nil;
  ENGINE_get_ECDSA: function(const _e: PENGINE): PECDSA_METHOD; cdecl = nil;
  ENGINE_get_DH: function(const _e: PENGINE): PDH_METHOD; cdecl = nil;
  ENGINE_get_RAND: function(const _e: PENGINE): PRAND_METHOD; cdecl = nil;
  ENGINE_get_STORE: function(const _e: PENGINE): PSTORE_METHOD; cdecl = nil;
  ENGINE_get_destroy_function: function(const _e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
	ENGINE_get_init_function: function(const _e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
	ENGINE_get_finish_function: function(const _e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
	ENGINE_get_ctrl_function: function(const _e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl = nil;
	ENGINE_get_load_privkey_function: function(const _e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
	ENGINE_get_load_pubkey_function: function(const _e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
	ENGINE_get_ssl_client_cert_function: function(const _e: PENGINE): ENGINE_SSL_CLIENT_CERT_PTR; cdecl = nil;
	ENGINE_get_ciphers: function(const _e: PENGINE): ENGINE_CIPHERS_PTR; cdecl = nil;
	ENGINE_get_digests: function(const _e: PENGINE): ENGINE_DIGESTS_PTR; cdecl = nil;
	ENGINE_get_pkey_meths: function(const _e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl = nil;
	ENGINE_get_pkey_asn1_meths: function(const _e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl = nil;
	ENGINE_get_cipher: function(_e: PENGINE; _nid: TC_INT): PEVP_CIPHER; cdecl = nil;
	ENGINE_get_digest: function(_e: PENGINE; _nid: TC_INT): PEVP_MD; cdecl = nil;
	ENGINE_get_pkey_meth: function(_e: PENGINE; _nid: TC_INT): PEVP_PKEY_METHOD; cdecl = nil;
	ENGINE_get_pkey_asn1_meth: function(_e: PENGINE; _nid: TC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
	ENGINE_get_cmd_defns: function(const _e: PENGINE): PENGINE_CMD_DEFN; cdecl = nil;
	ENGINE_get_flags: function(const _e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_init: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_finish: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_load_private_key: function(_e: PENGINE; const _key_id: PAnsiChar;_ui_method: PUI_METHOD; _callback_data: Pointer): PEVP_PKEY; cdecl = nil;
	ENGINE_load_public_key: function(_e: PENGINE; const _key_id: PAnsiChar;_ui_method: PUI_METHOD; _callback_data: Pointer): PEVP_PKEY; cdecl = nil;
	ENGINE_load_ssl_client_cert: function(_e: PENGINE; _s: PSSL; _ca_dn: PSTACK_OF_X509_NAME; _pcert: PPX509; _ppkey: PPEVP_PKEY; _pother: PPSTACK_OF_X509;_ui_method: PUI_METHOD; _callback_data: Pointer): TC_INT; cdecl = nil;
	ENGINE_get_default_RSA: function: PENGINE; cdecl = nil;
	ENGINE_get_default_DSA: function: PENGINE; cdecl = nil;
	ENGINE_get_default_ECDH: function: PENGINE; cdecl = nil;
	ENGINE_get_default_ECDSA: function: PENGINE; cdecl = nil;
	ENGINE_get_default_DH: function: PENGINE; cdecl = nil;
	ENGINE_get_default_RAND: function: PENGINE; cdecl = nil;
	ENGINE_get_cipher_engine: function(_nid: TC_INT): PENGINE; cdecl = nil;
	ENGINE_get_digest_engine: function(_nid: TC_INT): PENGINE; cdecl = nil;
	ENGINE_get_pkey_meth_engine: function(_nid: TC_INT): PENGINE; cdecl = nil;
	ENGINE_get_pkey_asn1_meth_engine: function(_nid: TC_INT): PENGINE; cdecl = nil;
	ENGINE_set_default_RSA: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_string: function(_e: PENGINE; const _def_list: PAnsiChar): TC_INT; cdecl = nil;
	ENGINE_set_default_DSA: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_ECDH: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_ECDSA: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_DH: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_RAND: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_ciphers: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_digests: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_pkey_meths: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default_pkey_asn1_meths: function(_e: PENGINE): TC_INT; cdecl = nil;
	ENGINE_set_default: function(_e: PENGINE; _flags: TC_UINT): TC_INT; cdecl = nil;
	ENGINE_get_static_state: function: Pointer; cdecl = nil;
	ERR_load_ENGINE_strings: procedure; cdecl = nil;

procedure SSL_InitENGINE;

implementation
uses ssl_lib;

procedure SSL_InitENGINE;
begin
  if @ENGINE_get_first = nil then
  begin
     @ENGINE_get_first := LoadFunctionCLib('ENGINE_get_first');
     @ENGINE_get_last := LoadFunctionCLib('ENGINE_get_last');
     @ENGINE_get_next:= LoadFunctionCLib('ENGINE_get_next');
     @ENGINE_get_prev:= LoadFunctionCLib('ENGINE_get_prev');
     @ENGINE_add:= LoadFunctionCLib('ENGINE_add');
     @ENGINE_remove:= LoadFunctionCLib('ENGINE_remove');
     @ENGINE_by_id:= LoadFunctionCLib('ENGINE_by_id');
     @ENGINE_load_openssl := LoadFunctionCLib('ENGINE_load_openssl');
     @ENGINE_load_dynamic:= LoadFunctionCLib('ENGINE_load_dynamic');
     @ENGINE_load_4758cca:= LoadFunctionCLib('ENGINE_load_4758cca', false);
     @ENGINE_load_aep:= LoadFunctionCLib('ENGINE_load_aep', false);
     @ENGINE_load_atalla:= LoadFunctionCLib('ENGINE_load_atalla', false);
     @ENGINE_load_chil:= LoadFunctionCLib('ENGINE_load_chil', false);
     @ENGINE_load_cswift:= LoadFunctionCLib('ENGINE_load_cswift', false);
     @ENGINE_load_nuron:= LoadFunctionCLib('ENGINE_load_nuron', false);
     @ENGINE_load_sureware:= LoadFunctionCLib('ENGINE_load_sureware', false);
     @ENGINE_load_ubsec:= LoadFunctionCLib('ENGINE_load_ubsec', false);
     @ENGINE_load_padlock:= LoadFunctionCLib('ENGINE_load_padlock', false);
     @ENGINE_load_capi:= LoadFunctionCLib('ENGINE_load_capi', false);
     @ENGINE_load_gmp:= LoadFunctionCLib('ENGINE_load_gmp', false);
     @ENGINE_load_gost:= LoadFunctionCLib('ENGINE_load_gost', false);
     @ENGINE_load_cryptodev:= LoadFunctionCLib('ENGINE_load_cryptodev');
     @ENGINE_load_rsax:= LoadFunctionCLib('ENGINE_load_rsax');
     @ENGINE_load_rdrand:= LoadFunctionCLib('ENGINE_load_rdrand');
     @ENGINE_load_builtin_engines:= LoadFunctionCLib('ENGINE_load_builtin_engines');
     @ENGINE_get_table_flags:= LoadFunctionCLib('ENGINE_get_table_flags');
     @ENGINE_set_table_flags:= LoadFunctionCLib('ENGINE_set_table_flags');
     @ENGINE_register_RSA:= LoadFunctionCLib('ENGINE_register_RSA');
     @ENGINE_unregister_RSA:= LoadFunctionCLib('ENGINE_unregister_RSA');
     @ENGINE_register_all_RSA:= LoadFunctionCLib('ENGINE_register_all_RSA');
     @ENGINE_register_DSA:= LoadFunctionCLib('ENGINE_register_DSA');
     @ENGINE_unregister_DSA:= LoadFunctionCLib('ENGINE_unregister_DSA');
     @ENGINE_register_all_DSA:= LoadFunctionCLib('ENGINE_register_all_DSA');
     @ENGINE_register_ECDH:= LoadFunctionCLib('ENGINE_register_ECDH');
     @ENGINE_unregister_ECDH:= LoadFunctionCLib('ENGINE_unregister_ECDH');
     @ENGINE_register_all_ECDH:= LoadFunctionCLib('ENGINE_register_all_ECDH');
     @ENGINE_register_ECDSA:= LoadFunctionCLib('ENGINE_register_ECDSA');
     @ENGINE_unregister_ECDSA:= LoadFunctionCLib('ENGINE_unregister_ECDSA');
     @ENGINE_register_all_ECDSA:= LoadFunctionCLib('ENGINE_register_all_ECDSA');
     @ENGINE_register_DH:= LoadFunctionCLib('ENGINE_register_DH');
     @ENGINE_unregister_DH:= LoadFunctionCLib('ENGINE_unregister_DH');
     @ENGINE_register_all_DH:= LoadFunctionCLib('ENGINE_register_all_DH');
     @ENGINE_register_RAND:= LoadFunctionCLib('ENGINE_register_RAND');
     @ENGINE_unregister_RAND:= LoadFunctionCLib('ENGINE_unregister_RAND');
     @ENGINE_register_all_RAND:= LoadFunctionCLib('ENGINE_register_all_RAND');
     @ENGINE_register_STORE:= LoadFunctionCLib('ENGINE_register_STORE');
     @ENGINE_unregister_STORE:= LoadFunctionCLib('ENGINE_unregister_STORE');
     @ENGINE_register_all_STORE:= LoadFunctionCLib('ENGINE_register_all_STORE');
     @ENGINE_register_ciphers:= LoadFunctionCLib('ENGINE_register_ciphers');
     @ENGINE_unregister_ciphers:= LoadFunctionCLib('ENGINE_unregister_ciphers');
     @ENGINE_register_all_ciphers:= LoadFunctionCLib('ENGINE_register_all_ciphers');
     @ENGINE_register_digests:= LoadFunctionCLib('ENGINE_register_digests');
     @ENGINE_unregister_digests:= LoadFunctionCLib('ENGINE_unregister_digests');
     @ENGINE_register_all_digests:= LoadFunctionCLib('ENGINE_register_all_digests');
     @ENGINE_register_pkey_meths:= LoadFunctionCLib('ENGINE_register_pkey_meths');
     @ENGINE_unregister_pkey_meths:= LoadFunctionCLib('ENGINE_unregister_pkey_meths');
     @ENGINE_register_all_pkey_meths:= LoadFunctionCLib('ENGINE_register_all_pkey_meths');
     @ENGINE_register_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_register_pkey_asn1_meths');
     @ENGINE_unregister_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_unregister_pkey_asn1_meths');
     @ENGINE_register_all_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_register_all_pkey_asn1_meths');
     @ENGINE_register_complete:= LoadFunctionCLib('ENGINE_register_complete');
     @ENGINE_register_all_complete:= LoadFunctionCLib('ENGINE_register_all_complete');    
     @ENGINE_new:= LoadFunctionCLib('ENGINE_new');
     @ENGINE_free:= LoadFunctionCLib('ENGINE_free');
     @ENGINE_up_ref:= LoadFunctionCLib('ENGINE_up_ref');
     @ENGINE_set_id:= LoadFunctionCLib('ENGINE_set_id');
     @ENGINE_set_name:= LoadFunctionCLib('ENGINE_set_name');
     @ENGINE_set_RSA:= LoadFunctionCLib('ENGINE_set_RSA');
     @ENGINE_set_DSA:= LoadFunctionCLib('ENGINE_set_DSA');
     @ENGINE_set_ECDH:= LoadFunctionCLib('ENGINE_set_ECDH');
     @ENGINE_set_ECDSA:= LoadFunctionCLib('ENGINE_set_ECDSA');
     @ENGINE_set_DH:= LoadFunctionCLib('ENGINE_set_DH');
     @ENGINE_set_RAND:= LoadFunctionCLib('ENGINE_set_RAND');
     @ENGINE_set_STORE:= LoadFunctionCLib('ENGINE_set_STORE');
     @ENGINE_set_destroy_function:= LoadFunctionCLib('ENGINE_set_destroy_function');
     @ENGINE_set_init_function:= LoadFunctionCLib('ENGINE_set_init_function');
     @ENGINE_set_finish_function:= LoadFunctionCLib('ENGINE_set_finish_function');
     @ENGINE_set_ctrl_function:= LoadFunctionCLib('ENGINE_set_ctrl_function');
     @ENGINE_set_load_privkey_function:= LoadFunctionCLib('ENGINE_set_load_privkey_function');
     @ENGINE_set_load_pubkey_function:= LoadFunctionCLib('ENGINE_set_load_pubkey_function');
     @ENGINE_set_load_ssl_client_cert_function:= LoadFunctionCLib('ENGINE_set_load_ssl_client_cert_function');
     @ENGINE_set_ciphers:= LoadFunctionCLib('ENGINE_set_ciphers');
     @ENGINE_set_digests:= LoadFunctionCLib('ENGINE_set_digests');
     @ENGINE_set_pkey_meths:= LoadFunctionCLib('ENGINE_set_pkey_meths');
     @ENGINE_set_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_set_pkey_asn1_meths');
     @ENGINE_set_flags:= LoadFunctionCLib('ENGINE_set_flags');
     @ENGINE_set_cmd_defns:= LoadFunctionCLib('ENGINE_set_cmd_defns');
     @ENGINE_get_ex_new_index:= LoadFunctionCLib('ENGINE_get_ex_new_index');
     @ENGINE_set_ex_data:= LoadFunctionCLib('ENGINE_set_ex_data');
     @ENGINE_get_ex_data:= LoadFunctionCLib('ENGINE_get_ex_data');
     @ENGINE_add_conf_module := LoadFunctionCLib('ENGINE_add_conf_module');

     @ENGINE_ctrl:= LoadFunctionCLib('ENGINE_ctrl');
     @ENGINE_cmd_is_executable:= LoadFunctionCLib('ENGINE_cmd_is_executable');
     @ENGINE_ctrl_cmd:= LoadFunctionCLib('ENGINE_ctrl_cmd');
     @ENGINE_ctrl_cmd_string:= LoadFunctionCLib('ENGINE_ctrl_cmd_string');

     @ENGINE_get_pkey_asn1_meth_str := LoadFunctionCLib('ENGINE_get_pkey_asn1_meth_str');
          
	   @ENGINE_cleanup:= LoadFunctionCLib('ENGINE_cleanup');
     @ENGINE_get_id:= LoadFunctionCLib('ENGINE_get_id');
     @ENGINE_get_name:= LoadFunctionCLib('ENGINE_get_name');
     @ENGINE_get_RSA:= LoadFunctionCLib('ENGINE_get_RSA');
     @ENGINE_get_DSA:= LoadFunctionCLib('ENGINE_get_DSA');
     @ENGINE_get_ECDH:= LoadFunctionCLib('ENGINE_get_ECDH');
     @ENGINE_get_ECDSA:= LoadFunctionCLib('ENGINE_get_ECDSA');
     @ENGINE_get_DH:= LoadFunctionCLib('ENGINE_get_DH');
     @ENGINE_get_RAND:= LoadFunctionCLib('ENGINE_get_RAND');
     @ENGINE_get_STORE:= LoadFunctionCLib('ENGINE_get_STORE');
     @ENGINE_get_destroy_function:= LoadFunctionCLib('ENGINE_get_destroy_function');
	   @ENGINE_get_init_function:= LoadFunctionCLib('ENGINE_get_init_function');
	   @ENGINE_get_finish_function:= LoadFunctionCLib('ENGINE_get_finish_function');
	   @ENGINE_get_ctrl_function:= LoadFunctionCLib('ENGINE_get_ctrl_function');
	   @ENGINE_get_load_privkey_function:= LoadFunctionCLib('ENGINE_get_load_privkey_function');
	   @ENGINE_get_load_pubkey_function:= LoadFunctionCLib('ENGINE_get_load_pubkey_function');
	   @ENGINE_get_ssl_client_cert_function:= LoadFunctionCLib('ENGINE_get_ssl_client_cert_function');
	   @ENGINE_get_ciphers:= LoadFunctionCLib('ENGINE_get_ciphers');
	   @ENGINE_get_digests:= LoadFunctionCLib('ENGINE_get_digests');
	   @ENGINE_get_pkey_meths:= LoadFunctionCLib('ENGINE_get_pkey_meths');
	   @ENGINE_get_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_get_pkey_asn1_meths');
	   @ENGINE_get_cipher:= LoadFunctionCLib('ENGINE_get_cipher');
	   @ENGINE_get_digest:= LoadFunctionCLib('ENGINE_get_digest');
	   @ENGINE_get_pkey_meth:= LoadFunctionCLib('ENGINE_get_pkey_meth');
	   @ENGINE_get_pkey_asn1_meth:= LoadFunctionCLib('ENGINE_get_pkey_asn1_meth');
	   @ENGINE_get_cmd_defns:= LoadFunctionCLib('ENGINE_get_cmd_defns');
	   @ENGINE_get_flags:= LoadFunctionCLib('ENGINE_get_flags');
	   @ENGINE_init:= LoadFunctionCLib('ENGINE_init');
	   @ENGINE_finish:= LoadFunctionCLib('ENGINE_finish');
	   @ENGINE_load_private_key:= LoadFunctionCLib('ENGINE_load_private_key');
	   @ENGINE_load_public_key:= LoadFunctionCLib('ENGINE_load_public_key');
	   @ENGINE_load_ssl_client_cert:= LoadFunctionCLib('ENGINE_load_ssl_client_cert');
	   @ENGINE_get_default_RSA:= LoadFunctionCLib('ENGINE_get_default_RSA');
	   @ENGINE_get_default_DSA:= LoadFunctionCLib('ENGINE_get_default_DSA');
	   @ENGINE_get_default_ECDH:= LoadFunctionCLib('ENGINE_get_default_ECDH');
	   @ENGINE_get_default_ECDSA:= LoadFunctionCLib('ENGINE_get_default_ECDSA');
	   @ENGINE_get_default_DH:= LoadFunctionCLib('ENGINE_get_default_DH');
	   @ENGINE_get_default_RAND:= LoadFunctionCLib('ENGINE_get_default_RAND');
	   @ENGINE_get_cipher_engine:= LoadFunctionCLib('ENGINE_get_cipher_engine');
	   @ENGINE_get_digest_engine:= LoadFunctionCLib('ENGINE_get_digest_engine');
	   @ENGINE_get_pkey_meth_engine:= LoadFunctionCLib('ENGINE_get_pkey_meth_engine');
	   @ENGINE_get_pkey_asn1_meth_engine:= LoadFunctionCLib('ENGINE_get_pkey_asn1_meth_engine');
	   @ENGINE_set_default_RSA:= LoadFunctionCLib('ENGINE_set_default_RSA');
	   @ENGINE_set_default_string:= LoadFunctionCLib('ENGINE_set_default_string');
	   @ENGINE_set_default_DSA:= LoadFunctionCLib('ENGINE_set_default_DSA');
	   @ENGINE_set_default_ECDH:= LoadFunctionCLib('ENGINE_set_default_ECDH');
	   @ENGINE_set_default_ECDSA:= LoadFunctionCLib('ENGINE_set_default_ECDSA');
	   @ENGINE_set_default_DH:= LoadFunctionCLib('ENGINE_set_default_DH');
	   @ENGINE_set_default_RAND:= LoadFunctionCLib('ENGINE_set_default_RAND');
	   @ENGINE_set_default_ciphers:= LoadFunctionCLib('ENGINE_set_default_ciphers');
	   @ENGINE_set_default_digests:= LoadFunctionCLib('ENGINE_set_default_digests');
	   @ENGINE_set_default_pkey_meths:= LoadFunctionCLib('ENGINE_set_default_pkey_meths');
	   @ENGINE_set_default_pkey_asn1_meths:= LoadFunctionCLib('ENGINE_set_default_pkey_asn1_meths');
	   @ENGINE_set_default:= LoadFunctionCLib('ENGINE_set_default');
	   @ENGINE_get_static_state:= LoadFunctionCLib('ENGINE_get_static_state');
	   @ERR_load_ENGINE_strings:= LoadFunctionCLib('ERR_load_ENGINE_strings');


  end;

end;
end.
