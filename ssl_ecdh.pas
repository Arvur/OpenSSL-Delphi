unit ssl_ecdh;

interface
uses ssl_types;
var
	ECDH_OpenSSL: function: PECDH_METHOD; cdecl = nil;

	ECDH_set_default_method: procedure(const _p: PECDH_METHOD); cdecl = nil;
	ECDH_get_default_method: function: PECDH_METHOD; cdecl = nil;
	ECDH_set_method: function(_key: PEC_KEY; const _p: PECDH_METHOD): TC_INT; cdecl = nil;

	ECDH_compute_key: function(_out: Pointer; outlen: TC_SIZE_T; const _pub_key: PEC_POINT; _ecdh: PEC_KEY; KDF: ecdh_kdf): TC_INT; cdecl = nil;

	ECDH_get_ex_new_index: function(_argl: TC_LONG; _argp: Pointer; _new_func: CRYPTO_EX_new; _dup_func: CRYPTO_EX_dup; _free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
	ECDH_set_ex_data: function(_d: PEC_KEY; _idx: TC_INT; _arg: Pointer): TC_INT; cdecl = nil;
	ECDH_get_ex_data: function(_d: Pointer; _idx: TC_INT): Pointer; cdecl = nil;

	ERR_load_ECDH_strings: procedure; cdecl = nil;


procedure SSL_InitSSLDH;

implementation
uses ssl_lib;

procedure SSL_InitSSLDH;
begin
	if @ECDH_OpenSSL = nil then
	begin
		@ECDH_OpenSSL:= LoadFunctionCLib('ECDH_OpenSSL');

		@ECDH_set_default_method:= LoadFunctionCLib('ECDH_set_default_method');
		@ECDH_get_default_method:= LoadFunctionCLib('ECDH_get_default_method');
		@ECDH_set_method:= LoadFunctionCLib('ECDH_set_method');
              
		@ECDH_compute_key:= LoadFunctionCLib('ECDH_compute_key');

		@ECDH_get_ex_new_index:= LoadFunctionCLib('ECDH_get_ex_new_index');
		@ECDH_set_ex_data:= LoadFunctionCLib('ECDH_set_ex_data');
		@ECDH_get_ex_data:= LoadFunctionCLib('ECDH_get_ex_data');

		@ERR_load_ECDH_strings:= LoadFunctionCLib('ERR_load_ECDH_strings');

	end;
end;

end.
