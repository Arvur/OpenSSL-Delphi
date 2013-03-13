unit ssl_ecdsa;

interface
uses ssl_types;

var
	ECDSA_SIG_new: function: PECDSA_SIG; cdecl = nil;

	ECDSA_SIG_free: procedure(_sig: PECDSA_SIG); cdecl = nil;

	i2d_ECDSA_SIG: function(const _sig: PECDSA_SIG; _pp: PPAnsiChar): TC_INT; cdecl = nil;
	d2i_ECDSA_SIG: function(_sig: PPECDSA_SIG; const _pp: PPAnsiChar; _len: TC_LONG): PECDSA_SIG; cdecl = nil;

	ECDSA_do_sign: function(const _dgst: PAnsiChar; _dgst_len: TC_INT; _eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;

	ECDSA_do_sign_ex: function(const _dgst: PAnsiChar; _dgstlen: TC_INT; const _kinv: PBIGNUM; const _rp: Pointer; _eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;

	ECDSA_do_verify: function(const _dgst: PAnsiChar; _dgst_len: TC_INT; const _sig: PECDSA_SIG; _eckey: PEC_KEY): TC_INT; cdecl = nil;

	ECDSA_OpenSSL: function: PECDSA_METHOD; cdecl = nil;

	ECDSA_set_default_method: procedure(const _meth: PECDSA_METHOD); cdecl = nil;

	ECDSA_get_default_method: function: PECDSA_METHOD; cdecl = nil;

	ECDSA_set_method: function(_eckey: PEC_KEY; const _meth: PECDSA_METHOD): TC_INT; cdecl = nil;

	ECDSA_size: function(const _eckey: PEC_KEY): TC_INT; cdecl = nil;

	ECDSA_sign_setup: function(_eckey: PEC_KEY; _ctx: PBN_CTX; _kinv: PPBIGNUM; _rp: PPBIGNUM): TC_INT; cdecl = nil;
	ECDSA_sign: function(_type: TC_INT; const _dgst: PAnsiChar; _dgstlen: TC_INT; _sig: PAnsiChar; var _siglen: TC_UINT; _eckey: PEC_KEY): TC_INT; cdecl = nil;

	ECDSA_sign_ex: function(_type: TC_INT; const _dgst: PAnsiChar; _dgstlen: TC_INT; _sig: PAnsiChar; var _siglen: TC_UINT; const _kinv: PBIGNUM;const _rp: PBIGNUM; _eckey: PEC_KEY): TC_INT; cdecl = nil;

	ECDSA_verify: function(_type: TC_INT; const _dgst: PAnsiChar; _dgstlen: TC_INT; const _sig: PAnsiChar; _siglen: TC_INT; _eckey: PEC_KEY): TC_INT; cdecl = nil;

	ECDSA_get_ex_new_index: function(_argl: TC_LONG; _argp: Pointer; _new_func: CRYPTO_EX_new; _dup_func: CRYPTO_EX_dup; _free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
	ECDSA_set_ex_data: function(_d: PEC_KEY; _idx: TC_INT; _arg: Pointer): TC_INT; cdecl = nil;
	ECDSA_get_ex_data: function(_d: PEC_KEY; _idx: TC_INT): Pointer; cdecl = nil;

	ERR_load_ECDSA_strings: procedure; cdecl = nil;

procedure SSL_InitECDSA;

implementation
uses ssl_lib;

procedure SSL_InitECDSA;
begin
	if @ECDSA_SIG_new = nil then
	begin      
		@ECDSA_SIG_new:= LoadFunctionCLib('ECDSA_SIG_new');
		@ECDSA_SIG_free:= LoadFunctionCLib('ECDSA_SIG_free');
		@i2d_ECDSA_SIG:= LoadFunctionCLib('i2d_ECDSA_SIG');
		@d2i_ECDSA_SIG:= LoadFunctionCLib('d2i_ECDSA_SIG');
		@ECDSA_do_sign:= LoadFunctionCLib('ECDSA_do_sign');
		@ECDSA_do_sign_ex:= LoadFunctionCLib('ECDSA_do_sign_ex');
		@ECDSA_do_verify:= LoadFunctionCLib('ECDSA_do_verify');
		@ECDSA_OpenSSL:= LoadFunctionCLib('ECDSA_OpenSSL');
		@ECDSA_set_default_method:= LoadFunctionCLib('ECDSA_set_default_method');
		@ECDSA_get_default_method:= LoadFunctionCLib('ECDSA_get_default_method');
		@ECDSA_set_method:= LoadFunctionCLib('ECDSA_set_method');
		@ECDSA_size:= LoadFunctionCLib('ECDSA_size');
		@ECDSA_sign_setup:= LoadFunctionCLib('ECDSA_sign_setup');
		@ECDSA_sign:= LoadFunctionCLib('ECDSA_sign');
		@ECDSA_sign_ex:= LoadFunctionCLib('ECDSA_sign_ex');
		@ECDSA_verify:= LoadFunctionCLib('ECDSA_verify');
		@ECDSA_get_ex_new_index:= LoadFunctionCLib('ECDSA_get_ex_new_index');
		@ECDSA_set_ex_data:= LoadFunctionCLib('ECDSA_set_ex_data');
		@ECDSA_get_ex_data:= LoadFunctionCLib('ECDSA_get_ex_data');
		@ERR_load_ECDSA_strings:= LoadFunctionCLib('ERR_load_ECDSA_strings');

	end;
end;

end.
