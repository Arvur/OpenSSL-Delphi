unit ssl_hmac;

interface
uses ssl_types;

var
	HMAC_CTX_init: procedure(_ctx: PHMAC_CTX); cdecl = nil;
	HMAC_CTX_cleanup: procedure(_ctx: PHMAC_CTX); cdecl = nil;

	HMAC_Init: function(_ctx: PHMAC_CTX; const _key: Pointer; _len: TC_INT;const _md: PEVP_MD): TC_INT; cdecl = nil;
	HMAC_Init_ex: function(_ctx: PHMAC_CTX; const _key: Pointer; _len: TC_INT;const _md: PEVP_MD; _impl: PENGINE): TC_INT; cdecl = nil;
	HMAC_Update: function(_ctx: PHMAC_CTX; const _data: PAnsiChar; _len: TC_SIZE_T): TC_INT; cdecl = nil;
	HMAC_Final: function(_ctx: PHMAC_CTX; _md: PAnsiChar; var _len: TC_UINT): TC_INT; cdecl = nil;
	HMAC: function(const _evp_md: PEVP_MD; const _key: Pointer; _key_len: TC_INT; const _d: PAnsiChar; _n: TC_SIZE_T; _md: PAnsiChar; var _md_len: TC_UINT): PAnsiChar; cdecl = nil;
	HMAC_CTX_copy: function(_dctx: PHMAC_CTX; _sctx: PHMAC_CTX): TC_INT; cdecl = nil;

	HMAC_CTX_set_flags: procedure(_ctx: PHMAC_CTX; _flags: TC_ULONG); cdecl = nil;

procedure SSL_InitHMAC;
implementation
uses ssl_lib;

procedure SSL_InitHMAC;
begin

	if @HMAC_CTX_init = nil then
	begin
		@HMAC_CTX_init:= LoadFunctionCLib('HMAC_CTX_init');
		@HMAC_CTX_cleanup:= LoadFunctionCLib('HMAC_CTX_cleanup');
		@HMAC_Init:= LoadFunctionCLib('HMAC_Init');
		@HMAC_Init_ex:= LoadFunctionCLib('HMAC_Init_ex');
		@HMAC_Update:= LoadFunctionCLib('HMAC_Update');
		@HMAC_Final:= LoadFunctionCLib('HMAC_Final');
		@HMAC:= LoadFunctionCLib('HMAC');
		@HMAC_CTX_copy:= LoadFunctionCLib('HMAC_CTX_copy');
		@HMAC_CTX_set_flags:= LoadFunctionCLib('HMAC_CTX_set_flags');
	end;

end;

end.
