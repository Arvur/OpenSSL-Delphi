unit ssl_rc4;

interface
uses ssl_types;

var
	RC4_options: function: PAnsiChar; cdecl = nil;
	RC4_set_key: procedure(_key: PRC4_KEY; _len: TC_INT; const _data: PAnsiChar); cdecl = nil;
	private_RC4_set_key: procedure(_key: PRC4_KEY; _len: TC_INT; const _data: PAnsiChar); cdecl = nil;
	RC4: procedure(_key: PRC4_KEY; _len: TC_SIZE_T; const _indata: PAnsiChar; _outdata: PAnsiChar); cdecl = nil;

procedure SSL_Initrc4;

implementation
uses ssl_lib;

procedure SSL_Initrc4;
begin
	if @RC4_options = nil then
		begin
			@RC4_options:= LoadFunctionCLib('RC4_options');
			@RC4_set_key:= LoadFunctionCLib('RC4_set_key');
			@private_RC4_set_key:= LoadFunctionCLib('private_RC4_set_key');
			@RC4:= LoadFunctionCLib('RC4');
		end;

end;

end.

