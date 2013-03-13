unit ssl_rc5;

interface
uses ssl_types;

var
	RC5_32_set_key: procedure(_key: PRC5_32_KEY; _len: TC_INT; const _data: PAnsiChar; _rounds: TC_INT); cdecl = nil;
	RC5_32_ecb_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _key: PRC5_32_KEY; _enc: TC_INT); cdecl = nil;
	RC5_32_encrypt: procedure(_data: PC_ULONG; _key: PRC5_32_KEY); cdecl = nil;
	RC5_32_decrypt: procedure(data: PC_ULONG; _key: PRC5_32_KEY); cdecl = nil;
	RC5_32_cbc_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _ks: PRC5_32_KEY; _iv: PAnsiChar; _enc: TC_INT); cdecl = nil;
	RC5_32_cfb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _schedule: PRC5_32_KEY; _ivec: PAnsiChar; var _num: TC_INT; _enc: TC_INT); cdecl = nil;
	RC5_32_ofb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _schedule: PRC5_32_KEY; _ivec: PAnsiChar; var _num: TC_INT); cdecl = nil;

procedure SSL_Initrc5;

implementation
uses ssl_lib;

procedure SSL_Initrc5;
begin
	if @RC5_32_encrypt = nil then
		begin
			@RC5_32_set_key:= LoadFunctionCLib('RC5_32_set_key', false);
			@RC5_32_ecb_encrypt:= LoadFunctionCLib('RC5_32_ecb_encrypt', false);
			@RC5_32_encrypt:= LoadFunctionCLib('RC5_32_encrypt', false);
			@RC5_32_decrypt:= LoadFunctionCLib('RC5_32_decrypt', false);
			@RC5_32_cbc_encrypt:= LoadFunctionCLib('RC5_32_cbc_encrypt', false);
			@RC5_32_cfb64_encrypt:= LoadFunctionCLib('RC5_32_cfb64_encrypt', false);
			@RC5_32_ofb64_encrypt:= LoadFunctionCLib('RC5_32_ofb64_encrypt', false);
		end;
end;

end.

