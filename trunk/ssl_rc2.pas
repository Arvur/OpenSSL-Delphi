unit ssl_rc2;

interface
uses ssl_types;

var
	RC2_set_key: procedure(_key: PRC2_KEY; _len: TC_INT; const _data: PAnsiChar;_bits: TC_INT); cdecl = nil;
	RC2_ecb_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _key: PRC2_KEY; _enc: TC_INT); cdecl = nil;
	RC2_encrypt: procedure(_data: PC_ULONG;_key: PRC2_KEY); cdecl = nil;
	RC2_decrypt: procedure(_data: PC_ULONG;_key: PRC2_KEY); cdecl = nil;
	RC2_cbc_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _ks: PRC2_KEY; _iv: PAnsiChar; _enc: TC_INT); cdecl = nil;
	RC2_cfb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _schedule: PRC2_KEY; _ivec: PAnsiChar; var _num: TC_INT; _enc: TC_INT); cdecl = nil;
	RC2_ofb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _schedule: PRC2_KEY; _ivec: PAnsiChar; var _num: TC_INT); cdecl = nil;

procedure SSL_Initrc2;

implementation
uses ssl_lib;

procedure SSL_Initrc2;
begin
  if @RC2_encrypt = nil then
	  begin
		 @RC2_set_key:= LoadFunctionCLib('RC2_set_key');
		 @RC2_ecb_encrypt:= LoadFunctionCLib('RC2_ecb_encrypt');
		 @RC2_encrypt:= LoadFunctionCLib('RC2_encrypt');
		 @RC2_decrypt:= LoadFunctionCLib('RC2_decrypt');
		 @RC2_cbc_encrypt:= LoadFunctionCLib('RC2_cbc_encrypt');
		 @RC2_cfb64_encrypt:= LoadFunctionCLib('RC2_cfb64_encrypt');
		 @RC2_ofb64_encrypt:= LoadFunctionCLib('RC2_ofb64_encrypt');
    end;

end;

end.

