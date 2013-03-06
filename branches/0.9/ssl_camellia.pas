unit ssl_camellia;
interface
uses ssl_types;
var
	Camellia_set_key: function (userKey: PAnsiChar; const bits: TC_INT; key: PCAMELLIA_KEY): TC_INT; cdecl = nil;

	Camellia_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; const key: PCAMELLIA_KEY); cdecl = nil;
	Camellia_decrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; const key: PCAMELLIA_KEY); cdecl = nil;

	Camellia_ecb_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; const key: PCAMELLIA_KEY; const enc: TC_INT); cdecl = nil;
	Camellia_cbc_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar;_length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: PAnsiChar; const enc: TC_INT); cdecl = nil;
	Camellia_cfb128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: PAnsiChar; var num: TC_INT; const enc: TC_INT); cdecl = nil;
	Camellia_cfb1_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar;_length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: PAnsiChar; var num: TC_INT; const enc: TC_INT); cdecl = nil;
	Camellia_cfb8_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: PAnsiChar; var num: TC_INT; const enc: TC_INT); cdecl = nil;
	Camellia_ofb128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: PAnsiChar; var num: TC_INT); cdecl = nil;
	Camellia_ctr128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; const key: PCAMELLIA_KEY; ivec: CAMELLIA_BUF; ecount_buf: CAMELLIA_BUF;	var num: TC_UINT); cdecl = nil;

procedure SSL_InitCAMELLIA;

implementation
uses ssl_lib;

procedure SSL_InitCAMELLIA;
begin
 if @Camellia_encrypt = nil then
  begin
	@Camellia_set_key:= LoadFunctionCLib('Camellia_set_key');
	@Camellia_encrypt:= LoadFunctionCLib('Camellia_encrypt');
	@Camellia_decrypt:= LoadFunctionCLib('Camellia_decrypt');
	@Camellia_ecb_encrypt:= LoadFunctionCLib('Camellia_ecb_encrypt');
	@Camellia_cbc_encrypt:= LoadFunctionCLib('Camellia_cbc_encrypt');
	@Camellia_cfb128_encrypt:= LoadFunctionCLib('Camellia_cfb128_encrypt');
	@Camellia_cfb1_encrypt:= LoadFunctionCLib('Camellia_cfb1_encrypt');
	@Camellia_cfb8_encrypt:= LoadFunctionCLib('Camellia_cfb8_encrypt');
	@Camellia_ofb128_encrypt:= LoadFunctionCLib('Camellia_ofb128_encrypt');
	@Camellia_ctr128_encrypt:= LoadFunctionCLib('Camellia_ctr128_encrypt');  
  end;
end;

end.