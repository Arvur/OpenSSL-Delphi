unit ssl_cast;

interface
uses ssl_types;
var
 private_CAST_set_key: procedure(key: PCAST_KEY; len: TC_INT; data: PAnsiChar); cdecl = nil;
 CAST_set_key: procedure(key: PCAST_KEY; len: TC_INT; data: PAnsiChar); cdecl = nil;
 CAST_ecb_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; const key: PCAST_KEY; enc: TC_INT); cdecl = nil;
 CAST_encrypt: procedure(var data: CAST_LONG; key: PCAST_KEY); cdecl = nil;
 CAST_decrypt: procedure(var data: CAST_LONG; key: PCAST_KEY); cdecl = nil;
 CAST_cbc_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; ks: PCAST_KEY;iv: PAnsiChar; enc: TC_INT); cdecl = nil;
 CAST_cfb64_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; schedule: PCAST_KEY;ivec: PAnsiChar; var num: TC_INT; enc: TC_INT); cdecl = nil;
 CAST_ofb64_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar;	_length: TC_LONG; schedule: PCAST_KEY;ivec: PAnsiChar; var num: TC_INT); cdecl = nil;

procedure SLL_InitCAST;

implementation
uses ssl_lib;

procedure SLL_InitCAST;
begin
  if @CAST_set_key = nil then
  begin
     @private_CAST_set_key:= LoadFunctionCLib('private_CAST_set_key', false);
     @CAST_set_key:= LoadFunctionCLib('CAST_set_key');
     @CAST_ecb_encrypt:= LoadFunctionCLib('CAST_ecb_encrypt');
     @CAST_encrypt:= LoadFunctionCLib('CAST_encrypt');
     @CAST_decrypt:= LoadFunctionCLib('CAST_decrypt');
     @CAST_cbc_encrypt:= LoadFunctionCLib('CAST_cbc_encrypt');
     @CAST_cfb64_encrypt:= LoadFunctionCLib('CAST_cfb64_encrypt');
     @CAST_ofb64_encrypt:= LoadFunctionCLib('CAST_ofb64_encrypt');
  end;

end;

end.
