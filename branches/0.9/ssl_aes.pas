unit ssl_aes;

interface
uses ssl_types;

var
  AES_options: function: PAnsiChar; cdecl = nil;
  AES_set_encrypt_key: function(userKey: PAnsiChar; bits: TC_INT; key: PAES_KEY): TC_INT; cdecl = nil;
  AES_set_decrypt_key: function(userKey: PAnsiChar; bits: TC_INT; key: PAES_KEY): TC_INT; cdecl = nil;
  private_AES_set_encrypt_key: function(userKey: PAnsiChar; bits: TC_INT; key: PAES_KEY): TC_INT; cdecl = nil;
  private_AES_set_decrypt_key: function(userKey: PAnsiChar; bits: TC_INT; key: PAES_KEY): TC_INT; cdecl = nil;
  AES_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; key: PAES_KEY); cdecl = nil;
  AES_decrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; key: PAES_KEY); cdecl = nil;
  AES_ecb_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; key: PAES_KEY; enc: TC_INT); cdecl = nil;
  AES_cbc_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; enc: TC_INT); cdecl = nil;
  AES_cfb128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; num: PC_INT; enc: TC_INT); cdecl = nil;
  AES_cfb1_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; num: PC_INT; enc: TC_INT); cdecl = nil;
  AES_cfb8_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; num: PC_INT; enc: TC_INT); cdecl = nil;
  AES_ofb128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; num: PC_INT); cdecl = nil;
  AES_ctr128_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: aes_buf; ecount_buf: aes_buf; num: PC_INT); cdecl = nil;
  AES_ige_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; ivec: PAnsiChar; enc: TC_INT); cdecl = nil;
  AES_bi_ige_encrypt: procedure(_in: PAnsiChar; _out: PAnsiChar; _length: TC_SIZE_T; key: PAES_KEY; key2: PAES_KEY; ivec: PAnsiChar; enc: TC_INT); cdecl = nil;
  AES_wrap_key: function(key: PAES_KEY; iv: PAnsiChar; _out: PAnsiChar; _in: PAnsiChar; inlen: TC_UINT): TC_INT; cdecl = nil;
  AES_unwrap_key: function(key: PAES_KEY; iv: PAnsiChar; _out: PAnsiChar; _in: PAnsiChar; inlen: TC_UINT): TC_INT; cdecl = nil;

procedure SSL_InitAES;

implementation
uses ssl_lib;
procedure SSL_InitAES;
begin
 if @AES_options = nil then
  begin
        
      @AES_options:= LoadFunctionCLib('AES_options');
      @AES_set_encrypt_key:= LoadFunctionCLib('AES_set_encrypt_key');
      @AES_set_decrypt_key:= LoadFunctionCLib('AES_set_decrypt_key');
      @private_AES_set_encrypt_key:= LoadFunctionCLib('private_AES_set_encrypt_key');
      @private_AES_set_decrypt_key:= LoadFunctionCLib('private_AES_set_decrypt_key');
      @AES_encrypt:= LoadFunctionCLib('AES_encrypt');
      @AES_decrypt:= LoadFunctionCLib('AES_decrypt');
      @AES_ecb_encrypt:= LoadFunctionCLib('AES_ecb_encrypt');
      @AES_cbc_encrypt:= LoadFunctionCLib('AES_cbc_encrypt');
      @AES_cfb128_encrypt:= LoadFunctionCLib('AES_cfb128_encrypt');
      @AES_cfb1_encrypt:= LoadFunctionCLib('AES_cfb1_encrypt');
      @AES_cfb8_encrypt:= LoadFunctionCLib('AES_cfb8_encrypt');
      @AES_ofb128_encrypt:= LoadFunctionCLib('AES_ofb128_encrypt');
      @AES_ctr128_encrypt:= LoadFunctionCLib('AES_ctr128_encrypt');
      @AES_ige_encrypt:= LoadFunctionCLib('AES_ige_encrypt');
      @AES_bi_ige_encrypt:= LoadFunctionCLib('AES_bi_ige_encrypt');
      @AES_wrap_key:= LoadFunctionCLib('AES_wrap_key');
      @AES_unwrap_key:= LoadFunctionCLib('AES_unwrap_key');

  end;
end;

end.
