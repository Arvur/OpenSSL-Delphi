unit ssl_cmac;

interface
uses ssl_types;
var
  CMAC_CTX_new: function: PCMAC_CTX; cdecl = nil;
  CMAC_CTX_cleanup: procedure(ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_free: procedure(ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_get0_cipher_ctx: function(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl = nil;
  CMAC_CTX_copy: function(_out: PCMAC_CTX; _in: CMAC_CTX): TC_INT; cdecl = nil;
  CMAC_Init: function(ctx: PCMAC_CTX; key: Pointer; keylen: TC_SIZE_T; cipher: PEVP_CIPHER; impl: PENGINE): TC_INT; cdecl = nil;
  CMAC_Update: function(ctx: PCMAC_CTX; data: Pointer; dlen: TC_SIZE_T): TC_INT; cdecl = nil;
  CMAC_Final: function(ctx: PCMAC_CTX; _out: PAnsiChar; var poutlen: TC_SIZE_T): TC_INT; cdecl = nil;
  CMAC_resume: function(ctx: PCMAC_CTX): TC_INT; cdecl = nil;

procedure SSL_InitCMAC;

implementation
uses ssl_lib;

procedure SSL_InitCMAC;
begin

 if @CMAC_CTX_new = nil then
 begin
    @CMAC_CTX_new:= LoadFunctionCLib('CMAC_CTX_new');
    @CMAC_CTX_cleanup:= LoadFunctionCLib('CMAC_CTX_cleanup');
    @CMAC_CTX_free:= LoadFunctionCLib('CMAC_CTX_free');
    @CMAC_CTX_get0_cipher_ctx:= LoadFunctionCLib('CMAC_CTX_get0_cipher_ctx');
    @CMAC_CTX_copy:= LoadFunctionCLib('CMAC_CTX_copy');
    @CMAC_Init:= LoadFunctionCLib('CMAC_Init');
    @CMAC_Update:= LoadFunctionCLib('CMAC_Update');
    @CMAC_Final:= LoadFunctionCLib('CMAC_Final');
    @CMAC_resume:= LoadFunctionCLib('CMAC_resume');
 end;
end;
end.
