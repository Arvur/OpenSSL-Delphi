unit ssl_rsa;

interface
uses ssl_types;

type
  TRSACallback = procedure(p1, p2: TC_INT; p3: Pointer); cdecl;

var
  RSA_new: function: PRSA; cdecl = nil;
  RSA_new_method: function(pengine: PENGINE): PRSA; cdecl = nil;
  RSA_size: function(pval: Pointer): TC_INT; cdecl = nil;
  RSA_generate_key: function(bits: TC_INT; e: TC_ULONG; callback: TRSACallback; cb_arg: Pointer): PRSA; cdecl = nil;
  RSA_generate_key_ex: function(rsa: PRSA; bits: TC_INT; e: PBIGNUM; cb: PBN_GENCB): TC_INT; cdecl = nil;
  RSA_check_key: function(rsa: PRSA): TC_INT; cdecl = nil;
  RSA_public_encrypt: function(flen: TC_INT; from: PByte; _to: PByte; rsa: PRSA; padding: TC_INT): TC_INT cdecl = nil;
  RSA_private_encrypt: function(flen: TC_INT; from: PByte; _to: PByte; rsa: PRSA; padding: TC_INT): TC_INT cdecl = nil;
  RSA_public_decrypt: function(flen: TC_INT; from: PByte; _to: PByte; rsa: PRSA; padding: TC_INT): TC_INT cdecl = nil;
  RSA_private_decrypt: function(flen: TC_INT; from: PByte; _to: PByte; rsa: PRSA; padding: TC_INT): TC_INT cdecl = nil;
  RSA_free : procedure(rsa: PRSA) cdecl = nil;
  RSA_up_ref: function(rsa: PRSA): TC_INT; cdecl = nil;
  RSA_flags: function(rsa: PRSA): TC_INT; cdecl = nil;
  ERR_load_RSA_strings: procedure; cdecl = nil;

procedure EVP_PKEY_assign_RSA(key: PEVP_PKEY; rsa: PRSA); inline;

procedure SSL_InitRSA;

implementation

uses ssl_lib, ssl_evp, ssl_const;

procedure EVP_PKEY_assign_RSA(key: PEVP_PKEY; rsa: PRSA); inline;
begin
  EVP_PKEY_assign(key, EVP_PKEY_RSA, rsa);
end;

procedure SSL_InitRSA;
begin
 if @RSA_new = nil then
  begin
    @RSA_new := LoadFunctionCLib('RSA_new');
    @RSA_new_method := LoadFunctionCLib('RSA_new_method');
    @RSA_size := LoadFunctionCLib('RSA_size');
    @RSA_generate_key := LoadFunctionCLib('RSA_generate_key');
    @RSA_generate_key_ex := LoadFunctionCLib('RSA_generate_key_ex');
    @RSA_check_key := LoadFunctionCLib('RSA_check_key');
    @RSA_public_encrypt := LoadFunctionCLib('RSA_public_encrypt');
    @RSA_private_encrypt := LoadFunctionCLib('RSA_private_encrypt');
    @RSA_public_decrypt := LoadFunctionCLib('RSA_public_decrypt');
    @RSA_private_decrypt := LoadFunctionCLib('RSA_private_decrypt');
    @RSA_free := LoadFunctionCLib('RSA_free');
    @RSA_up_ref := LoadFunctionCLib('RSA_up_ref');
    @RSA_flags := LoadFunctionCLib('RSA_flags');
    @ERR_load_RSA_strings := LoadFunctionCLib('ERR_load_RSA_strings');
  end;
end;

end.
