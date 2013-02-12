unit ssl_dsa;

interface
uses ssl_types;

type TDSACallback = procedure(p1, p2: TC_INT; p3: Pointer); cdecl;

var
  DSA_new: function: PDSA; cdecl = nil;
  DSA_new_method: function(engine: PENGINE): PDSA; cdecl = nil;
  DSA_size: function(dsa: Pointer): TC_INT; cdecl = nil;
  DSA_free: procedure(dsa: PDSA); cdecl = nil;
  DSA_generate_parameters: function(bits: TC_INT; seed: PByte; seed_len: TC_INT; counter_ret: PC_INT; h_ret: PC_ULONG; callback: TDSACallback; cb_agr: Pointer): PDSA; cdecl = nil;
  DSA_generate_parameters_ex: function(dsa: PDSA; bits: TC_INT; seed: PByte; seed_len: TC_INT; counter_ret: PC_INT; h_ret: PC_ULONG; cb: BN_GENCB): TC_INT; cdecl = nil;
  DSA_generate_key: function (a: PDSA): TC_INT; cdecl = nil;
  DSA_up_ref: function(dsa: PDSA): TC_INT; cdecl = nil;


procedure EVP_PKEY_assign_DSA(key: PEVP_PKEY; dsa: PDSA); inline;

implementation
uses ssl_lib, ssl_evp;

procedure EVP_PKEY_assign_DSA(key: PEVP_PKEY; dsa: PDSA); inline;
begin
  EVP_PKEY_assign(key, EVP_PKEY_DSA, dsa);
end;


procedure SSL_InitDSA;
begin
 if @DSA_new = nil then
  begin
    @DSA_new := LoadFunctionCLib('DSA_new');
    @DSA_new_method := LoadFunctionCLib('DSA_new_method');
    @DSA_size := LoadFunctionCLib('DSA_size');
    @DSA_generate_key := LoadFunctionCLib('DSA_generate_key');
    @DSA_generate_parameters := LoadFunctionCLib('DSA_generate_parameters');
    @DSA_generate_parameters_ex := LoadFunctionCLib('DSA_generate_parameters_ex');
    @DSA_free := LoadFunctionCLib('DSA_free');
    @DSA_up_ref := LoadFunctionCLib('DSA_up_ref');
  end;
end;


end.
