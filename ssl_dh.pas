unit ssl_dh;

interface
uses ssl_types;
var
  d2i_DHparams_fp: function(var fp: FILE; var x: PAnsiChar): PDH; cdecl = nil;
  i2d_DHparams_fp: procedure(var fp: FILE; x: PAnsiChar); cdecl = nil;

  d2i_DHparams_bio: function(bp: PBIO; var x: PAnsiChar): PDH; cdecl = nil;
  i2d_DHparams_bio: procedure(bp: PBIO; x: PAnsiChar); cdecl = nil;

  DHparams_dup: function(_dh: PDH): PDH; cdecl = nil;
  DH_OpenSSL: function: PDH_METHOD; cdecl = nil;

  DH_set_default_method: procedure(const meth: PDH_METHOD); cdecl = nil;
  DH_get_default_method: function: PDH_METHOD; cdecl = nil;
  DH_set_method: function(_dh: PDH; const meth: PDH_METHOD): TC_INT; cdecl = nil;
  DH_new_method: function(_engine: PENGINE): PDH; cdecl = nil;

  DH_new: function: PDH; cdecl = nil;
  DH_free: procedure(_dh: PDH); cdecl = nil;
  DH_up_ref: function(_dh: PDH): TC_INT; cdecl = nil;
  DH_size: function(const _dh: PDH): TC_INT; cdecl = nil;

  DH_get_ex_new_index: function(argl: TC_LONG; argp: Pointer; new_func: CRYPTO_EX_new; dup_func: CRYPTO_EX_dup; free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
  DH_set_ex_data: function(d: PDH; idx: TC_INT; arg: Pointer): TC_INT; cdecl = nil;
  DH_get_ex_data: function(d: PDH; idx: TC_INT): Pointer; cdecl = nil;

  DH_generate_parameters: function(prime_len: TC_INT;generator: TC_INT; callback: DH_Callback; cb_arg: Pointer): PDH; cdecl = nil;

  DH_generate_parameters_ex: function(_dh: PDH; prime_len: TC_INT;generator: TC_INT; cb: PBN_GENCB): TC_INT; cdecl = nil;

  DH_check: function(const _dh: PDH;var codes: TC_INT): TC_INT; cdecl = nil;
  DH_check_pub_key: function(const _dh: PDH;const pub_key: PBIGNUM; var codes: TC_INT): TC_INT; cdecl = nil;
  DH_generate_key: function(_dh: PDH): TC_INT; cdecl = nil;
  DH_compute_key: function(key: PAnsiChar;const pub_key: PBIGNUM;_dh: PDH): TC_INT; cdecl = nil;
  d2i_DHparams: function(var a: PDH; var pp: PAnsiChar; _length: TC_LONG): PDH;
  i2d_DHparams: function(const a: PDH;var pp: PAnsiChar): TC_INT; cdecl = nil;
  DHparams_print_fp: function(var fp: FILE; x: PDH): TC_INT; cdecl = nil;
  DHparams_print: function(bp: BIO; x: PDH): TC_INT; cdecl = nil;
  ERR_load_DH_strings: procedure; cdecl = nil;

procedure SSL_InitDH;

procedure EVP_PKEY_assign_DH(key: PEVP_PKEY; _dh: PDH); inline;

implementation
uses ssl_lib, ssl_evp, ssl_const;

procedure EVP_PKEY_assign_DH(key: PEVP_PKEY; _dh: PDH); inline;
begin
  EVP_PKEY_assign(key, EVP_PKEY_DH, _dh);
end;


procedure SSL_InitDH;
begin
 if @DH_new = nil then
  begin
    @d2i_DHparams_fp:= LoadFunctionCLib('d2i_DHparams_fp', false);
    @i2d_DHparams_fp:= LoadFunctionCLib('i2d_DHparams_fp', false);
    @d2i_DHparams_bio:= LoadFunctionCLib('d2i_DHparams_bio', false);
    @i2d_DHparams_bio:= LoadFunctionCLib('i2d_DHparams_bio', false);
    @DHparams_dup:= LoadFunctionCLib('DHparams_dup');
    @DH_OpenSSL:= LoadFunctionCLib('DH_OpenSSL');
    @DH_set_default_method:= LoadFunctionCLib('DH_set_default_method');
    @DH_get_default_method:= LoadFunctionCLib('DH_get_default_method');
    @DH_set_method:= LoadFunctionCLib('DH_set_method');
    @DH_new_method:= LoadFunctionCLib('DH_new_method');
    @DH_new:= LoadFunctionCLib('DH_new');
    @DH_free:= LoadFunctionCLib('DH_free');
    @DH_up_ref:= LoadFunctionCLib('DH_up_ref');
    @DH_size:= LoadFunctionCLib('DH_size');
    @DH_get_ex_new_index:= LoadFunctionCLib('DH_get_ex_new_index');
    @DH_set_ex_data:= LoadFunctionCLib('DH_set_ex_data');
    @DH_get_ex_data:= LoadFunctionCLib('DH_get_ex_data');
    @DH_generate_parameters:= LoadFunctionCLib('DH_generate_parameters');
    @DH_generate_parameters_ex:= LoadFunctionCLib('DH_generate_parameters_ex');
    @DH_check:= LoadFunctionCLib('DH_check');
    @DH_check_pub_key:= LoadFunctionCLib('DH_check_pub_key');
    @DH_generate_key:= LoadFunctionCLib('DH_generate_key');
    @DH_compute_key:= LoadFunctionCLib('DH_compute_key');
    @d2i_DHparams:= LoadFunctionCLib('d2i_DHparams');
    @i2d_DHparams:= LoadFunctionCLib('i2d_DHparams');
    @DHparams_print_fp:= LoadFunctionCLib('DHparams_print_fp');
    @DHparams_print:= LoadFunctionCLib('DHparams_print');
    @ERR_load_DH_strings := LoadFunctionCLib('ERR_load_DH_strings');
  end;
end;

end.
