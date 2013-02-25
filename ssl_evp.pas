unit ssl_evp;

interface

uses ssl_types, ssl_const;

var
  EVP_PKEY_assign: function(pkey: PEVP_PKEY; itype: TC_INT;  Key: Pointer): TC_INT; cdecl = nil;
  EVP_PKEY_new: function: EVP_PKEY; cdecl = nil;
  EVP_PKEY_free: procedure(pkey: EVP_PKEY); cdecl = nil;

procedure SSL_InitEVP;

implementation

uses ssl_lib;

procedure SSL_InitEVP;
begin
  if @EVP_PKEY_assign = nil then
  begin
    @EVP_PKEY_new := LoadFunctionCLib('EVP_PKEY_new');
    @EVP_PKEY_free := LoadFunctionCLib('EVP_PKEY_free');
    @EVP_PKEY_assign := LoadFunctionCLib('EVP_PKEY_assign');
  end;
end;

end.
