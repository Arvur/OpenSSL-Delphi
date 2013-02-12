unit ssl_evp;

interface

uses ssl_types, ssl_const;

const
  EVP_PKEY_NONE = NID_undef;
  EVP_PKEY_RSA = NID_rsaEncryption;
  EVP_PKEY_RSA2 = NID_rsa;
  EVP_PKEY_DSA = NID_dsa;
  EVP_PKEY_DSA1 = NID_dsa_2;
  EVP_PKEY_DSA2 = NID_dsaWithSHA;
  EVP_PKEY_DSA3 = NID_dsaWithSHA1;
  EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
  EVP_PKEY_DH = NID_dhKeyAgreement;
  EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;
  EVP_PKEY_HMAC = NID_hmac;
  EVP_PKEY_CMAC = NID_cmac;

  EVP_PKEY_MO_SIGN = $1;
  EVP_PKEY_MO_VERIFY = $2;
  EVP_PKEY_MO_ENCRYPT = $4;
  EVP_PKEY_MO_DECRYPT = $8;

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
