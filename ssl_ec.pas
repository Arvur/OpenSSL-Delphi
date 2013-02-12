{$R-}
unit ssl_ec;

interface
uses ssl_types;

var
  EC_Curves: PEC_builtin_curves = nil;
  EC_NumCurves: Integer = 0;

  EC_get_builtin_curves: function (r: PEC_builtin_curves; nItems: TC_INT): TC_INT; cdecl = nil;
  EC_GROUP_new_by_curve_name: function(nid: TC_INT): EC_GROUP; cdecl = nil;
  EC_KEY_new: function: PEC_KEY; cdecl = nil;
  EC_GROUP_free: procedure (group: EC_GROUP); cdecl = nil;
  EC_GROUP_set_asn1_flag: procedure(group: EC_GROUP; flag: TC_INT); cdecl = nil;
  EC_GROUP_get_curve_name: function(group: EC_GROUP): TC_INT; cdecl = nil;
  EC_KEY_set_group: function(key: PEC_KEY; group: EC_GROUP): TC_INT; cdecl = nil;
  EC_KEY_generate_key: function(key: PEC_KEY): TC_INT; cdecl = nil;
  EC_KEY_check_key: function(key: PEC_KEY): TC_INT; cdecl = nil;
  EC_KEY_free: procedure(key: PEC_KEY); cdecl = nil;

procedure EVP_PKEY_assign_EC_KEY(key: PEVP_PKEY; eckey: PEC_KEY); inline;

procedure SSL_InitEC;

implementation

uses ssl_util, ssl_lib, ssl_evp;


procedure LoadCurves;
var BufSize: Integer;
begin
  if EC_Curves <> nil then
  begin
   OpenSSL_free(EC_Curves);
   EC_Curves := nil;
   EC_NumCurves := 0;
  end;

  if @EC_get_builtin_curves <> nil then
  begin
    EC_NumCurves := EC_get_builtin_curves(nil, 0);
    BufSize := SizeOf(EC_builtin_curve) * EC_NumCurves;
    EC_Curves := OpenSSL_malloc(BufSize);
    EC_get_builtin_curves(EC_Curves, EC_NumCurves);
  end;
end;

procedure SSL_InitEC;
begin
 if SSLCryptHandle <> 0 then
   begin
    SSL_InitUtil;
    @EC_get_builtin_curves  :=LoadFunctionCLib('EC_get_builtin_curves');
    @EC_GROUP_new_by_curve_name := LoadFunctionCLib('EC_GROUP_new_by_curve_name');
    @EC_KEY_new := LoadFunctionCLib('EC_KEY_new');
    @EC_GROUP_free := LoadFunctionCLib('EC_GROUP_free');
    @EC_GROUP_set_asn1_flag := LoadFunctionCLib('EC_GROUP_set_asn1_flag');
    @EC_GROUP_get_curve_name := LoadFunctionCLib('EC_GROUP_get_curve_name');
    @EC_KEY_set_group := LoadFunctionCLib('EC_KEY_set_group');
    @EC_KEY_generate_key := LoadFunctionCLib('EC_KEY_generate_key');
    @EC_KEY_check_key := LoadFunctionCLib('EC_KEY_check_key');
    @EC_KEY_free := LoadFunctionCLib('EC_KEY_free');
    if @EC_get_builtin_curves <> nil then
      LoadCurves;
  end;
end;

procedure EVP_PKEY_assign_EC_KEY(key: PEVP_PKEY; eckey: PEC_KEY);
begin
  EVP_PKEY_assign(key, EVP_PKEY_EC, eckey);
end;

initialization
finalization
 if (EC_Curves <> nil) then
 begin
   OpenSSL_free(EC_Curves);
   EC_Curves := nil;
   EC_NumCurves := 0;
 end;
end.

