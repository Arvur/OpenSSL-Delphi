unit ssl_util;

interface
uses ssl_types;
var
  CRYPTO_malloc : function(num: TC_INT; const _file: PAnsiChar; line: TC_INT): Pointer cdecl = nil;
  CRYPTO_free : procedure(ptr : Pointer) cdecl = nil;

function OpenSSL_malloc(iSize: TC_INT): Pointer;
procedure OpenSSL_free(ptr: Pointer);

procedure SSL_InitUtil;

implementation
uses ssl_lib;

procedure SSL_InitUtil;
begin
 if @CRYPTO_malloc = nil then
  begin
    @CRYPTO_malloc := LoadFunctionCLib('CRYPTO_malloc');
    @CRYPTO_free := LoadFunctionCLib('CRYPTO_free');
  end;
end;


function OpenSSL_malloc(iSize: TC_INT): Pointer;
begin
  if @CRYPTO_malloc <> nil then
   Result := CRYPTO_malloc(iSize, '', 0)
  else
   Result := nil;
end;

procedure OpenSSL_free(ptr: Pointer);
begin
  if @CRYPTO_Free <> nil then
    CRYPTO_free(ptr);
end;

end.


