unit ssl_lib;

interface

function SSLCryptHandle: THandle;
function LoadSSLCrypt: Boolean;
function LoadFunctionCLib(const FceName: String; const ACritical : Boolean = True): Pointer;

implementation
uses windows, sysutils;

const SSL_C_LIB = 'libeay32.dll';

var hCrypt: THandle = 0;

function SSLCryptHandle: THandle;
begin
  Result := hCrypt;
end;

function LoadSSLCrypt: Boolean;
begin
  hCrypt := LoadLibrary(SSL_C_LIB);
  Result := hCrypt <> 0;
end;


function LoadFunctionCLib(const FceName: String; const ACritical : Boolean = True): Pointer;
begin
  Result := Windows.GetProcAddress(SSLCryptHandle, PChar(FceName));
  if ACritical then
  begin
    if Result = nil then begin
     raise Exception.CreateFmt('Процедура %s не загружена.'#13#10'%s', [FceName, SysErrorMessage(GetLastError)]);
    end;
  end;
end;


initialization

finalization
 if hCrypt <> 0 then
  FreeLibrary(hCrypt);

end.
