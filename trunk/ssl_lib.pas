unit ssl_lib;

interface

var
{$IFDEF UNIX}
  SSL_C_LIB : AnsiString = 'libeay32.so';
{$ELSE}
  SSL_C_LIB : AnsiString = 'libeay32.dll';
{$ENDIF}


function SSLCryptHandle: THandle;
function LoadSSLCrypt: Boolean;
function LoadFunctionCLib(const FceName: String; const ACritical : Boolean = True): Pointer;

implementation
uses {$IFDEF UNIX}dynlibs{$ELSE}windows{$ENDIF}, sysutils;


var hCrypt: THandle = 0;

function SSLCryptHandle: THandle;
begin
  Result := hCrypt;
end;

function LoadSSLCrypt: Boolean;
begin
{$IFDEF UNIX}
  hCrypt := LoadLibrary(SSL_C_LIB);
{$ELSE}
  hCrypt := LoadLibraryA(PAnsiChar(SSL_C_LIB));
{$ENDIF}
  Result := hCrypt <> 0;
end;


function LoadFunctionCLib(const FceName: String; const ACritical : Boolean = True): Pointer;
begin
 if SSLCryptHandle = 0 then
  LoadSSLCrypt;
  {$IFDEF UNIX}
   Result := GetProcAddress(SSLCryptHandle, PChar(FceName));
  {$ELSE}
  Result := Windows.GetProcAddress(SSLCryptHandle, PChar(FceName));
  {$ENDIF}
  if ACritical then
  begin
    if Result = nil then begin
{$ifdef fpc}
     raise Exception.CreateFmt('Error loading library. Func %s'#13#10'%s', [FceName, SysErrorMessage(GetLastOSError)]);
{$else}
     raise Exception.CreateFmt('Error loading library. Func %s'#13#10'%s', [FceName, SysErrorMessage(GetLastError)]);
{$endif}
    end;
  end;
end;


initialization

finalization
 if hCrypt <> 0 then
  FreeLibrary(hCrypt);

end.