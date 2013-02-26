unit ssl_sk;

interface
uses ssl_types;
var
  sk_value: function (_stack: PSTACK_OF; _i: TC_INT): Pointer; cdecl = nil;


function sk_X509_NAME_ENTRY_value(_stack: PSTACK_OF_X509_NAME_ENTRY; i: Integer): PX509_NAME_ENTRY;

procedure SSL_initSk;

implementation
uses ssl_lib;

function sk_X509_NAME_ENTRY_value(_stack: PSTACK_OF_X509_NAME_ENTRY; i: Integer): PX509_NAME_ENTRY;
begin
  Result := sk_value(_stack, i);
end;

procedure SSL_initSk;
begin
  if @sk_value = nil then
   begin
     @sk_value := LoadFunctionCLib('sk_value');
   end;
end;

end.
