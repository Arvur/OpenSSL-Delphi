unit ssl_sk;

interface
uses ssl_types;
var
  sk_value: function (_stack: PSTACK_OF; _i: TC_INT): Pointer; cdecl = nil;
  sk_new_null: function: PSTACK_OF; cdecl = nil;
  sk_push: function(st: PSTACK_OF; data: Pointer): TC_INT; cdecl = nil;
  sk_pop_free: procedure(st: PSTACK_OF; func: SK_POP_FREE_PROC); cdecl = nil;
  sk_free: procedure(_stack: PSTACK_OF); cdecl = nil;

function sk_X509_NAME_ENTRY_value(_stack: PSTACK_OF_X509_NAME_ENTRY; i: Integer): PX509_NAME_ENTRY;
function sk_X509_EXTENSION_new_null: PSTACK_OF_X509_EXTENSION;
function sk_X509_EXTENSION_push(_stak: PSTACK_OF_X509_EXTENSION; data: Pointer): TC_INT;
procedure sk_X509_EXTENSION_pop_free(st: PSTACK_OF_X509_EXTENSION; func: SK_POP_FREE_PROC);
procedure sk_X509_EXTENSION_free(st: PSTACK_OF_X509_EXTENSION);

function sk_X509_new_null: PSTACK_OF_X509;
function sk_X509_push(_stak: PSTACK_OF_X509; data: Pointer): TC_INT;
procedure SSL_initSk;

implementation
uses ssl_lib;

function sk_X509_NAME_ENTRY_value(_stack: PSTACK_OF_X509_NAME_ENTRY; i: Integer): PX509_NAME_ENTRY;
begin
  Result := sk_value(_stack, i);
end;

function sk_X509_EXTENSION_new_null: PSTACK_OF_X509_EXTENSION;
begin
  Result := sk_new_null;
end;

function sk_X509_new_null: PSTACK_OF_X509;
begin
  Result := sk_new_null;
end;

function sk_X509_EXTENSION_push(_stak: PSTACK_OF_X509_EXTENSION; data: Pointer): TC_INT;
begin
  Result := sk_push(_stak, data);
end;

function sk_X509_push(_stak: PSTACK_OF_X509; data: Pointer): TC_INT;
begin
  Result := sk_push(_stak, data);
end;

procedure sk_X509_EXTENSION_pop_free(st: PSTACK_OF_X509_EXTENSION; func: SK_POP_FREE_PROC);
begin
  sk_pop_free(st, func);
end;

procedure sk_X509_EXTENSION_free(st: PSTACK_OF_X509_EXTENSION);
begin
  sk_free(st);
end;

procedure SSL_initSk;
begin
  if @sk_value = nil then
   begin
     @sk_value := LoadFunctionCLib('sk_value');
     @sk_new_null := LoadFunctionCLib('sk_new_null');
     @sk_push := LoadFunctionCLib('sk_push');
     @sk_pop_free := LoadFunctionCLib('sk_pop_free');
     @sk_free := LoadFunctionCLib('sk_free');
   end;
end;

end.
