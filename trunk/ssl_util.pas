unit ssl_util;

interface
uses ssl_types;
var
  CRYPTO_malloc : function(num: TC_INT; const _file: PAnsiChar; line: TC_INT): Pointer cdecl = nil;
  CRYPTO_realloc: function(addr: Pointer; num: TC_INT; _file: PAnsiChar; line: TC_INT): Pointer; cdecl = nil;
  CRYPTO_free : procedure(ptr : Pointer) cdecl = nil;
  CRYPTO_malloc_init: procedure; cdecl = nil;
  CRYPTO_set_mem_functions:function (_malloc: CRYPTO_mem_alloc_func; _realloc: CRYPTO_mem_realloc_func; _free: CRYPTO_mem_free_func): TC_INT; cdecl = nil;

function OpenSSL_malloc(iSize: TC_INT): Pointer;
procedure OpenSSL_free(ptr: Pointer);

procedure SSL_InitUtil;

implementation
uses ssl_lib;

function _CR_alloc(_size: TC_SIZE_T): Pointer; cdecl;
begin
  Result := AllocMem(_size);
end;

function _CR_realloc(_mem: Pointer; _size: TC_SIZE_T): Pointer; cdecl;
begin
  Result := ReallocMemory(_mem, _size);
end;

procedure _CR_free(_mem: Pointer); cdecl;
begin
  FreeMem(_mem);
end;


procedure SSL_InitUtil;
begin
 if @CRYPTO_malloc = nil then
  begin
    @CRYPTO_malloc := LoadFunctionCLib('CRYPTO_malloc');
    @CRYPTO_free := LoadFunctionCLib('CRYPTO_free');
    @CRYPTO_realloc := LoadFunctionCLib('CRYPTO_realloc', false);
    @CRYPTO_set_mem_functions := LoadFunctionCLib('CRYPTO_set_mem_functions');
    CRYPTO_set_mem_functions(_CR_alloc, _CR_realloc, _CR_free);
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


