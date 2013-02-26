unit ssl_util;

interface
uses ssl_types, ssl_asn;
var
  CRYPTO_malloc : function(num: TC_INT; const _file: PAnsiChar; line: TC_INT): Pointer cdecl = nil;
  CRYPTO_realloc: function(addr: Pointer; num: TC_INT; _file: PAnsiChar; line: TC_INT): Pointer; cdecl = nil;
  CRYPTO_free : procedure(ptr : Pointer) cdecl = nil;
  CRYPTO_malloc_init: procedure; cdecl = nil;
  CRYPTO_set_mem_functions:function (_malloc: CRYPTO_mem_alloc_func; _realloc: CRYPTO_mem_realloc_func; _free: CRYPTO_mem_free_func): TC_INT; cdecl = nil;

function OpenSSL_malloc(iSize: TC_INT): Pointer;
procedure OpenSSL_free(ptr: Pointer);

function Asn1ToString(str: PASN1_STRING): String;
function StringToASN1(s: String; nid: Integer): PASN1_STRING;

procedure SSL_InitUtil;

implementation
uses ssl_lib, ssl_const, Winapi.WinSock, SysUtils, ssl_err;

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

function Asn1ToString(str: PASN1_STRING): String;
var
  P: PWideChar;
begin
  case Str._type of
   V_ASN1_BMPSTRING: begin
                        P := GetMemory(Str.length div 2);
                        UnicodeToUtf8(str.data, p, str.length div 2);
                        Result := P;
                        FreeMem(P);
                     end;
   V_ASN1_UTF8STRING: begin
                        Result := Str.data;
                      end;
   V_ASN1_T61STRING: begin
                        Result := Str.data;
                     end;
   else
     Result := Str.data;
  end;
end;

function StringToASN1(s: String; nid: Integer): PASN1_STRING;
var
  B: TBytes;
  gmask: TC_ULONG;
  mask: TC_ULONG;
  tbl: PASN1_STRING_TABLE;
  _in: PAnsiChar;
  _ins: AnsiString;
begin
  B := TEncoding.Convert(TEncoding.Default, TEncoding.UTF8, BytesOf(s));
  _ins := StringOf(B);

  gmask := ASN1_STRING_get_default_mask();
  mask := DIRSTRING_TYPE and gmask;
  Result := nil;
  tbl := ASN1_STRING_TABLE_get(nid);
  SSL_CheckError;
  if tbl <> nil then
   begin
     mask := tbl.mask;
     if (tbl.flags and STABLE_NO_MASK) = 0 then
      mask := mask and gmask;
   end;
   ASN1_mbstring_copy(Result, @_ins[1], -1, MBSTRING_UTF8, mask);
   SSL_CheckError;

end;


end.


