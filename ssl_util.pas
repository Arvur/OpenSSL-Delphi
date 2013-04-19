unit ssl_util;

interface
uses ssl_types, ssl_asn;
var
  CRYPTO_malloc : function(num: TC_INT; const _file: PAnsiChar; line: TC_INT): Pointer cdecl = nil;
  CRYPTO_realloc: function(addr: Pointer; num: TC_INT; _file: PAnsiChar; line: TC_INT): Pointer; cdecl = nil;
  CRYPTO_free : procedure(ptr : Pointer) cdecl = nil;
  CRYPTO_malloc_init: procedure; cdecl = nil;
  CRYPTO_set_mem_functions:function (_malloc: CRYPTO_mem_alloc_func; _realloc: CRYPTO_mem_realloc_func; _free: CRYPTO_mem_free_func): TC_INT; cdecl = nil;
  fCRYPTO_lock: procedure(_mode: TC_INT; _type: TC_INT; _file:  PAnsiChar; line: TC_INT); cdecl = nil;


  OPENSSL_gmtime: function(var timer: TC_time_t; var time: tm): tm; cdecl = nil;

function OpenSSL_malloc(iSize: TC_INT): Pointer;
procedure OpenSSL_free(ptr: Pointer);

function Asn1ToString(str: PASN1_STRING): String;
function StringToASN1(s: String; nid: Integer): PASN1_STRING;
function OBJ_ln2sn(ln: PAnsiChar): PAnsiChar;
function OBJ_sn2ln(ln: PAnsiChar): PAnsiChar;
function OBJ_obj2sn(a: PASN1_OBJECT): PAnsiChar;
function OBJ_obj2String(a: PASN1_OBJECT; no_name: Integer = 0): String;

procedure SSL_InitUtil;

function DateTimeToUnixTime(ADateTime: TDateTime): TC_time_t;
function UnixTimeToDateTime(const AUnixTime: TC_time_t): TDateTime;

function ASN1ToDateTime(a: PASN1_TIME): TDateTime;
function DateTimeToASN1(ADateTime: TDateTime): PASN1_TIME;

implementation
uses ssl_lib, ssl_const, Winapi.WinSock, SysUtils, ssl_err, ssl_objects, Math;

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
    @fCRYPTO_lock := LoadFunctionCLib('CRYPTO_lock');
    CRYPTO_set_mem_functions(_CR_alloc, _CR_realloc, _CR_free);

    @OPENSSL_gmtime := LoadFunctionCLib('OPENSSL_gmtime', False);
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
   ASN1_mbstring_copy(@Result, @_ins[1], -1, MBSTRING_UTF8, mask);
   SSL_CheckError;

end;

function OBJ_ln2sn(ln: PAnsiChar): PAnsiChar;
begin
  Result := OBJ_nid2sn(OBJ_ln2nid(ln))
end;

function OBJ_sn2ln(ln: PAnsiChar): PAnsiChar;
begin
  Result := OBJ_nid2ln(OBJ_sn2nid(ln))
end;

function OBJ_obj2sn(a: PASN1_OBJECT): PAnsiChar;
begin
 OBJ_obj2nid(a);
 SSL_CheckError;
 Result := OBJ_nid2sn(OBJ_obj2nid(a));
end;

function OBJ_obj2String(a: PASN1_OBJECT; no_name: Integer = 0): String;
var len: Integer;
    buf: PAnsiChar;
begin
  Len := OBJ_obj2txt(buf, 256, a, no_name);
  SSL_CheckError;
  Result := buf;
end;

function DateTimeToUnixTime(ADateTime: TDateTime): TC_time_t;
begin
  Result := Round((ADateTime - UnixDateDelta) * SecsPerDay);
end;

function UnixTimeToDateTime(const AUnixTime: TC_time_t): TDateTime;
begin
  Result:= UnixDateDelta + (AUnixTime / SecsPerDay);
end;

function GeneralizedTimeToDateTime(AGenTime: String): TDateTime;
var FS: TFormatSettings;
    y, m, d, h, mm, s: Word;
begin
  y := StrToInt(Copy(AGenTime, 1, 4));
  m := StrToInt(Copy(AGenTime, 5, 2));
  d := StrToInt(Copy(AGenTime, 7, 2));
  h := StrToInt(Copy(AGenTime, 9, 2));
  mm := StrToInt(Copy(AGenTime, 11, 2));
  s := StrToInt(Copy(AGenTime, 13, 2));
  Result := EncodeDate(y, m, d)+EncodeTime(h, mm, s, 0);
end;

function ASN1ToDateTime(a: PASN1_TIME): TDateTime;
var gt: PASN1_GENERALIZEDTIME;
begin
 gt := ASN1_TIME_to_generalizedtime(a, nil);
 Result := GeneralizedTimeToDateTime(gt.data);
end;


function DateTimeToASN1(ADateTime: TDateTime): PASN1_TIME;
begin
  Result := ASN1_TIME_new;
  ASN1_TIME_set(Result, DateTimeToUnixTime(ADateTime));
end;

end.


