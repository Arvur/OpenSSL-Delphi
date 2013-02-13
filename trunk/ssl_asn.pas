unit ssl_asn;

interface
uses ssl_types;
var
  ASN1_dup : function (i2d : i2d_of_void; d2i : d2i_of_void; x : PAnsiChar) : Pointer cdecl = nil;
  ASN_ANY_it: function: ASN1_ITEM;

  ASN1_PCTX_new: function: PASN1_PCTX; cdecl = nil;

  ASN1_TYPE_get: function(a: PASN1_TYPE): TC_INT; cdecl = nil;
  ASN1_TYPE_set: procedure(a: PASN1_TYPE; _type: TC_INT; value: Pointer); cdecl = nil;
  ASN1_TYPE_set1: function(a: PASN1_TYPE; _type: TC_INT; value: Pointer): TC_INT; cdecl = nil;
  ASN1_TYPE_cmp: function (a: PASN1_TYPE; b: PASN1_TYPE): TC_INT; cdecl = nil;

  ASN1_OBJECT_new: function: PASN1_OBJECT; cdecl = nil;
  ASN1_OBJECT_free: procedure(a: PASN1_OBJECT); cdecl = nil;
  ASN1_OBJECT_create: function(nid: TC_INT; data: PAnsiChar; len: TC_INT;	sn: PAnsiChar; ln: PAnsiChar): ASN1_OBJECT; cdecl = nil;
  i2d_ASN1_OBJECT: function(a: PASN1_OBJECT; var pp: PAnsiChar): TC_INT; cdecl = nil;
  c2i_ASN1_OBJECT: function(var a: PASN1_OBJECT; var pp: PAnsiChar; _length: TC_LONG): PASN1_OBJECT; cdecl = nil;
  d2i_ASN1_OBJECT: function(var a: PASN1_OBJECT; var pp: PAnsiChar; _length: TC_LONG): PASN1_OBJECT; cdecl = nil;
  ASN1_OBJECT_it: function: ASN1_ITEM;

  ASN1_STRING_new: function: PASN1_STRING; cdecl = nil;
  ASN1_STRING_free : procedure(a: PASN1_STRING) cdecl = nil;
  ASN1_STRING_copy: function(dst: PASN1_STRING; str: PASN1_STRING): TC_INT; cdecl = nil;
  ASN1_STRING_dup: function(a: PASN1_STRING): PASN1_STRING; cdecl = nil;
  ASN1_STRING_type_new : function(_type: TC_INT): PASN1_STRING cdecl = nil;
  ASN1_STRING_cmp: function(a: PASN1_STRING; b: PASN1_STRING): TC_INT; cdecl = nil;
  ASN1_STRING_set: function(str: PASN1_STRING; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  ASN1_STRING_set0: procedure(str: PASN1_STRING; data: Pointer; len: TC_INT); cdecl = nil;
  ASN1_STRING_length: function(x: PASN1_STRING): TC_INT; cdecl = nil;
  ASN1_STRING_length_set: procedure(x: PASN1_STRING; n: TC_INT); cdecl = nil;
  ASN1_STRING_type: function (x: PASN1_STRING): TC_INT; cdecl = nil;
  ASN1_STRING_data: function(x: PASN1_STRING): PAnsiChar; cdecl = nil;
  ASN1_STRING_set_default_mask: procedure(mask: TC_ULONG); cdecl = nil;
  ASN1_STRING_set_default_mask_asc: function(p: PAnsiChar): TC_INT;cdecl = nil;
  ASN1_STRING_get_default_mask: function: TC_ULONG; cdecl = nil;
  ASN1_STRING_print_ex_fp: function(var fp: FILE; str: PASN1_STRING; flags: TC_ULONG): TC_INT; cdecl = nil;
  ASN1_STRING_print: function (bp: PBIO; v: PASN1_STRING): TC_INT; cdecl = nil;
  ASN1_STRING_print_ex: function(_out: PBIO; str: PASN1_STRING; flags: TC_ULONG): TC_INT; cdecl = nil;
  ASN1_STRING_set_by_NID: function(var _out: PASN1_STRING; _in: PAnsiChar; inlen: TC_INT; inform: TC_INT; nid: TC_INT): PASN1_STRING; cdecl = nil;
  ASN1_STRING_to_UTF8: function(var _out: PAnsiChar; _in: PASN1_STRING): TC_INT; cdecl = nil;

  ASN1_OCTET_STRING_NDEF_it: function: ASN1_ITEM; cdecl = nil;
  ASN1_OCTET_STRING_new: function: PASN1_OCTET_STRING;
  ASN1_OCTET_STRING_free : procedure(a: PASN1_OCTET_STRING) cdecl = nil;
  ASN1_OCTET_STRING_cmp: function(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TC_INT; cdecl = nil;
  ASN1_OCTET_STRING_dup: function(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = nil;
  ASN1_OCTET_STRING_set: function(str: PASN1_OCTET_STRING; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  ASN1_OCTET_STRING_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_BIT_STRING_new: function: PASN1_BIT_STRING; cdecl = nil;
  ASN1_BIT_STRING_free: procedure(a: PASN1_BIT_STRING); cdecl = nil;
  ASN1_BIT_STRING_dup: function(a: PASN1_BIT_STRING): PASN1_BIT_STRING; cdecl = nil;
  ASN1_BIT_STRING_cmp: function(a: PASN1_BIT_STRING; b: PASN1_BIT_STRING): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_set: function(str: PASN1_BIT_STRING; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_check: function (a: PASN1_BIT_STRING; flags: PAnsiChar; flags_len: TC_INT): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_get_bit: function(a: PASN1_BIT_STRING; n: TC_INT): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_name_print: function(_out: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indend: TC_INT): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_num_asc: function(name: PAnsiChar; tbl: PBIT_STRING_BITNAME): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_set_asc: function(bs: PASN1_BIT_STRING; name: PAnsiChar;value: TC_INT; tbl: PBIT_STRING_BITNAME): TC_INT; cdecl = nil;
  ASN1_BIT_STRING_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_BMPSTRING_new: function: PASN1_BMPSTRING; cdecl = nil;
  ASN1_BMPSTRING_free: procedure(a: PASN1_BMPSTRING); cdecl = nil;
  ASN1_BMPSTRING_it: function: ASN1_ITEM; cdecl = nil;

  i2d_ASN1_BOOLEAN: function(a: TC_INT; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_BOOLEAN: function(var a: TC_INT; var pp: PAnsiChar; _length: TC_LONG): TC_INT; cdecl = nil;
  ASN1_BOOLEAN_it: function: ASN1_ITEM;
  ASN1_FBOOLEAN_it: function: ASN1_ITEM;

  ASN1_ENUMERATED_new: function: PASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_free: procedure(a: PASN1_ENUMERATED); cdecl = nil;
  ASN1_ENUMERATED_it: function: ASN1_ITEM; cdecl = nil;
  ASN1_ENUMERATED_set: function(a: PASN1_ENUMERATED; v: TC_LONG): ASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_get: function(a: PASN1_ENUMERATED): TC_LONG; cdecl = nil;
  BN_to_ASN1_ENUMERATED: function (bn: PBIGNUM; ai: PASN1_ENUMERATED): ASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_to_BN: function(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = nil;


  ASN1_INTEGER_new: function: PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_free : procedure(a: PASN1_INTEGER) cdecl = nil;
  ASN1_INTEGER_dup: function(a: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_cmp: function(x: PASN1_INTEGER; y: PASN1_INTEGER): TC_INT; cdecl = nil;
  ASN1_INTEGER_set : function(a: PASN1_INTEGER; v: TC_LONG): TC_INT cdecl = nil;
  ASN1_INTEGER_get : function(a: PASN1_INTEGER) : TC_LONG cdecl = nil;
  ASN1_INTEGER_it: function: ASN1_ITEM; cdecl = nil;
  ASN1_INTEGER_to_BN: function (ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_to_ASN1_INTEGER: function(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  i2c_ASN1_INTEGER: function (a: PASN1_INTEGER; var pp: PAnsiChar): TC_INT; cdecl = nil;
  c2i_ASN1_INTEGER: function (var a: PASN1_INTEGER; var pp: PAnsiChar; _length: TC_LONG): PASN1_INTEGER; cdecl = nil;
  d2i_ASN1_UINTEGER: function (var a: PASN1_INTEGER; var pp: PAnsiChar; _length: TC_LONG): PASN1_INTEGER; cdecl = nil;

  ASN1_GENERALIZEDTIME_new: function: PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_free: procedure(a: PASN1_GENERALIZEDTIME); cdecl = nil;
  ASN1_GENERALIZEDTIME_it: function: ASN1_ITEM; cdecl = nil;
  ASN1_GENERALIZEDTIME_print: function(fp: PBIO; a: PASN1_GENERALIZEDTIME): TC_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_check: function(a: PASN1_GENERALIZEDTIME): TC_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_set: function(s: PASN1_GENERALIZEDTIME; t: TC_time_t): PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_adj: function(s: PASN1_GENERALIZEDTIME;t: TC_time_t; offset_day: TC_INT; offset_sec: TC_INT): ASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_set_string: function(s: PASN1_GENERALIZEDTIME; str: PAnsiChar): TC_INT; cdecl = nil;

  ASN1_GENERALSTRING_new: function: PASN1_GENERALSTRING; cdecl = nil;
  ASN1_GENERALSTRING_free: procedure(a: PASN1_GENERALSTRING); cdecl = nil;
  ASN1_GENERALSTRING_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_IA5STRING_new: function: PASN1_IA5STRING; cdecl = nil;
  ASN1_IA5STRING_free: procedure(a: PASN1_IA5STRING); cdecl = nil;
  ASN1_IA5STRING_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_NULL_new: function: PASN1_NULL; cdecl = nil;
  ASN1_NULL_free: procedure(a: PASN1_NULL); cdecl = nil;
  ASN1_NULL_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_PRINTABLESTRING_new: function: PASN1_PRINTABLESTRING; cdecl = nil;
  ASN1_PRINTABLESTRING_free: procedure(a: PASN1_PRINTABLESTRING); cdecl = nil;
  ASN1_PRINTABLESTRING_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_PRINTABLE_type: function(s: PAnsiChar; max: TC_INT): TC_INT; cdecl = nil;
  ASN1_PRINTABLE_new: function: PASN1_T61STRING; cdecl = nil;
  ASN1_PRINTABLE_free: procedure(a: PASN1_T61STRING); cdecl = nil;
  ASN1_PRINTABLE_it: function: ASN1_ITEM; cdecl = nil;

  ASN1_T61STRING_new: function: PASN1_T61STRING; cdecl = nil;
  ASN1_T61STRING_free: procedure(a: PASN1_T61STRING); cdecl = nil;
  ASN1_T61STRING_it: function: ASN1_ITEM; cdecl = nil;


function M_ASN1_STRING_length(x : PASN1_STRING): TC_INT;
procedure M_ASN1_STRING_length_set(x : PASN1_STRING; n : TC_INT);
function M_ASN1_STRING_type(x : PASN1_STRING) : TC_INT;
function M_ASN1_STRING_data(x : PASN1_STRING) : PAnsiChar;

implementation

function M_ASN1_STRING_length(x : PASN1_STRING): TC_INT; inline;
begin
  Result := x^.length;
end;

procedure M_ASN1_STRING_length_set(x : PASN1_STRING; n : TC_INT); inline;
begin
  x^.length := n;
end;

function M_ASN1_STRING_type(x : PASN1_STRING) : TC_INT; inline;
begin
  Result := x^._type;
end;

function M_ASN1_STRING_data(x : PASN1_STRING) : PAnsiChar; inline;
begin
  Result := x^.data;
end;


end.
