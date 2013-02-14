unit ssl_asn;

interface
uses ssl_types;
var
  ASN1_dup : function (i2d : i2d_of_void; d2i : d2i_of_void; x : PAnsiChar) : Pointer cdecl = nil;
  ASN_ANY_it: function: PASN1_ITEM;

  ASN1_PCTX_new: function: PASN1_CTX; cdecl = nil;

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
  ASN1_OBJECT_it: function: PASN1_ITEM;

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

  ASN1_OCTET_STRING_NDEF_it: function: PASN1_ITEM; cdecl = nil;
  ASN1_OCTET_STRING_new: function: PASN1_OCTET_STRING;
  ASN1_OCTET_STRING_free : procedure(a: PASN1_OCTET_STRING) cdecl = nil;
  ASN1_OCTET_STRING_cmp: function(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TC_INT; cdecl = nil;
  ASN1_OCTET_STRING_dup: function(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = nil;
  ASN1_OCTET_STRING_set: function(str: PASN1_OCTET_STRING; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  ASN1_OCTET_STRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_OCTET_STRING: function(a: PASN1_OCTET_STRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_OCTET_STRING: function(var a: PASN1_OCTET_STRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_OCTET_STRING; cdecl = nil;

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
  ASN1_BIT_STRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_BIT_STRING: function(a: PASN1_BIT_STRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_BIT_STRING: function(var a: PASN1_BIT_STRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_BIT_STRING; cdecl = nil;

  ASN1_BMPSTRING_new: function: PASN1_BMPSTRING; cdecl = nil;
  ASN1_BMPSTRING_free: procedure(a: PASN1_BMPSTRING); cdecl = nil;
  ASN1_BMPSTRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_BMPSTRING: function(a: PASN1_BMPSTRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_BMPSTRING: function(var a: PASN1_BMPSTRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_BMPSTRING; cdecl = nil;

  i2d_ASN1_BOOLEAN: function(a: TC_INT; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_BOOLEAN: function(var a: TC_INT; var pp: PAnsiChar; _length: TC_LONG): TC_INT; cdecl = nil;
  ASN1_BOOLEAN_it: function: PASN1_ITEM;
  ASN1_FBOOLEAN_it: function: PASN1_ITEM;


  ASN1_ENUMERATED_new: function: PASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_free: procedure(a: PASN1_ENUMERATED); cdecl = nil;
  ASN1_ENUMERATED_it: function: PASN1_ITEM; cdecl = nil;
  ASN1_ENUMERATED_set: function(a: PASN1_ENUMERATED; v: TC_LONG): ASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_get: function(a: PASN1_ENUMERATED): TC_LONG; cdecl = nil;
  BN_to_ASN1_ENUMERATED: function (bn: PBIGNUM; ai: PASN1_ENUMERATED): ASN1_ENUMERATED; cdecl = nil;
  ASN1_ENUMERATED_to_BN: function(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  i2d_ASN1_ENUMERATED: function(a: PASN1_ENUMERATED; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_ENUMERATED: function(var a: PASN1_ENUMERATED; var pp: PAnsiChar; _length: TC_LONG): PASN1_ENUMERATED; cdecl = nil;

  ASN1_INTEGER_new: function: PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_free : procedure(a: PASN1_INTEGER) cdecl = nil;
  ASN1_INTEGER_dup: function(a: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  ASN1_INTEGER_cmp: function(x: PASN1_INTEGER; y: PASN1_INTEGER): TC_INT; cdecl = nil;
  ASN1_INTEGER_set : function(a: PASN1_INTEGER; v: TC_LONG): TC_INT cdecl = nil;
  ASN1_INTEGER_get : function(a: PASN1_INTEGER) : TC_LONG cdecl = nil;
  ASN1_INTEGER_it: function: PASN1_ITEM; cdecl = nil;
  ASN1_INTEGER_to_BN: function (ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_to_ASN1_INTEGER: function(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  i2c_ASN1_INTEGER: function (a: PASN1_INTEGER; var pp: PAnsiChar): TC_INT; cdecl = nil;
  c2i_ASN1_INTEGER: function (var a: PASN1_INTEGER; var pp: PAnsiChar; _length: TC_LONG): PASN1_INTEGER; cdecl = nil;
  d2i_ASN1_UINTEGER: function (var a: PASN1_INTEGER; var pp: PAnsiChar; _length: TC_LONG): PASN1_INTEGER; cdecl = nil;

  ASN1_GENERALIZEDTIME_new: function: PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_free: procedure(a: PASN1_GENERALIZEDTIME); cdecl = nil;
  ASN1_GENERALIZEDTIME_it: function: PASN1_ITEM; cdecl = nil;
  ASN1_GENERALIZEDTIME_print: function(fp: PBIO; a: PASN1_GENERALIZEDTIME): TC_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_check: function(a: PASN1_GENERALIZEDTIME): TC_INT; cdecl = nil;
  ASN1_GENERALIZEDTIME_set: function(s: PASN1_GENERALIZEDTIME; t: TC_time_t): PASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_adj: function(s: PASN1_GENERALIZEDTIME;t: TC_time_t; offset_day: TC_INT; offset_sec: TC_INT): ASN1_GENERALIZEDTIME; cdecl = nil;
  ASN1_GENERALIZEDTIME_set_string: function(s: PASN1_GENERALIZEDTIME; str: PAnsiChar): TC_INT; cdecl = nil;
  i2d_ASN1_GENERALIZEDTIME: function(a: PASN1_GENERALIZEDTIME; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_GENERALIZEDTIME: function(var a: PASN1_GENERALIZEDTIME; var pp: PAnsiChar; _length: TC_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;

  ASN1_GENERALSTRING_new: function: PASN1_GENERALSTRING; cdecl = nil;
  ASN1_GENERALSTRING_free: procedure(a: PASN1_GENERALSTRING); cdecl = nil;
  ASN1_GENERALSTRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_GENERALSTRING: function(a: PASN1_GENERALSTRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_GENERALSTRING: function(var a: PASN1_GENERALSTRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_GENERALSTRING; cdecl = nil;

  ASN1_IA5STRING_new: function: PASN1_IA5STRING; cdecl = nil;
  ASN1_IA5STRING_free: procedure(a: PASN1_IA5STRING); cdecl = nil;
  ASN1_IA5STRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_IA5STRING: function(a: PASN1_IA5STRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_IA5STRING: function(var a: PASN1_IA5STRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_IA5STRING; cdecl = nil;

  ASN1_NULL_new: function: PASN1_NULL; cdecl = nil;
  ASN1_NULL_free: procedure(a: PASN1_NULL); cdecl = nil;
  ASN1_NULL_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_NULL: function(a: PASN1_NULL; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_NULL: function(var a: PASN1_NULL; var pp: PAnsiChar; _length: TC_LONG): PASN1_NULL; cdecl = nil;

  ASN1_PRINTABLESTRING_new: function: PASN1_PRINTABLESTRING; cdecl = nil;
  ASN1_PRINTABLESTRING_free: procedure(a: PASN1_PRINTABLESTRING); cdecl = nil;
  ASN1_PRINTABLESTRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_PRINTABLESTRING: function(a: PASN1_PRINTABLESTRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_PRINTABLESTRING: function(var a: PASN1_PRINTABLESTRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_PRINTABLESTRING; cdecl = nil;

  ASN1_PRINTABLE_type: function(s: PAnsiChar; max: TC_INT): TC_INT; cdecl = nil;
  ASN1_PRINTABLE_new: function: PASN1_T61STRING; cdecl = nil;
  ASN1_PRINTABLE_free: procedure(a: PASN1_T61STRING); cdecl = nil;
  ASN1_PRINTABLE_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_PRINTABLE: function(a: PASN1_T61STRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_PRINTABLE: function(var a: PASN1_T61STRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_T61STRING; cdecl = nil;

  ASN1_T61STRING_new: function: PASN1_T61STRING; cdecl = nil;
  ASN1_T61STRING_free: procedure(a: PASN1_T61STRING); cdecl = nil;
  ASN1_T61STRING_it: function: PASN1_ITEM; cdecl = nil;
  i2d_ASN1_T61STRING: function(a: PASN1_T61STRING; var pp: PAnsiChar): TC_INT; cdecl = nil;
  d2i_ASN1_T61STRING: function(var a: PASN1_T61STRING; var pp: PAnsiChar; _length: TC_LONG): PASN1_T61STRING; cdecl = nil;

function M_ASN1_STRING_length(x : PASN1_STRING): TC_INT;
procedure M_ASN1_STRING_length_set(x : PASN1_STRING; n : TC_INT);
function M_ASN1_STRING_type(x : PASN1_STRING) : TC_INT;
function M_ASN1_STRING_data(x : PASN1_STRING) : PAnsiChar;


procedure SSL_InitASN1;

implementation
uses ssl_lib;



procedure SSL_InitASN1;
begin
  if @ASN1_STRING_new = nil then
  begin
      @ASN1_dup := LoadFunctionCLib('ASN1_dup');
      @ASN_ANY_it := LoadFunctionCLib('ASN_ANY_it', false);

      @ASN1_PCTX_new := LoadFunctionCLib('ASN1_PCTX_new');

      @ASN1_TYPE_get := LoadFunctionCLib('ASN1_TYPE_get');
      @ASN1_TYPE_set:= LoadFunctionCLib('ASN1_TYPE_set');
      @ASN1_TYPE_set1 := LoadFunctionCLib('ASN1_TYPE_set1');
      @ASN1_TYPE_cmp:= LoadFunctionCLib('ASN1_TYPE_cmp');

      @ASN1_OBJECT_new:= LoadFunctionCLib('ASN1_OBJECT_new');
      @ASN1_OBJECT_free:= LoadFunctionCLib('ASN1_OBJECT_free');
      @ASN1_OBJECT_create:= LoadFunctionCLib('ASN1_OBJECT_create');
      @i2d_ASN1_OBJECT:= LoadFunctionCLib('i2d_ASN1_OBJECT');
      @c2i_ASN1_OBJECT:= LoadFunctionCLib('c2i_ASN1_OBJECT');
      @d2i_ASN1_OBJECT:= LoadFunctionCLib('d2i_ASN1_OBJECT');
      @ASN1_OBJECT_it:= LoadFunctionCLib('ASN1_OBJECT_it');

      @ASN1_STRING_new:= LoadFunctionCLib('ASN1_STRING_new');
      @ASN1_STRING_free:= LoadFunctionCLib('ASN1_STRING_free');
      @ASN1_STRING_copy:= LoadFunctionCLib('ASN1_STRING_copy');
      @ASN1_STRING_dup:= LoadFunctionCLib('ASN1_STRING_dup');
      @ASN1_STRING_type_new:= LoadFunctionCLib('ASN1_STRING_type_new');
      @ASN1_STRING_cmp:= LoadFunctionCLib('ASN1_STRING_cmp');
      @ASN1_STRING_set:= LoadFunctionCLib('ASN1_STRING_set');
      @ASN1_STRING_set0:= LoadFunctionCLib('ASN1_STRING_set0');
      @ASN1_STRING_length:= LoadFunctionCLib('ASN1_STRING_length');
      @ASN1_STRING_length_set:= LoadFunctionCLib('ASN1_STRING_length_set');
      @ASN1_STRING_type:= LoadFunctionCLib('ASN1_STRING_type');
      @ASN1_STRING_data:= LoadFunctionCLib('ASN1_STRING_data');
      @ASN1_STRING_set_default_mask:= LoadFunctionCLib('ASN1_STRING_set_default_mask');
      @ASN1_STRING_set_default_mask_asc:= LoadFunctionCLib('ASN1_STRING_set_default_mask_asc');
      @ASN1_STRING_get_default_mask:= LoadFunctionCLib('ASN1_STRING_get_default_mask');
      @ASN1_STRING_print_ex_fp:= LoadFunctionCLib('ASN1_STRING_print_ex_fp');
      @ASN1_STRING_print:= LoadFunctionCLib('ASN1_STRING_print');
      @ASN1_STRING_print_ex:= LoadFunctionCLib('ASN1_STRING_print_ex');
      @ASN1_STRING_set_by_NID:= LoadFunctionCLib('ASN1_STRING_set_by_NID');
      @ASN1_STRING_to_UTF8:= LoadFunctionCLib('ASN1_STRING_to_UTF8');

      @ASN1_OCTET_STRING_NDEF_it:= LoadFunctionCLib('ASN1_OCTET_STRING_NDEF_it');
      @ASN1_OCTET_STRING_new:= LoadFunctionCLib('ASN1_OCTET_STRING_new');
      @ASN1_OCTET_STRING_free:= LoadFunctionCLib('ASN1_OCTET_STRING_free');
      @ASN1_OCTET_STRING_cmp:= LoadFunctionCLib('ASN1_OCTET_STRING_cmp');
      @ASN1_OCTET_STRING_dup:= LoadFunctionCLib('ASN1_OCTET_STRING_dup');
      @ASN1_OCTET_STRING_set:= LoadFunctionCLib('ASN1_OCTET_STRING_set');
      @ASN1_OCTET_STRING_it:= LoadFunctionCLib('ASN1_OCTET_STRING_it');
      @i2d_ASN1_OCTET_STRING:= LoadFunctionCLib('i2d_ASN1_OCTET_STRING');
      @d2i_ASN1_OCTET_STRING:= LoadFunctionCLib('d2i_ASN1_OCTET_STRING');

      @ASN1_BIT_STRING_new:= LoadFunctionCLib('ASN1_BIT_STRING_new');
      @ASN1_BIT_STRING_free:= LoadFunctionCLib('ASN1_BIT_STRING_free');
      @ASN1_BIT_STRING_dup:= LoadFunctionCLib('ASN1_BIT_STRING_dup', false);
      @ASN1_BIT_STRING_cmp:= LoadFunctionCLib('ASN1_BIT_STRING_cmp', false);
      @ASN1_BIT_STRING_set:= LoadFunctionCLib('ASN1_BIT_STRING_set');
      @ASN1_BIT_STRING_check:= LoadFunctionCLib('ASN1_BIT_STRING_check');
      @ASN1_BIT_STRING_get_bit:= LoadFunctionCLib('ASN1_BIT_STRING_get_bit');
      @ASN1_BIT_STRING_name_print:= LoadFunctionCLib('ASN1_BIT_STRING_name_print');
      @ASN1_BIT_STRING_num_asc:= LoadFunctionCLib('ASN1_BIT_STRING_num_asc');
      @ASN1_BIT_STRING_set_asc:= LoadFunctionCLib('ASN1_BIT_STRING_set_asc');
      @ASN1_BIT_STRING_it:= LoadFunctionCLib('ASN1_BIT_STRING_it');
      @i2d_ASN1_BIT_STRING:= LoadFunctionCLib('i2d_ASN1_BIT_STRING');
      @d2i_ASN1_BIT_STRING:= LoadFunctionCLib('d2i_ASN1_BIT_STRING');

      @ASN1_BMPSTRING_new:= LoadFunctionCLib('ASN1_BMPSTRING_new');
      @ASN1_BMPSTRING_free:= LoadFunctionCLib('ASN1_BMPSTRING_free');
      @ASN1_BMPSTRING_it:= LoadFunctionCLib('ASN1_BMPSTRING_it');
      @i2d_ASN1_BMPSTRING:= LoadFunctionCLib('i2d_ASN1_BMPSTRING');
      @d2i_ASN1_BMPSTRING:= LoadFunctionCLib('d2i_ASN1_BMPSTRING');

      @i2d_ASN1_BOOLEAN:= LoadFunctionCLib('i2d_ASN1_BOOLEAN');
      @d2i_ASN1_BOOLEAN:= LoadFunctionCLib('d2i_ASN1_BOOLEAN');
      @ASN1_BOOLEAN_it:= LoadFunctionCLib('ASN1_BOOLEAN_it');
      @ASN1_FBOOLEAN_it:= LoadFunctionCLib('ASN1_FBOOLEAN_it');


      @ASN1_ENUMERATED_new:= LoadFunctionCLib('ASN1_ENUMERATED_new');
      @ASN1_ENUMERATED_free:= LoadFunctionCLib('ASN1_ENUMERATED_free');
      @ASN1_ENUMERATED_it:= LoadFunctionCLib('ASN1_ENUMERATED_it');
      @ASN1_ENUMERATED_set:= LoadFunctionCLib('ASN1_ENUMERATED_set');
      @ASN1_ENUMERATED_get:= LoadFunctionCLib('ASN1_ENUMERATED_get');
      @BN_to_ASN1_ENUMERATED:= LoadFunctionCLib('BN_to_ASN1_ENUMERATED');
      @ASN1_ENUMERATED_to_BN:= LoadFunctionCLib('ASN1_ENUMERATED_to_BN');
      @i2d_ASN1_ENUMERATED:= LoadFunctionCLib('i2d_ASN1_ENUMERATED');
      @d2i_ASN1_ENUMERATED:= LoadFunctionCLib('d2i_ASN1_ENUMERATED');

      @ASN1_INTEGER_new:= LoadFunctionCLib('ASN1_INTEGER_new');
      @ASN1_INTEGER_free:= LoadFunctionCLib('ASN1_INTEGER_free');
      @ASN1_INTEGER_dup:= LoadFunctionCLib('ASN1_INTEGER_dup');
      @ASN1_INTEGER_cmp:= LoadFunctionCLib('ASN1_INTEGER_cmp');
      @ASN1_INTEGER_set:= LoadFunctionCLib('ASN1_INTEGER_set');
      @ASN1_INTEGER_get:= LoadFunctionCLib('ASN1_INTEGER_get');
      @ASN1_INTEGER_it:= LoadFunctionCLib('ASN1_INTEGER_it');
      @ASN1_INTEGER_to_BN:= LoadFunctionCLib('ASN1_INTEGER_to_BN');
      @BN_to_ASN1_INTEGER:= LoadFunctionCLib('BN_to_ASN1_INTEGER');
      @i2c_ASN1_INTEGER:= LoadFunctionCLib('i2c_ASN1_INTEGER');
      @c2i_ASN1_INTEGER:= LoadFunctionCLib('c2i_ASN1_INTEGER');
      @d2i_ASN1_UINTEGER:= LoadFunctionCLib('d2i_ASN1_UINTEGER');

      @ASN1_GENERALIZEDTIME_new:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_new');
      @ASN1_GENERALIZEDTIME_free:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_free');
      @ASN1_GENERALIZEDTIME_it:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_it');
      @ASN1_GENERALIZEDTIME_print:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_print');
      @ASN1_GENERALIZEDTIME_check:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_check');
      @ASN1_GENERALIZEDTIME_set:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_set');
      @ASN1_GENERALIZEDTIME_adj:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_adj');
      @ASN1_GENERALIZEDTIME_set_string:= LoadFunctionCLib('ASN1_GENERALIZEDTIME_set_string');
      @i2d_ASN1_GENERALIZEDTIME:= LoadFunctionCLib('i2d_ASN1_GENERALIZEDTIME');
      @d2i_ASN1_GENERALIZEDTIME:= LoadFunctionCLib('d2i_ASN1_GENERALIZEDTIME');

      @ASN1_GENERALSTRING_new:= LoadFunctionCLib('ASN1_GENERALSTRING_new');
      @ASN1_GENERALSTRING_free:= LoadFunctionCLib('ASN1_GENERALSTRING_free');
      @ASN1_GENERALSTRING_it:= LoadFunctionCLib('ASN1_GENERALSTRING_it');
      @i2d_ASN1_GENERALSTRING:= LoadFunctionCLib('i2d_ASN1_GENERALSTRING');
      @d2i_ASN1_GENERALSTRING:= LoadFunctionCLib('d2i_ASN1_GENERALSTRING');

      @ASN1_IA5STRING_new:= LoadFunctionCLib('ASN1_IA5STRING_new');
      @ASN1_IA5STRING_free:= LoadFunctionCLib('ASN1_IA5STRING_free');
      @ASN1_IA5STRING_it:= LoadFunctionCLib('ASN1_IA5STRING_it');
      @i2d_ASN1_IA5STRING:= LoadFunctionCLib('i2d_ASN1_IA5STRING');
      @d2i_ASN1_IA5STRING:= LoadFunctionCLib('d2i_ASN1_IA5STRING');

      @ASN1_NULL_new:= LoadFunctionCLib('ASN1_NULL_new');
      @ASN1_NULL_free:= LoadFunctionCLib('ASN1_NULL_free');
      @ASN1_NULL_it:= LoadFunctionCLib('ASN1_NULL_it');
      @i2d_ASN1_NULL:= LoadFunctionCLib('i2d_ASN1_NULL');
      @d2i_ASN1_NULL:= LoadFunctionCLib('d2i_ASN1_NULL');

      @ASN1_PRINTABLESTRING_new:= LoadFunctionCLib('ASN1_PRINTABLESTRING_new');
      @ASN1_PRINTABLESTRING_free:= LoadFunctionCLib('ASN1_PRINTABLESTRING_free');
      @ASN1_PRINTABLESTRING_it:= LoadFunctionCLib('ASN1_PRINTABLESTRING_it');
      @i2d_ASN1_PRINTABLESTRING:= LoadFunctionCLib('i2d_ASN1_PRINTABLESTRING');
      @d2i_ASN1_PRINTABLESTRING:= LoadFunctionCLib('d2i_ASN1_PRINTABLESTRING');

      @ASN1_PRINTABLE_type:= LoadFunctionCLib('ASN1_PRINTABLE_type');
      @ASN1_PRINTABLE_new:= LoadFunctionCLib('ASN1_PRINTABLE_new');
      @ASN1_PRINTABLE_free:= LoadFunctionCLib('ASN1_PRINTABLE_free');
      @ASN1_PRINTABLE_it:= LoadFunctionCLib('ASN1_PRINTABLE_it');
      @i2d_ASN1_PRINTABLE:= LoadFunctionCLib('i2d_ASN1_PRINTABLE');
      @d2i_ASN1_PRINTABLE:= LoadFunctionCLib('d2i_ASN1_PRINTABLE');

      @ASN1_T61STRING_new:= LoadFunctionCLib('ASN1_T61STRING_new');
      @ASN1_T61STRING_free:= LoadFunctionCLib('ASN1_T61STRING_free');
      @ASN1_T61STRING_it:= LoadFunctionCLib('ASN1_T61STRING_it');
      @i2d_ASN1_T61STRING:= LoadFunctionCLib('i2d_ASN1_T61STRING');
      @d2i_ASN1_T61STRING:= LoadFunctionCLib('d2i_ASN1_T61STRING');
  end;
end;

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
