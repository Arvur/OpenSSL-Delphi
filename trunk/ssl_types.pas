{$I ssl.inc}

unit ssl_types;

interface
uses Winapi.Windows, ssl_const;

type

  qword = UInt64;
  TC_INT   = LongInt;
  PC_INT   = ^TC_INT;

  TC_UINT  = LongWord;
  PC_UINT  = ^TC_UINT;
  TC_LONG  = LongInt;
  PC_LONG = ^TC_LONG;
  TC_ULONG = LongWord;
  PC_ULONG = ^TC_ULONG;
  TC_ULONGLONG = qword;
  TC_time_t = TC_LONG;
  TC_USHORT = Word;
  PC_USHORT = ^TC_USHORT;
  TC_SIZE_T = LongWord;
  PC_SIZE_T = ^TC_SIZE_T;
  BN_ULONG = TC_ULONGLONG;
  PBN_ULONG = ^BN_ULONG;
  TC_UCHAR = AnsiChar;
  DES_LONG= TC_ULONG;
  point_conversion_form_t = byte;

type

  STACK = record
    num : TC_INT;
    data : PPAnsiChar;
    sorted : TC_INT;
    num_alloc : TC_INT;
    comp : function (_para1: PPAnsiChar; _para2: PPAnsiChar):  TC_INT; cdecl;
  end;

  STACK_OF = record
    _stack: STACK;
  end;
  PSTACK_OF = ^STACK_OF;
  PSTACK    = PSTACK_OF;

  CRYPTO_EX_DATA = record
    sk : PSTACK;
    dummy : TC_INT;
  end;

  PENGINE_CMD_DEFN = ^ENGINE_CMD_DEFN;
  ENGINE_CMD_DEFN = record
    cmd_num: TC_UINT;
    cmd_name: PAnsiChar;
    cmd_desc: PAnsiChar;
    cmd_flags: TC_UINT;
  end;

  PENGINE = ^ENGINE;
  ENGINE = record
      id: PAnsiChar;
      name: PAnsiChar;
      rsa_meth: Pointer;
      dsa_meth: Pointer;
      dh_meth: Pointer;
    ecdh_meth: Pointer;
    ecdsa_meth: Pointer;
      rand_meth: Pointer;
      store_meth: Pointer;
    ciphers: Pointer;
      digests: Pointer;
      pkey_meths: Pointer;
      pkey_asn1_meths: Pointer;
      _destroy: Pointer;
    init: Pointer;
    finish: Pointer;
    ctrl: Pointer;
    load_privkey: Pointer;
    load_pubkey: Pointer;
    load_ssl_client_cert: Pointer;
    cmd_defns: PENGINE_CMD_DEFN;
    flags: TC_INT;
      struct_ref: TC_INT;
    funct_ref: TC_INT;
      ex_data: CRYPTO_EX_DATA;
    prev: PENGINE;
      next: PENGINE;
  end;

  PUI_METHOD = Pointer;
  PSSL = Pointer;

{$IF DEFINED(WIN32)}
  BF_LONG = TC_ULONG;
{$ELSIF (DEFINED(OPENSSL_SYS_CRAY) OR DEFINED(WIN64))}
  BF_LONG = TC_ULONG;
{$ELSE}
  BF_LONG = TC_UINT;
{$IFEND}
  PBF_LONG = ^BF_LONG;

  BUF_MEM = record
    length : TC_SIZE_T;
    data : PAnsiChar;
    max: TC_SIZE_T;
  end;
  PBUF_MEM = ^BUF_MEM;


{$REGION 'CRYPTO'}
type
  PCRYPTO_THREADID = ^CRYPTO_THREADID;

  CRYPTO_THREADID = record
    ptr: Pointer;
    val: TC_ULONG;
  end;

  PCRYPTO_EX_DATA = ^CRYPTO_EX_DATA;

  CRYPTO_EX_new = function(parent: Pointer; ptr: Pointer; ad: PCRYPTO_EX_DATA;
                    idx: TC_INT; argl: TC_LONG; argp: Pointer): TC_INT; cdecl;

  CRYPTO_EX_free = procedure(parent: Pointer; ptr: Pointer; ad: PCRYPTO_EX_DATA;
                    idx: TC_INT; argl: TC_LONG; argp: Pointer); cdecl;

  CRYPTO_EX_dup = function(_to: PCRYPTO_EX_DATA; _from: PCRYPTO_EX_DATA; from_d: Pointer;
                    idx: TC_INT; argl: TC_LONG; argp: Pointer): TC_INT; cdecl;

{$ENDREGION}


{$REGION 'BN'}
  BIGNUM = record
    d : PBN_ULONG;
    top : TC_INT;
    dmax : TC_INT;
    neg : TC_INT;
    flags : TC_INT;
  end;
  PBIGNUM = ^BIGNUM;
  BIGNUM_ARR = array[0..1] of BIGNUM;
  PBIGNUM_ARR = ^BIGNUM_ARR;

  PBN_GENCB = ^BN_GENCB;
  BN_cb_1 = procedure (p1, p2 : TC_INT; p3 : Pointer); cdecl;
  BN_cb_2 = function (p1, p2 : TC_INT; p3 : PBN_GENCB): TC_INT; cdecl;

  BN_GENCB_union = record
    case Integer of
        0 : (cb_1 : BN_cb_1);
        1 : (cb_2 : BN_cb_2);
  end;

  BN_GENCB = record
    ver : TC_UINT;
    arg : Pointer;
    cb : BN_GENCB_union;
  end;

  BN_MONT_CTX = record
    ri : TC_INT;
    RR: BIGNUM;
    N: BIGNUM;
    Ni: BIGNUM;
    n0 : array[0..1] of  BN_ULONG;
    flags : TC_INT;
  end;
  PBN_MONT_CTX = ^BN_MONT_CTX;

  PBN_CTX_STACK = ^BN_CTX_STACK;
  BN_CTX_STACK = record
    indexes: PC_UINT;
    depth: TC_UINT;
    size: TC_UINT;
  end;
  BN_STACK = BN_CTX_STACK;
  PBN_STACK = ^BN_STACK;

  PBN_POOL_ITEM = ^BN_POOL_ITEM;
  BN_POOL_ITEM = record
    vals: array[0..BN_CTX_POOL_SIZE-1] of BIGNUM;
    prev: PBN_POOL_ITEM;
    next: PBN_POOL_ITEM;
  end;

  BN_POOL = record
    head: PBN_POOL_ITEM;
    current: PBN_POOL_ITEM;
    tail: PBN_POOL_ITEM;
    used: TC_UINT;
    size: TC_UINT;
  end;

  PBN_CTX = ^BN_CTX;
  BN_CTX = record
   pool: BN_POOL;
   stack: BN_STACK;
   used: TC_UINT;
   err_stack: TC_INT;
   too_many: TC_INT;
  end;

  PPBN_CTX = ^PBN_CTX;
  PBN_BLINDING = ^BN_BLINDING;

  BN_BLINDING = record
   A: PBIGNUM;
   Ai: PBIGNUM;
   e: PBIGNUM;
   _mod: PBIGNUM;
   thread_id: TC_ULONG;
   tid: CRYPTO_THREADID;
   counter: TC_INT;
   flags: TC_ULONG;
   m_ctx: PBN_MONT_CTX;
   bn_mod_exp: function(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TC_INT;
  end;

  PBN_RECP_CTX = ^BN_RECP_CTX;
  BN_RECP_CTX = record
   N: BIGNUM;
   Nr: BIGNUM;
   num_bits: TC_INT;
   shift: TC_INT;
   flags: TC_INT;
  end;

  BN_mod_exp_cb = function(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TC_INT; cdecl;
{$ENDREGION}

{$REGION 'CAST'}

type
  CAST_LONG = TC_UINT;
  PCAST_LONG = ^CAST_LONG;

  CAST_KEY = record
    data: array[0..31] of CAST_LONG;
    short_key: TC_INT;
  end;
  PCAST_KEY = ^CAST_KEY;

{$ENDREGION}

{$REGION 'EC'}
  EC_builtin_curve = record
    nid : TC_INT;
    comment : PAnsiChar;
  end;

  PEC_GROUP = Pointer;

  PEC_METHOD = ^EC_METHOD;

  PEC_POINT = ^EC_POINT;
  EC_POINT = record
      meth: PEC_METHOD;
    X: PBIGNUM;
    Y: PBIGNUM;
    Z: PBIGNUM;
    Z_is_one: TC_INT;
  end;
  EC_POINT_ARR = array[0..0] of EC_POINT;
  PEC_POINT_ARR = ^EC_POINT_ARR;

  EC_METHOD = record
    flags: TC_INT;
    field_type: TC_INT;
    group_init: function: PEC_GROUP; cdecl;
    group_finsh: procedure(_group: PEC_GROUP); cdecl;
    group_clear_finish: procedure(_group: PEC_GROUP); cdecl;
    group_copy: function(dst: PEC_GROUP; src: PEC_GROUP): TC_INT; cdecl;
    group_set_curve: function(_gr: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    group_get_curve: function(_gr: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    group_get_degree: function(g: PEC_GROUP): TC_INT; cdecl;
    group_check_discriminant: function(_gr: PEC_GROUP; ctx: PBN_CTX): TC_INT; cdecl;
    point_init: function: PEC_POINT;
    point_finish: procedure(p: PEC_POINT); cdecl;
    point_finish_clear: procedure(p: PEC_POINT); cdecl;
    point_copy: function(p1, p2: PEC_POINT): TC_INT; cdecl;
    point_set_to_infinity: function(g: PEC_GROUP; p: PEC_POINT): TC_INT; cdecl;
    point_set_Jprojective_coordinates_GFp: function(g: PEC_GROUP; p: PEC_POINT; x,y,z: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    point_get_Jprojective_coordinates_GFp: function(g: PEC_GROUP; p: PEC_POINT; x,y,z: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    point_set_affine_coordinates: function(g: PEC_GROUP; p: PEC_POINT; x,y,z: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    point_get_affine_coordinates: function(g: PEC_GROUP; p: PEC_POINT; x,y,z: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
    point_set_compressed_coordinates: function(g: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TC_INT; ctx: PBN_CTX): TC_INT; cdecl;
    point2oct: function(g: PEC_GROUP; p: PEC_POINT; _form: point_conversion_form_t; buf: PAnsiChar; len: TC_SIZE_T; ctx: PBN_CTX): TC_SIZE_T; cdecl;
    oct2point: function(g: PEC_GROUP; p: PEC_POINT; buf: PAnsiChar; len: TC_SIZE_T; ctx: PBN_CTX): TC_INT; cdecl;
    add: function(g: PEC_GROUP; r,a,b: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    dbl: function(g: PEC_GROUP; r,a: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    invert: function(g: PEC_GROUP; p: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    is_at_infinity: function(g: PEC_GROUP; p: PEC_POINT): TC_INT; cdecl;
    is_on_curve: function(g: PEC_GROUP; p: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    point_cmp: function(g: PEC_GROUP; a,b: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    make_affine: function(g: PEC_GROUP; p: PEC_POINT; ctx: PBN_CTX): TC_INT; cdecl;
    points_make_affine: function(g: PEC_GROUP; num: TC_SIZE_T; p: PEC_POINT_ARR; ctx: PBN_CTX): TC_INT; cdecl;
    mul: function(g: PEC_GROUP; r: PEC_POINT; scalar: PBIGNUM; num: TC_SIZE_T; points: PEC_POINT_ARR; scalars: PBIGNUM_ARR; ctx: PBN_CTX): TC_INT; cdecl;
    precompute_mult: function(g: PEC_GROUP; ctx: PBN_CTX): TC_INT; cdecl;
    have_precompute_mult: function(g: PEC_GROUP): TC_INT; cdecl;
      field_mul: function(g: PEC_GROUP; r, a, b: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
      field_sqr: function(g: PEC_GROUP; r, a: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
      field_div: function(g: PEC_GROUP; r, a, b: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
      field_encode: function(g: PEC_GROUP; r, a: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
      field_decode: function(g: PEC_GROUP; r, a: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
      field_set_to_one: function(g: PEC_GROUP; r : PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
  end;

  PEC_EXTRA_DATA = ^EC_EXTRA_DATA;
  EC_EXTRA_DATA = record
    next: PEC_EXTRA_DATA;
    data: Pointer;
      dup_func: function: pointer; cdecl;
      free_func: procedure(_par: Pointer); cdecl;
      clear_free_func: procedure(_par: Pointer); cdecl;
  end;


  EC_GROUP = record
    meth: PEC_METHOD;
    generator: PEC_POINT;
    order, cofactor: PBIGNUM;
    curve_name : TC_INT;
      asn1_flag: TC_INT;
      asn1_form: point_conversion_form_t;
      seed: PAnsiChar;
    seed_len: TC_SIZE_T;

    extra_data: PEC_EXTRA_DATA;

      field : BIGNUM;
      poly: array[0..5] of TC_INT;
      a, b: BIGNUM;
      a_is_minus3: TC_INT;
    field_data1: Pointer;
      field_data2: Pointer;
    field_mod_func: function(a, b, c: PBIGNUM; ctx: PBN_CTX): TC_INT; cdecl;
  end;

  EC_builtin_curves = array[0..0] of EC_builtin_curve;
  PEC_builtin_curves = ^EC_builtin_curves;


  PEC_KEY = ^EC_KEY;
  EC_KEY = record
      version: TC_INT;
    group: PEC_GROUP;

    pub_key: PEC_POINT;
    priv_key:PBIGNUM;

      enc_flag: TC_UINT;
      conv_form: point_conversion_form_t;

    references: TC_INT;
    flags: TC_INT;
    method_data: PEC_EXTRA_DATA;
  end;

  EC_dup_func = function(par: Pointer): Pointer; cdecl;
  EC_free_func = procedure(par: Pointer); cdecl;
  EC_clear_free_func = procedure(par: Pointer); cdecl;


{$ENDREGION}


  PSTACK_OF_IPAddressFamily = PSTACK;
  PSTACK_OF_ASN1_TYPE = PSTACK; // may be ^
  PSTACK_OF_ASN1_OBJECT = PSTACK;
  PSTACK_OF_GENERAL_NAME = PSTACK;
  PGENERAL_NAMES = PSTACK_OF_GENERAL_NAME;
  PSTACK_OF_ASIdOrRange = PSTACK;
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;
  PSTACK_OF_CONF_VALUE = PSTACK;




  BIT_STRING_BITNAME = record
    bitnum : TC_INT;
    lname : PAnsiChar;
    sname : PAnsiChar;
  end;
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;


{$REGION 'BIO'}
  PBIO = ^BIO;
  PBIO_METHOD = ^BIO_METHOD;

  Pbio_info_cb = procedure (_para1 : PBIO; _para2 : TC_INT; _para3 : PAnsiChar;
     _para4 : TC_INT; _para5, _para6 : TC_LONG); cdecl;
  pbio_dump_cb = function(data: Pointer; len: TC_SIZE_T; u: pointer): TC_INT; cdecl;

  BIO_METHOD = record
    _type : TC_INT;
    name : PAnsiChar;
    bwrite : function(_para1 : PBIO; _para2 : PAnsiChar; _para3 : TC_Int) : TC_Int; cdecl;
    bread : function(_para1: PBIO; _para2: PAnsiChar; _para3: TC_Int) : TC_Int; cdecl;
    bputs : function (_para1 : PBIO; _para2 : PAnsiChar) : TC_Int; cdecl;
    bgets : function (_para1 : PBIO; _para2 : PAnsiChar; _para3 : TC_Int) : TC_Int; cdecl;
    ctrl : function (_para1 : PBIO; _para2 : TC_Int; _para3 : TC_LONG; _para4 : Pointer) : TC_LONG; cdecl;
    create : function(_para1 : PBIO) : TC_Int; cdecl;
    destroy : function (_para1 : PBIO) : TC_Int; cdecl;
    callback_ctrl : function (_para1 : PBIO; _para2 : TC_Int; _para3 : pbio_info_cb): TC_LONG; cdecl;
  end;

  BIO = record
    method : PBIO_METHOD;
    callback : function (_para1 : PBIO; _para2 : TC_INT; _para3 : PAnsiChar;
       _para4 : TC_INT; _para5, _para6 : TC_LONG) : TC_LONG cdecl;
    cb_arg : PAnsiChar;
    init : TC_INT;
    shutdown : TC_INT;
    flags : TC_INT;
    retry_reason : TC_INT;
    num : TC_INT;
    ptr : Pointer;
    next_bio : PBIO;
    prev_bio : PBIO;
    references : TC_INT;
    num_read : TC_ULONG;
    num_write : TC_ULONG;
    ex_data : CRYPTO_EX_DATA;
  end;

{$ENDREGION}

{$REGION 'ASN1'}
  ASN1_OBJECT = record
    sn, ln : PAnsiChar;
    nid    : TC_INT;
    length : TC_INT;
    data   : PAnsiChar;
    flags  : TC_INT; // Should we free this one
  end;

  asn1_string_st = record
    length : TC_INT;
    _type : TC_INT;
    data : PAnsiChar;
    flags : TC_LONG;
  end;

  ASN1_STRING = asn1_string_st;
  PASN1_STRING = ^ASN1_STRING;
  PPASN1_STRING = ^PASN1_STRING;
  ASN1_INTEGER = ASN1_STRING;
  PASN1_INTEGER = ^ASN1_INTEGER;
  PPASN1_INTEGER = ^PASN1_INTEGER;

  PASN1_OBJECT = ^ASN1_OBJECT;
  ASN1_UNIVERSALSTRING = ASN1_STRING;
  PASN1_UNIVERSALSTRING = ^ASN1_UNIVERSALSTRING;
  PPASN1_UNIVERSALSTRING = ^PASN1_UNIVERSALSTRING;
  ASN1_BMPSTRING = ASN1_STRING;
  PASN1_BMPSTRING = ^ASN1_BMPSTRING;
  PPASN1_BMPSTRING = ^PASN1_BMPSTRING;
  ASN1_VISIBLESTRING = ASN1_STRING;
  PASN1_VISIBLESTRING = ^ASN1_VISIBLESTRING;
  PPASN1_VISIBLESTRING = ^PASN1_VISIBLESTRING;
  ASN1_UTF8STRING = ASN1_STRING;
  PASN1_UTF8STRING = ^ASN1_UTF8STRING;
  PPASN1_UTF8STRING = ^PASN1_UTF8STRING;
  ASN1_BOOLEAN = TC_INT;
  PASN1_BOOLEAN = ^ASN1_BOOLEAN;
  PPASN1_BOOLEAN = ^PASN1_BOOLEAN;
  ASN1_NULL = TC_INT;
  PASN1_NULL = ^ASN1_NULL;
  PPASN1_NULL = ^PASN1_NULL;
  ASN1_ENUMERATED = ASN1_STRING;
  PASN1_ENUMERATED = ^ASN1_ENUMERATED;
  ASN1_BIT_STRING = ASN1_STRING;
  PASN1_BIT_STRING = ^ASN1_BIT_STRING;
  ASN1_OCTET_STRING = ASN1_STRING;
  PASN1_OCTET_STRING = ^ASN1_OCTET_STRING;
  ASN1_PRINTABLESTRING = ASN1_STRING;
  PASN1_PRINTABLESTRING = ^ASN1_PRINTABLESTRING;
  ASN1_T61STRING = ASN1_STRING;
  PASN1_T61STRING = ^ASN1_T61STRING;
  ASN1_IA5STRING = ASN1_STRING;
  PASN1_IA5STRING = ^ASN1_IA5STRING;
  ASN1_GENERALSTRING = ASN1_STRING;
  PASN1_GENERALSTRING = ^ASN1_GENERALSTRING;
  ASN1_UTCTIME = ASN1_STRING;
  PASN1_UTCTIME = ^ASN1_UTCTIME;
  ASN1_GENERALIZEDTIME = ASN1_STRING;
  PASN1_GENERALIZEDTIME = ^ASN1_GENERALIZEDTIME;
  ASN1_TIME = ASN1_STRING;
  PASN1_TIME = ^ASN1_TIME;

  ASN1_ENCODING = record
    enc: PAnsiChar;
    len: TC_LONG;
    modified: TC_INT;
  end;
  PASN1_ENCODING = ^ASN1_ENCODING;

  ASN1_TYPE = record
    case Integer of
      0:  (ptr: PAnsiChar);
      1:  (boolean: ASN1_BOOLEAN);
      2:  (asn1_string: PASN1_STRING);
      3:  (_object: PASN1_OBJECT);
      4:  (integer: PASN1_INTEGER);
      5:  (enumerated: PASN1_ENUMERATED);
      6:  (bit_string: PASN1_BIT_STRING);
      7:  (octet_string: PASN1_OCTET_STRING);
      8:  (printablestring: PASN1_PRINTABLESTRING);
      9:  (t61string: PASN1_T61STRING);
      10: (ia5string: PASN1_IA5STRING);
      11: (generalstring: PASN1_GENERALSTRING);
      12: (bmpstring: PASN1_BMPSTRING);
      13: (universalstring: PASN1_UNIVERSALSTRING);
      14: (utctime: PASN1_UTCTIME);
      15: (generalizedtime: PASN1_GENERALIZEDTIME);
      16: (visiblestring: PASN1_VISIBLESTRING);
      17: (utf8string: PASN1_UTF8STRING);
      18: (_set: PASN1_STRING);
      19: (sequence: PASN1_STRING);
  end;
  PASN1_TYPE = ^ASN1_TYPE;

  AUTHORITY_KEYID = record
    keyid : PASN1_OCTET_STRING;
    issuer : PGENERAL_NAMES;
    serial : PASN1_INTEGER;
  end;
  PAUTHORITY_KEYID = ^AUTHORITY_KEYID;

  ASIdentifierChoice_union = record
  case byte of
   ASIdentifierChoice_inherit : (inherit : PASN1_NULL);
   ASIdentifierChoice_asIdsOrRanges : (asIdsOrRanges : PASIdOrRanges);
  end;
  ASIdentifierChoice = record
    _type : TC_INT;
    u : ASIdentifierChoice_union;
  end;
  PASIdentifierChoice = ^ASIdentifierChoice;


  ASIdentifiers = record
    asnum : PASIdentifierChoice;
    rdi : PASIdentifierChoice;
  end;
  PASIdentifiers = ^ASIdentifiers;

  ASN1_CTX = record
    p : PAnsiChar;   // work char pointer
    eos : TC_INT;    // end of sequence read for indefinite encoding
    error : TC_INT;  // error code to use when returning an error
    inf : TC_INT;    // constructed if 0x20, indefinite is 0x21
    tag : TC_INT;    // tag from last 'get object'
    xclass : TC_INT; // class from last 'get object'
    slen : TC_LONG;  // length of last 'get object'
    max : PAnsiChar; // largest value of p allowed
    q : PAnsiChar;   // temporary variable
    pp : PPAnsiChar; // variable
    line : TC_INT;   // used in error processing
  end;
  PASN1_CTX = ^ASN1_CTX;

  ASN1_PCTX = record
    flags: TC_ULONG;
    nm_flags: TC_ULONG;
    cert_flags: TC_ULONG;
    oid_flags: TC_ULONG;
    str_flags: TC_ULONG;
  end;

  PASN1_PCTX = ^ASN1_PCTX;

  I2D_OF_void = function(_para1 : Pointer; var _para2 : PByte) : TC_INT cdecl;
  D2I_OF_void = function (_para1 : PPointer;  var _para2 : PByte; _para3 : TC_LONG) : Pointer cdecl;

  ASN1_METHOD = record
    i2d : i2d_of_void;
    d2i : i2d_of_void;
    create : function: Pointer; cdecl;
    destroy : procedure(ptr: Pointer); cdecl;
  end;
  PASN1_METHOD = ^ASN1_METHOD;

  ASN1_HEADER = record
    header : PASN1_OCTET_STRING;
    data : Pointer;
    meth : PASN1_METHOD;
  end;
  PASN1_HEADER = ^ASN1_HEADER;

  ASN1_STRING_TABLE = record
    nid : TC_INT;
    minsize : TC_LONG;
    maxsize : TC_LONG;
    mask : TC_ULONG;
    flags : TC_ULONG;
  end;
  PASN1_STRING_TABLE = ^ASN1_STRING_TABLE;
  PSTACK_OF_ASN1_STRING_TABLE = PSTACK;

  PASN1_ITEM = ^ASN1_ITEM;
  PASN1_ITEM_EXP = PASN1_ITEM;

  ASN1_TEMPLATE = record
    flags : TC_ULONG;         // Various flags
    tag : TC_LONG;            // tag, not used if no tagging
    offset : TC_ULONG;        // Offset of this field in structure
    field_name : PAnsiChar;   // Field name
    item : PASN1_ITEM_EXP;    // Relevant ASN1_ITEM or ASN1_ADB
  end;

  PASN1_TEMPLATE = ^ASN1_TEMPLATE;
  ASN1_ITEM = record
    itype : Char;               // The item type, primitive, SEQUENCE, CHOICE or extern
    utype : TC_LONG;            // underlying type
    templates : PASN1_TEMPLATE; // If SEQUENCE or CHOICE this contains the contents
    tcount : TC_LONG;           // Number of templates if SEQUENCE or CHOICE
    funcs : Pointer;            // functions that handle this type
    size : TC_LONG;             // Structure size (usually)
    sname : PAnsiChar;            // Structure name
  end;

  PSTACK_OF_ASN1_ADB_TABLE = PSTACK;
  PPSTACK_OF_ASN1_ADB_TABLE = ^PSTACK_OF_ASN1_ADB_TABLE;
  PASN1_ADB_TABLE = ^ASN1_ADB_TABLE;
  PASN1_ADB = ^ASN1_ADB;

  ASN1_ADB = record
    flags : TC_ULONG;                       // Various flags
    offset : TC_ULONG;                      // Offset of selector field
    app_items : PPSTACK_OF_ASN1_ADB_TABLE;  // Application defined items
    tbl : PASN1_ADB_TABLE;                  // Table of possible types
    tblcount : TC_LONG;                     // Number of entries in tbl
    default_tt : PASN1_TEMPLATE;            // Type to use if no match
    null_tt : PASN1_TEMPLATE;               // Type to use if selector is NULL
  end;
  ASN1_ADB_TABLE = record
    flags : TC_LONG;                        // Various flags
    offset : TC_LONG;                         // Offset of selector field
    app_items : PPSTACK_OF_ASN1_ADB_TABLE;  // Application defined items
    tbl : PASN1_ADB_TABLE;                  // Table of possible types
    tblcount : TC_LONG;                     // Number of entries in tbl
    default_tt : PASN1_TEMPLATE;            // Type to use if no match
    null_tt : PASN1_TEMPLATE;               // Type to use if selector is NULL
  end;

  PASN1_TLC = ^ASN1_TLC;
  ASN1_TLC = record
      valid : Byte;     // Values below are valid
      ret : TC_INT;     // return value
      plen : TC_LONG;     // length
      ptag : TC_INT;      // class value
      pclass : TC_INT;  // class value
      hdrlen : TC_INT;  // header length
  end;
  PASN1_VALUE = Pointer;

  ASN1_new_func = function : PASN1_VALUE; cdecl;
  ASN1_free_func = procedure (a : PASN1_VALUE); cdecl;
  ASN1_d2i_func = function (a : PASN1_VALUE; var _in : PByte; length : TC_LONG ) : PASN1_VALUE; cdecl;
  ASN1_i2d_func = function (a : PASN1_VALUE; var _in : PByte)  : TC_INT; cdecl;
  ASN1_ex_d2i = function(var pval : PASN1_VALUE; var _in : PByte; len : TC_LONG; it : PASN1_ITEM; tag, aclass : TC_INT;
                   opt : Byte; ctx : PASN1_TLC) : TC_INT; cdecl;
  ASN1_ex_i2d = function(var pval : PASN1_VALUE; var _out : PByte;  it : PASN1_ITEM; tag, aclass : TC_INT) : TC_INT; cdecl;
  ASN1_ex_new_func = function(var pval : PASN1_VALUE; it : PASN1_ITEM) : TC_INT; cdecl;
  ASN1_ex_free_func = procedure(var pval : PASN1_VALUE; it : PASN1_ITEM); cdecl;
  ASN1_primitive_i2c = function (var pval : PASN1_VALUE; cont : PByte; putype : PC_INT; it : PASN1_ITEM ) : TC_INT; cdecl;
  ASN1_primitive_c2i = function (var pval : PASN1_VALUE; cont : PByte; len, utype : TC_INT; free_cont : PByte; it: PASN1_ITEM) : TC_INT; cdecl;

  ASN1_COMPAT_FUNCS = record
      asn1_new : ASN1_new_func;
      asn1_free : ASN1_free_func;
      asn1_d2i : ASN1_d2i_func;
     asn1_i2d : ASN1_i2d_func;
  end;
  PASN1_COMPAT_FUNCS = ^ASN1_COMPAT_FUNCS;

  ASN1_EXTERN_FUNCS = record
      app_data : Pointer;
    asn1_ex_new : ASN1_ex_new_func;   //    ASN1_ex_new_func *asn1_ex_new;
    asn1_ex_free : ASN1_ex_free_func; //    ASN1_ex_free_func *asn1_ex_free;
    asn1_ex_clear: ASN1_ex_free_func; //    ASN1_ex_free_func *asn1_ex_clear;
    asn1_ex_d2i : ASN1_ex_d2i;        //    ASN1_ex_d2i *asn1_ex_d2i;
    asn1_ex_i2d : ASN1_ex_i2d;        //    ASN1_ex_i2d *asn1_ex_i2d;
  end;
  PASN1_EXTERN_FUNCS = ^ASN1_EXTERN_FUNCS;

  ASN1_PRIMITIVE_FUNCS = record
    app_data : Pointer;
    flags : TC_ULONG;
    prim_new : ASN1_ex_new_func;
    prim_free : ASN1_ex_free_func;
    prim_clear : ASN1_ex_free_func;
    prim_c2i : ASN1_primitive_c2i;
    prim_i2c : ASN1_primitive_i2c;
  end;
  PASN1_PRIMITIVE_FUNCS = ^ASN1_PRIMITIVE_FUNCS;

  ASN1_aux_cb = function (operation : TC_INT; var _in : PASN1_VALUE; it : PASN1_ITEM) : TC_INT; cdecl;
  asn1_ps_func = function(b: PBIO; var pbuf: PAnsiChar; plen: PC_INT; var parg: Pointer): TC_INT; cdecl;

  ASN1_AUX = record
    app_data : Pointer;
    flags : TC_INT;
    ref_offset : TC_INT;        // Offset of reference value
    ref_lock : TC_INT;        // Lock type to use
    asn1_cb : ASN1_aux_cb;
    enc_offset : TC_INT;        // Offset of ASN1_ENCODING structure
  end;
  PASN1_AUX = ^ASN1_AUX;

{$ENDREGION}

{$REGION 'LHASH'}

  PLHASH_NODE = ^LHASH_NODE;
  PPLHASH_NODE = ^PLHASH_NODE;
  LHASH_NODE = record
    data : Pointer;
    next : PLHASH_NODE;
    hash : TC_ULONG;
  end;

  LHASH_COMP_FN_TYPE = function (const p1,p2 : Pointer) : TC_INT; cdecl;
  LHASH_HASH_FN_TYPE = function(const p1 : Pointer) : TC_ULONG; cdecl;
  LHASH = record
    b : PPLHASH_NODE;
    comp : LHASH_COMP_FN_TYPE;
    hash : LHASH_HASH_FN_TYPE;
    num_nodes : TC_UINT;
    num_alloc_nodes : TC_UINT;
    p : TC_UINT;
    pmax : TC_UINT;
    up_load : TC_ULONG; // load times 256
    down_load : TC_ULONG; // load times 256
    num_items : TC_ULONG;
    num_expands : TC_ULONG;
    num_expand_reallocs : TC_ULONG;
    num_contracts : TC_ULONG;
    num_contract_reallocs : TC_ULONG;
    num_hash_calls : TC_ULONG;
    num_comp_calls : TC_ULONG;
    num_insert : TC_ULONG;
    num_replace : TC_ULONG;
    num_delete : TC_ULONG;
    num_no_delete : TC_ULONG;
    num_retrieve : TC_ULONG;
    num_retrieve_miss : TC_ULONG;
    num_hash_comps : TC_ULONG;
    error : TC_INT;
  end;
  {$EXTERNALSYM PLHASH}
  PLHASH = ^LHASH;
{$ENDREGION}

{$REGION 'CONF'}
  CONF_VALUE = record
    section : PAnsiChar;
    name : PAnsiChar;
    value : PAnsiChar;
  end;
  PCONF_VALUE = ^CONF_VALUE;

  PCONF_METHOD = ^CONF_METHOD;
  PCONF = ^CONF;

  CONF_METHOD = record
    name: PAnsiChar;
    create: function(meth: PCONF_METHOD): PCONF; cdecl;
    init: function(_conf: PCONF): TC_INT; cdecl;
    destroy: function(_conf: PCONF): TC_INT; cdecl;
    destroy_data: function(_conf: PCONF): TC_INT; cdecl;
    load_bio: function(_conf: PCONF; bp: PBIO; eline: PC_LONG): TC_INT; cdecl;
    dump: function(_conf: PCONF; bp: PBIO): TC_INT; cdecl;
    is_number: function(_conf: PCONF; c: AnsiChar): TC_INT; cdecl;
    to_int: function(_conf: PCONF; c: AnsiChar): TC_INT; cdecl;
    load: function(_conf: PCONF; name: PAnsiChar; eline: PC_LONG): TC_INT; cdecl;
  end;

  CONF = record
    method: PCONF_METHOD;
    meth_data: Pointer;
    data: PLHASH;
  end;
{$ENDREGION}

{$REGION 'DH'}

  PDH = ^DH;

  PDH_METHOD = ^DH_METHOD;
  DH_METHOD = record
    name: PAnsiChar;
    generate_key: function(_dh: PDH): TC_INT; cdecl;
    compute_key: function(key: PAnsiChar; pub_key: PBIGNUM; _dh: PDH): TC_INT; cdecl;
    bn_mod_exp: function(_dh: PDH; r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TC_INT; cdecl;
    init: function(_dh: PDH): TC_INT; cdecl;
    finish: function(_dh: PDH): TC_INT; cdecl;
    flags: TC_INT;
    app_data: PAnsiChar;
    generate_params: function(_dh: PDH; prime_len: TC_INT; generator: TC_INT; cb: PBN_GENCB): TC_INT; cdecl;
  end;

  DH = record
    pad : TC_INT;
    version : TC_INT;
    p: PBIGNUM;
    g: PBIGNUM;
    _length: TC_LONG;
    pub_key: PBIGNUM;
    priv_key: PBIGNUM;
    flags: TC_INT;
    method_mont_p: PBN_MONT_CTX;
    q: PBIGNUM;
    j: PBIGNUM;
    seed: PAnsiChar;
    seedlen: TC_INT;
    counter: PBIGNUM;
    references: TC_INT;
    ex_data: CRYPTO_EX_DATA;
    meth : PDH_METHOD;
    engine: PENGINE;
  end;

{$ENDREGION}


{$REGION 'RSA'}
type
  PRSA = ^RSA;
  RSA_METHOD = record
    name : PAnsiChar;
    rsa_pub_enc : function (flen : TC_INT; const from : PAnsiChar;
      _to : PAnsiChar; rsa : PRSA; padding : TC_INT) : TC_INT; cdecl;
    rsa_pub_dec : function (flen : TC_INT; const from : PAnsiChar;
      _to : PAnsiChar; rsa : PRSA; padding : TC_INT) : TC_INT; cdecl;
    rsa_priv_enc : function (flen : TC_INT; const from : PAnsiChar;
      _to : PAnsiChar; rsa : PRSA; padding : TC_INT) : TC_INT; cdecl;
    rsa_priv_dec : function (flen : TC_INT; const from : PAnsiChar;
       _to : PAnsiChar; rsa : PRSA; padding : TC_INT) : TC_INT; cdecl;
    rsa_mod_exp : function (r0 : PBIGNUM; const I : PBIGNUM;  rsa : PRSA; ctx : PBN_CTX) : TC_INT cdecl;
    bn_mod_exp : function (r : PBIGNUM; const a : PBIGNUM; const p : PBIGNUM; const m: PBIGNUM; ctx : PBN_CTX;
      m_ctx : PBN_MONT_CTX ) : TC_INT; cdecl;
    init : function (rsa : PRSA) : TC_INT; cdecl;
    finish : function (rsa : PRSA) : TC_INT; cdecl;
    flags : TC_INT;
    app_data : PAnsiChar;
    rsa_sign : function (_type : TC_INT; const m : PAnsiChar; m_length : TC_UINT; sigret : PAnsiChar; siglen : PC_UINT; const rsa : PRSA) : TC_INT; cdecl;
    rsa_verify : function(dtype : TC_INT; const m : PAnsiChar; m_length : PC_UINT; sigbuf : PAnsiChar; siglen : PC_UINT; const rsa :PRSA) : TC_INT; cdecl;
    rsa_keygen : function (rsa : PRSA; bits : TC_INT; e : PBIGNUM; cb : PBN_GENCB) : TC_INT; cdecl;
  end;

  PRSA_METHOD = ^RSA_METHOD;

  RSA = record
    pad : TC_INT;
    version : TC_LONG;
    meth : PRSA_METHOD;
    engine : PENGINE;
    n : PBIGNUM;
    e : PBIGNUM;
    d : PBIGNUM;
    p : PBIGNUM;
    q : PBIGNUM;
    dmp1 : PBIGNUM;
    dmq1 : PBIGNUM;
    iqmp : PBIGNUM;
    ex_data : CRYPTO_EX_DATA;
    references : TC_INT;
    flags : TC_INT;
    _method_mod_n : PBN_MONT_CTX;
    _method_mod_p : PBN_MONT_CTX;
    _method_mod_q : PBN_MONT_CTX;
    bignum_data : PAnsiChar;
    blinding : PBN_BLINDING;
    mt_blinding : PBN_BLINDING;
  end;
{$ENDREGION}


{$REGION 'DSA'}
  PDSA = ^DSA;

  DSA_SIG = record
    r : PBIGNUM;
    s : PBIGNUM;
  end;
  PDSA_SIG = ^DSA_SIG;

  DSA_METHOD = record
    name : PAnsiChar;
    dsa_do_sign : function (const dgst : PAnsiChar; dlen : TC_INT; dsa : PDSA) : PDSA_SIG; cdecl;
    dsa_sign_setup : function (dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBN_CTX) : TC_INT; cdecl;
    dsa_do_verify : function(dgst : PAnsiChar; dgst_len : TC_INT;
      sig : PDSA_SIG; dsa : PDSA) : TC_INT; cdecl;
    dsa_mod_exp : function(dsa : PDSA; rr, a1, p1,
       a2, p2, m : PBIGNUM; ctx : PBN_CTX;
       in_mont : PBN_MONT_CTX) : TC_INT; cdecl;
    bn_mod_exp : function (dsa : PDSA; r, a : PBIGNUM; const p, m : PBIGNUM;
      ctx : PBN_CTX; m_ctx : PBN_CTX): TC_INT; cdecl; // Can be null
    init : function (dsa : PDSA) : TC_INT; cdecl;
    finish : function (dsa : PDSA) : TC_INT; cdecl;
    flags : TC_INT;
    app_data : PAnsiChar;
     dsa_paramgen : function (dsa : PDSA; bits : TC_INT; seed : PAnsiChar;
       seed_len : TC_INT; counter_ret : PC_INT; h_ret : PC_ULONG;
       cb : PBN_GENCB ) : TC_INT; cdecl;
    dsa_keygen : function(dsa : PDSA) : TC_INT; cdecl;
  end;
  PDSA_METHOD = ^DSA_METHOD;

  DSA = record
    pad : TC_INT;
    version : TC_LONG;
    write_params : TC_INT;
    p : PBIGNUM;
    q : PBIGNUM;
    g : PBIGNUM;
    pub_key : PBIGNUM;
    priv_key : PBIGNUM;
    kinv : BIGNUM;
    r : PBIGNUM;
    flags : TC_INT;
    method_mont_p : PBN_MONT_CTX;
    references : TC_INT;
    ex_data : CRYPTO_EX_DATA;
    meth : PDSA_METHOD;
    engine : PENGINE;
  end;
{$ENDREGION}

{$REGION 'EVP'}

  PEVP_MD = ^EVP_MD;
  PEVP_PKEY_CTX = pointer;

  EVP_PKEY_union = record
    case byte of
      0: (ptr : PAnsiChar);
      1: (rsa : PRSA);    // RSA
      2: (dsa : PDSA);    // DSA
      3: (dh :PDH);       // DH
      4: (ec : PEC_KEY);  // ECC
  end;

  STACK_OF_X509_ATTRIBUTE = record
    _stack: STACK;
  end;
  PSTACK_OF_X509_ATTRIBUTE = ^STACK_OF_X509_ATTRIBUTE;


  PEVP_PKEY_ASN1_METHOD = pointer;
  PEVP_PKEY_METHOD = Pointer;

  PEVP_PKEY = ^EVP_PKEY;
  EVP_PKEY = record
    _type : TC_INT;
    save_type : TC_INT;
    references : TC_INT;
    ameth : PEVP_PKEY_ASN1_METHOD;
    pkey : EVP_PKEY_union;
    attributes : PSTACK_OF_X509_ATTRIBUTE;
  end;


  PEVP_CIPHER_CTX = ^EVP_CIPHER_CTX;
  PEVP_CIPHER = ^EVP_CIPHER;
  EVP_CIPHER = record
    nid : TC_Int;
    block_size : TC_Int;
    key_len : TC_Int;
    iv_len : TC_Int;
    flags : TC_UINT;
    init : function (ctx : PEVP_CIPHER_CTX; key : PAnsiChar; iv : PAnsiChar; enc : TC_Int): TC_Int; cdecl;
    do_cipher : function (ctx : PEVP_CIPHER_CTX; _out : PAnsiChar; _in : PAnsiChar; inl : size_t) : TC_Int; cdecl;
    cleanup : function (_para1 : PEVP_CIPHER_CTX): TC_Int; cdecl;
    ctx_size : TC_Int;
    set_asn1_parameters : function (_para1 : PEVP_CIPHER_CTX;
      _para2 : PASN1_TYPE) : TC_Int; cdecl;
    get_asn1_parameters :function (_para1 : PEVP_CIPHER_CTX;
      _para2 :  PASN1_TYPE) : TC_Int; cdecl;
    ctrl : function (_para1 : PEVP_CIPHER_CTX; _type : TC_Int; arg : TC_Int;
      ptr : Pointer): TC_Int; cdecl;
    app_data : Pointer;
  end;

  EVP_CIPHER_CTX = record
    cipher : PEVP_CIPHER;
    engine : PENGINE;
    encrypt: TC_INT;
    buf_len : TC_INT;
    oiv : array [0..EVP_MAX_IV_LENGTH-1] of AnsiChar;
    iv : array [0..EVP_MAX_IV_LENGTH -1] of AnsiChar;
    buf : array [0..EVP_MAX_BLOCK_LENGTH -1] of AnsiChar;
    num : TC_INT;
    app_data : Pointer;
    key_len : TC_INT;
    flags : TC_ULONG;
    cipher_data : Pointer;
    final_used : TC_INT;
    block_mask : TC_INT;
    _final : array [0..EVP_MAX_BLOCK_LENGTH-1] of AnsiChar;
  end;


  EVP_CIPHER_INFO = record
    cipher : PEVP_CIPHER;
    iv : array [0..EVP_MAX_IV_LENGTH -1] of AnsiChar;
  end;

  PEVP_MD_CTX = ^EVP_MD_CTX;
  EVP_MD_CTX = record
    digest : PEVP_MD;
    engine : PENGINE; // functional reference if 'digest' is ENGINE-provided
    flags : TC_ULONG;
    md_data : Pointer;
      pctx : PEVP_PKEY_CTX;
     update : function (ctx : PEVP_MD_CTX; const data : Pointer; count : size_t) : TC_INT cdecl;
  end;


  EVP_MD = record
    _type : TC_Int;
    pkey_type : TC_Int;
    md_size : TC_Int;
    flags : TC_ULONG;
    init : function (ctx : PEVP_MD_CTX) : TC_Int; cdecl;
    update : function (ctx : PEVP_MD_CTX; data : Pointer; count : size_t):TC_Int; cdecl;
    _final : function (ctx : PEVP_MD_CTX; md : PAnsiChar) : TC_Int; cdecl;
    copy : function (_to : PEVP_MD_CTX; from : PEVP_MD_CTX ) : TC_Int; cdecl;
    cleanup : function(ctx : PEVP_MD_CTX) : TC_Int; cdecl;
    sign : function(_type : TC_Int; m : PAnsiChar; m_length : TC_UINT;
      sigret : PAnsiChar; siglen : TC_UINT; key : Pointer) : TC_Int; cdecl;
    verify : function(_type : TC_Int; m : PAnsiChar; m_length : PAnsiChar;
      sigbuf : PAnsiChar; siglen : TC_UINT; key : Pointer) : TC_Int; cdecl;
    required_pkey_type : array [0..4] of TC_Int; // EVP_PKEY_xxx
    block_size : TC_Int;
    ctx_size : TC_Int; // how big does the ctx->md_data need to be
  end;

{$ENDREGION}



{$REGION 'X509'}
  PX509 = ^X509;
  PPX509 = ^PX509;
  PX509_REQ = ^X509_REQ;
  PX509_CRL = ^X509_CRL;
  PX509_NAME = ^X509_NAME;
  PX509_REQ_INFO = ^X509_REQ_INFO;
  PX509_POLICY_CACHE = Pointer;

  PSTACK_OF_X509_REVOKED = PSTACK_OF;
  PSTACK_OF_X509_NAME_ENTRY = PSTACK_OF;
  PSTACK_OF_X509 = PSTACK_OF;
  PSTACK_OF_X509_NAME = PSTACK_OF;

  X509_HASH_DIR_CTX = record
    num_dirs : TC_INT;
    dirs : PPAnsiChar;
    dirs_type : PC_INT;
    num_dirs_alloced : TC_INT;
  end;
  PX509_HASH_DIR_CTX = ^X509_HASH_DIR_CTX;

  X509_CERT_FILE_CTX = record
    num_paths : TC_INT;  // number of paths to files or directories
    num_alloced : TC_INT;
    paths : PPAnsiChar;  // the list of paths or directories
    path_type : TC_INT;
  end;
  PX509_CERT_FILE_CTX = ^X509_CERT_FILE_CTX;

  x509_object_union = record
    case byte of
      0: (ptr : PAnsiChar);
      1: (_x509 : Px509);
      2: (crl : PX509_CRL);
      3: (pkey : PEVP_PKEY);
  end;

  X509_OBJECT = record
    _type : TC_Int;
    data : x509_object_union;
  end;
  PX509_OBJECT  = ^X509_OBJECT;
  PPX509_OBJECT  = ^PX509_OBJECT;

  PSTACK_OF_X509_OBJECT = PSTACK;

  X509_ALGOR = record
    algorithm : PASN1_OBJECT;
    parameter : PASN1_TYPE;
  end;
  PX509_ALGOR  = ^X509_ALGOR;
  PPX509_ALGOR =^PX509_ALGOR;

  PSTACK_OF_X509_ALGOR = PSTACK;
  PPSTACK_OF_X509_ALGOR = ^PSTACK_OF_X509_ALGOR;

  X509_VAL = record
    notBefore : PASN1_TIME;
    notAfter : PASN1_TIME;
  end;
  PX509_VAL = ^X509_VAL;
  PPX509_VAL =^PX509_VAL;

  X509_PUBKEY = record
    algor : PX509_ALGOR;
    public_key : PASN1_BIT_STRING;
    pkey : PEVP_PKEY;
  end;
  PX509_PUBKEY = ^X509_PUBKEY;
  PPX509_PUBKEY =^PX509_PUBKEY;

  X509_SIG = record
    algor : PX509_ALGOR;
    digest : PASN1_OCTET_STRING;
  end;
  PX509_SIG = X509_SIG;
  PPX509_SIG =^PX509_SIG;

  X509_NAME_ENTRY = record
    _object : PASN1_OBJECT;
    value : PASN1_STRING;
    _set : TC_Int;
    size : TC_Int;
  end;

  X509_NAME = record
    entries : PSTACK_OF_X509_NAME_ENTRY;
    modified : TC_Int;
    bytes : PBUF_MEM;
    hash : TC_ULONG;
  end;

  X509_EXTENSION = record
    _object : PASN1_OBJECT;
    critical : ASN1_BOOLEAN;
    value : PASN1_OCTET_STRING;
  end;
  PX509_EXTENSION = ^X509_EXTENSION;
  PPX509_EXTENSION =^PX509_EXTENSION;

  PSTACK_OF_X509_EXTENSION = PSTACK;
  PPSTACK_OF_X509_EXTENSION = ^PSTACK_OF_X509_EXTENSION;
  PX509_EXTENSIONS = PPSTACK_OF_X509_EXTENSION;

  x509_attributes_union = record
    case Byte of
      $FF :(Ptr : PAnsiChar);
      0 : (_set: PSTACK_OF_ASN1_TYPE); // 0
      1  : (_single: PASN1_TYPE);
  end;

  X509_ATTRIBUTE = record
    _object : PASN1_OBJECT;
    single : TC_Int;
    value : x509_attributes_union;
  end;
  PX509_ATTRIBUTE = ^X509_ATTRIBUTE;
  PPX509_ATTRIBUTE = ^PX509_ATTRIBUTE;

  X509_REQ_INFO = record
    enc: ASN1_ENCODING;
    version: PASN1_INTEGER;
    subject: PX509_NAME;
    pubkey: PX509_PUBKEY;
    attributes: PSTACK_OF_X509_ATTRIBUTE; // [ 0 ]
  end;

  X509_REQ = record
    req_info: PX509_REQ_INFO;
    sig_alg: PX509_ALGOR;
    signature: PASN1_BIT_STRING;
    references: TC_Int;
  end;
  PPX509_REQ = ^PX509_REQ;


  X509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: PX509_ALGOR;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
    key: PX509_PUBKEY;
    issuerUID: PASN1_BIT_STRING;
    subjectUID: PASN1_BIT_STRING;
    extensions: PSTACK_OF_X509_EXTENSION;
    enc : ASN1_ENCODING;
  end;
  PX509_CINF = ^X509_CINF;

  X509_CERT_AUX = record
    trust : PSTACK_OF_ASN1_OBJECT;
    reject : PSTACK_OF_ASN1_OBJECT;
    alias : PASN1_UTF8STRING;
    keyid : PASN1_OCTET_STRING;
    other : PSTACK_OF_X509_ALGOR;
  end;
  PX509_CERT_AUX = ^X509_CERT_AUX;

  X509 = record
    cert_info: PX509_CINF;
    sig_alg : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    valid : TC_Int;
    references : TC_Int;
    name : PAnsiChar;
    ex_data : CRYPTO_EX_DATA;
    ex_pathlen : TC_LONG;
    ex_pcpathlen : TC_LONG;
    ex_flags : TC_ULONG;
    ex_kusage : TC_ULONG;
    ex_xkusage : TC_ULONG;
    ex_nscert : TC_ULONG;
    skid : PASN1_OCTET_STRING;
    akid : PAUTHORITY_KEYID;
    policy_cache : PX509_POLICY_CACHE;
    rfc3779_addr : PSTACK_OF_IPAddressFamily;
    rfc3779_asid : PASIdentifiers;
    sha1_hash : array [0..SHA_DIGEST_LENGTH-1] of AnsiChar;
    aux : PX509_CERT_AUX;
  end;

  X509_CRL_INFO = record
    version : PASN1_INTEGER;
    sig_alg : PX509_ALGOR;
    issuer : PX509_NAME;
    lastUpdate : PASN1_TIME;
    nextUpdate : PASN1_TIME;
    revoked : PSTACK_OF_X509_REVOKED;
    extensions : PSTACK_OF_X509_EXTENSION; // [0]
    enc : ASN1_ENCODING;
  end;

  PX509_CRL_INFO     = ^X509_CRL_INFO;
  PPX509_CRL_INFO    =^PX509_CRL_INFO;
  PSTACK_OF_X509_CRL_INFO = PSTACK;
  PX509_LOOKUP = ^X509_LOOKUP;
  PSTACK_OF_X509_LOOKUP = PSTACK;
  PX509_VERIFY_PARAM = ^X509_VERIFY_PARAM;
  PX509_STORE_CTX = ^X509_STORE_CTX;
  PPX509_CRL = ^PX509_CRL;
  X509_STORE = record
    cache : TC_Int;
    objs : PSTACK_OF_X509_OBJECT;
    get_cert_methods : PSTACK_OF_X509_LOOKUP;
    param : PX509_VERIFY_PARAM;
    verify : function (ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    verify_cb : function (ok : TC_Int; ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    get_issuer : function (issuer : PPX509; ctx : PX509_STORE_CTX; x : PX509) : TC_Int; cdecl;
    check_issued : function (ctx : PX509_STORE_CTX; x : PX509; issuer : PX509) : TC_Int; cdecl;
    check_revocation : function (ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    get_crl : function (ctx : PX509_STORE_CTX; crl : PPX509_CRL; x : PX509) : TC_Int; cdecl;
    check_crl : function(ctx : PX509_STORE_CTX; crl : PX509_CRL) : TC_Int; cdecl;
    cert_crl : function(ctx : PX509_STORE_CTX; crl : PX509_CRL; x : PX509) : TC_Int; cdecl;
    cleanup : function(ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    ex_data : CRYPTO_EX_DATA;
    references : TC_Int;
  end;
  PX509_STORE = ^X509_STORE;
  X509_CRL = record
    crl : PX509_CRL_INFO;
    sig_alg : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    references : TC_Int;
  end;
  PSTACK_OF_X509_CRL = PSTACK;

  X509_LOOKUP_METHOD = record
    name : PAnsiChar;
    new_item : function (ctx : PX509_LOOKUP): TC_Int; cdecl;
    free : procedure (ctx : PX509_LOOKUP); cdecl;
    init : function(ctx : PX509_LOOKUP) : TC_Int; cdecl;
    shutdown : function(ctx : PX509_LOOKUP) : TC_Int; cdecl;
    ctrl: function(ctx : PX509_LOOKUP; cmd : TC_Int; const argc : PAnsiChar; argl : TC_LONG; out ret : PAnsiChar ) : TC_Int; cdecl;
    get_by_subject: function(ctx : PX509_LOOKUP; _type : TC_Int; name : PX509_NAME; ret : PX509_OBJECT ) : TC_Int; cdecl;
    get_by_issuer_serial : function(ctx : PX509_LOOKUP; _type : TC_Int; name : PX509_NAME; serial : PASN1_INTEGER; ret : PX509_OBJECT) : TC_Int; cdecl;
    get_by_fingerprint : function (ctx : PX509_LOOKUP; _type : TC_Int; bytes : PAnsiChar; len : TC_Int; ret : PX509_OBJECT): TC_Int; cdecl;
    get_by_alias : function(ctx : PX509_LOOKUP; _type : TC_Int; str : PAnsiChar; ret : PX509_OBJECT) : TC_Int; cdecl;
  end;
  PX509_LOOKUP_METHOD      = ^X509_LOOKUP_METHOD;
  PPX509_LOOKUP_METHOD     = ^PX509_LOOKUP_METHOD;

  X509_VERIFY_PARAM = record
    name : PAnsiChar;
    check_time : TC_time_t;
    inh_flags : TC_ULONG;
    flags : TC_ULONG;
    purpose : TC_Int;
    trust : TC_Int;
    depth : TC_Int;
    policies : PSTACK_OF_ASN1_OBJECT;
  end;
  PSTACK_OF_X509_VERIFY_PARAM = PSTACK;

  X509_LOOKUP = record
    init : TC_Int;
    skip : TC_Int;
    method : PX509_LOOKUP_METHOD;
    method_data : PAnsiChar;
    store_ctx : PX509_STORE;
  end;
  PPSTACK_OF_X509_LOOKUP = ^PSTACK_OF_X509_LOOKUP;

  X509_STORE_CTX = record
    ctx : PX509_STORE;
    current_method : TC_Int;
    cert : PX509;
    untrusted : PSTACK_OF_X509;
    crls : PSTACK_OF_X509_CRL;
    param : PX509_VERIFY_PARAM;
    other_ctx : Pointer;
    verify : function (ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    verify_cb : function (ok : TC_Int; ctx : PX509_STORE_CTX) : TC_Int; cdecl;
    get_issuer : function (var issuer : PX509; ctx : PX509_STORE_CTX; x : PX509) : TC_Int; cdecl;
    check_issued : function(ctx : PX509_STORE_CTX; x, issuer : PX509) : TC_Int; cdecl;
    check_revocation : function (ctx : PX509_STORE_CTX): TC_Int; cdecl;
    get_crl : function (ctx : PX509_STORE_CTX; var crl : X509_CRL; x : PX509): TC_Int; cdecl;
    check_crl : function (ctx : PX509_STORE_CTX; var crl : X509_CRL) : TC_Int; cdecl;
    cert_crl : function (ctx : PX509_STORE_CTX; crl : PX509_CRL; x : PX509) : TC_Int; cdecl;
    check_policy : function (ctx : PX509_STORE_CTX) : TC_Int;  cdecl;
    cleanup : function (ctx : PX509_STORE_CTX) : TC_Int;  cdecl;
  end;
  PX509_EXTENSION_METHOD   = Pointer;

  PX509_TRUST = ^X509_TRUST;
  X509_TRUST_check_trust = function(_para1 : PX509_TRUST; para2 : PX509; _para3 : TC_Int) : TC_Int; cdecl;
  X509_TRUST = record
    trust : TC_Int;
    flags : TC_Int;
    check_trust : X509_TRUST_check_trust;
    name : PAnsiChar;
    arg1 : TC_Int;
    arg2 : Pointer;
  end;
  PPX509_TRUST = ^PX509_TRUST;
  PSTACK_OF_509_TRUST = PSTACK;

  X509_REVOKED = record
    serialNumber: PASN1_INTEGER;
    revocationDate: PASN1_TIME;
    extensions: PSTACK_OF_X509_EXTENSION;
    sequence: TC_Int;
  end;
  PX509_REVOKED      = ^X509_REVOKED;
  PPX509_REVOKED     =^PX509_REVOKED;

  PX509_PKEY       = Pointer;
  PPX509_PKEY      =^PX509_PKEY;

  X509_INFO = record
    x509 : PX509;
    crl : PX509_CRL;
    x_pkey : PX509_PKEY;
    enc_cipher: EVP_CIPHER_INFO;
    enc_len: TC_Int;
    enc_data: PAnsiChar;
    references: TC_Int;
  end;
  PX509_INFO       = ^X509_INFO;
  PPX509_INFO      =^PX509_INFO;
  PSTACK_OF_X509_INFO = PSTACK;

  NETSCAPE_SPKAC = record
    pubkey : PX509_PUBKEY;
    challenge : PASN1_IA5STRING;
  end;
  PNETSCAPE_SPKAC = ^NETSCAPE_SPKAC;
  PPNETSCAPE_SPKAC = ^PNETSCAPE_SPKAC;

  NETSCAPE_SPKI = record
    spkac : PNETSCAPE_SPKAC;
    sig_algor : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
  end;
  PNETSCAPE_SPKI = ^NETSCAPE_SPKI;
  PPNETSCAPE_SPKI = ^PNETSCAPE_SPKI;

  NETSCAPE_CERT_SEQUENCE = record
    _type : PASN1_OBJECT;
    certs : PSTACK_OF_X509;
  end;
  PNETSCAPE_CERT_SEQUENCE = ^NETSCAPE_CERT_SEQUENCE;
  PPNETSCAPE_CERT_SEQUENCE = ^PNETSCAPE_CERT_SEQUENCE;

{$ENDREGION}

{$REGION 'X509V3}

  X509V3_CONF_METHOD = record
    get_string : function(db : Pointer; section, value : PAnsiChar) : PAnsiChar; cdecl;
    get_section : function(db : Pointer; section : PAnsiChar) : PSTACK_OF_CONF_VALUE; cdecl;
    free_string : procedure(db : Pointer; _string : PAnsiChar); cdecl;
    free_section : procedure (db : Pointer; section : PSTACK_OF_CONF_VALUE);
  end;

  V3_EXT_CTX = record
    flags : TC_INT;
    issuer_cert : PX509;
    subject_cert : PX509;
    subject_req : PX509_REQ;
    crl : PX509_CRL;
    db_meth : X509V3_CONF_METHOD;
    db : Pointer;
  end;

  X509V3_CTX = V3_EXT_CTX;
  PX509V3_CTX = ^X509V3_CTX;

{$ENDREGION}

{$REGION 'PEM'}
type
    pem_password_cb = function(buf: PAnsiChar; size: TC_INT; rwflag: TC_INT; userdata: pointer): integer; cdecl;

{$ENDREGION}

{$REGION 'PKCS7'}
type
  PPKCS7 = ^PKCS7;
  PSTACK_OF_PKCS7_SIGNER_INFO = PSTACK;
  PSTACK_OF_PKCS7_RECIP_INFO = PSTACK;

  PKCS7_SIGNED = record
    version : PASN1_INTEGER;
    md_algs : PSTACK_OF_X509_ALGOR;
    cert : PSTACK_OF_X509;
    crl : PSTACK_OF_X509_CRL;
    signer_info : PSTACK_OF_PKCS7_SIGNER_INFO;
    contents : PPKCS7;
  end;
  PPKCS7_SIGNED = ^PKCS7_SIGNED;

  PKCS7_ENC_CONTENT = record
    content_type : PASN1_OBJECT;
    algorithm : PX509_ALGOR;
    enc_data : PASN1_OCTET_STRING;
    cipher : PEVP_CIPHER;
  end;
  PPKCS7_ENC_CONTENT = ^PKCS7_ENC_CONTENT;

  PKCS7_ENVELOPE = record
    version : PASN1_INTEGER;
    recipientinfo : PSTACK_OF_PKCS7_RECIP_INFO;
    enc_data : PPKCS7_ENC_CONTENT;
  end;
  PPKCS7_ENVELOPE = ^PKCS7_ENVELOPE;

  PKCS7_SIGN_ENVELOPE = record
    version : PASN1_INTEGER;
    md_algs : PSTACK_OF_X509_ALGOR;
    cert : PSTACK_OF_X509;
    crl : PSTACK_OF_X509_CRL;
    signer_info : PSTACK_OF_PKCS7_SIGNER_INFO;
    enc_data : PPKCS7_ENC_CONTENT;
    recipientinfo : PSTACK_OF_PKCS7_RECIP_INFO;
  end;
  PPKCS7_SIGN_ENVELOPE = ^PKCS7_SIGN_ENVELOPE;

  PKCS7_DIGEST = record
    version : PASN1_INTEGER;
    md : PX509_ALGOR;
    contents : PPKCS7;
    digest : PASN1_OCTET_STRING;
  end;
  PPKCS7_DIGEST = ^PKCS7_DIGEST;

  PKCS7_ENCRYPT = record
    version : PASN1_INTEGER;
    enc_data : PPKCS7_ENC_CONTENT;
  end;
  PPKCS7_ENCRYPT = ^PKCS7_ENCRYPT;

  PKCS7_union = record
    case Integer of
      0 : (ptr : PAnsiChar);
      1 : (data : PASN1_OCTET_STRING);
      2 : (sign : PPKCS7_SIGNED);
      3 : (enveloped : PPKCS7_ENVELOPE);
      4 : (signed_and_enveloped : PPKCS7_SIGN_ENVELOPE);
      5 : (digest : PPKCS7_DIGEST);
      6 : (encrypted : PPKCS7_ENCRYPT);
  end;

  PKCS7 = record
    asn1 : PAnsiChar;
    length : TC_LONG;
    state : TC_INT;
    detached : TC_INT;
    _type : PASN1_OBJECT;
    d : PKCS7_union;
  end;
{$ENDREGION}

{$REGION 'AES'}

type
  AES_KEY = record
{$IFDEF AES_LONG}
    rd_key: array[0..(4*(AES_MAXNR + 1))-1] of TC_ULONG;
{$ELSE}
    rd_key: array[0..(4*(AES_MAXNR + 1))-1] of TC_UINT;
{$ENDIF}
   rounds: TC_INT;
  end;
  PAES_KEY = ^AES_KEY;

  aes_buf = array[0..AES_BLOCK_SIZE-1] of Char;

{$ENDREGION}

{$REGION 'BLOWFISH'}

type
  BF_KEY = record
    P: array [0..BF_ROUNDS+1] of BF_LONG;
    S: array [0..(4*256)-1] of BF_LONG;
  end;
  PBF_KEY = ^BF_KEY;

{$ENDREGION}

{$REGION 'CMAX'}

type
  CMAC_CTX = record
    cctx: EVP_CIPHER_CTX;
    k1: array[0..EVP_MAX_BLOCK_LENGTH - 1] of TC_UCHAR;
    k2: array[0..EVP_MAX_BLOCK_LENGTH - 1] of TC_UCHAR;
    tbl: array[0..EVP_MAX_BLOCK_LENGTH - 1] of TC_UCHAR;
    last_block: array[0..EVP_MAX_BLOCK_LENGTH - 1] of TC_UCHAR;
    nlast_block: TC_INT;
  end;
  PCMAC_CTX = ^CMAC_CTX;

{$ENDREGION}

{$REGION 'CMS'}

type
  STACK_OF_CMS_SignerInfo = STACK_OF;
  PSTACK_OF_CMS_SignerInfo = ^STACK_OF_CMS_SignerInfo;

  STACK_OF_CMS_CertificateChoices = STACK_OF;
  PSTACK_OF_CMS_CertificateChoices = ^STACK_OF_CMS_CertificateChoices;

  STACK_OF_CMS_RevocationInfoChoice = STACK_OF;
  PSTACK_OF_CMS_RevocationInfoChoice = ^STACK_OF_CMS_RevocationInfoChoice;

  STACK_OF_CMS_RecipientInfo = STACK_OF;
  PSTACK_OF_CMS_RecipientInfo = ^STACK_OF_CMS_RecipientInfo;

  STACK_OF_CMS_RecipientEncryptedKey = STACK_OF;
  PSTACK_OF_CMS_RecipientEncryptedKey = ^STACK_OF_CMS_RecipientEncryptedKey;

  PCMS_EncapsulatedContentInfo = ^CMS_EncapsulatedContentInfo;
  CMS_EncapsulatedContentInfo = record
    eContentType: PASN1_OBJECT;
    eContent : PASN1_OCTET_STRING;
    partial: TC_INT;
  end;

  CMS_SignedData = record
   version: TC_LONG;
   digestAlgoritm: PSTACK_OF;
   encapContentInfo: PCMS_EncapsulatedContentInfo;
   certificates: PSTACK_OF_CMS_CertificateChoices;
   signerInfos: PSTACK_OF_CMS_SignerInfo;
  end;
  PCMS_SignedData = ^CMS_SignedData;

  PCMS_OriginatorInfo = ^CMS_OriginatorInfo;
  CMS_OriginatorInfo = record
     certificates: PSTACK_OF_CMS_CertificateChoices;
     crls: PSTACK_OF_CMS_RevocationInfoChoice
  end;

  PCMS_EncryptedContentInfo = ^CMS_EncryptedContentInfo;
  CMS_EncryptedContentInfo = record
      contentType: PASN1_OBJECT;
      contentEncryptionAlgorithm: PX509_ALGOR;
      encryptedContent: PASN1_OCTET_STRING;
      cipher: PEVP_CIPHER;
    key: PAnsiChar;
      keylen: TC_SIZE_T;
      debug: TC_INT;
    end;

  PCMS_EnvelopedData = ^CMS_EnvelopedData;
  CMS_EnvelopedData = record
      version: TC_LONG;
    originatorInfo: PCMS_OriginatorInfo;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
      encryptedContentInfo: PCMS_EncryptedContentInfo;
    unprotectedAttrs: PSTACK_OF_X509_ATTRIBUTE
  end;

  PCMS_DigestedData = ^CMS_DigestedData;
  CMS_DigestedData = record
      version: TC_LONG;
      digestAlgorithm: PX509_ALGOR;
      encapContentInfo: PCMS_EncapsulatedContentInfo;
      digest: PASN1_OCTET_STRING;
  end;

  PCMS_EncryptedData = ^CMS_EncryptedData;
  CMS_EncryptedData = record
    version: TC_LONG;
    encryptedContentInfo: PCMS_EncryptedContentInfo;
    unprotectedAttrs: PSTACK_OF_X509_ATTRIBUTE
  end;

  PCMS_AuthenticatedData = ^CMS_AuthenticatedData;
  CMS_AuthenticatedData = record
    version: TC_LONG;
      originatorInfo: PCMS_OriginatorInfo;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
    macAlgorithm: PX509_ALGOR;
      digestAlgorithm: PX509_ALGOR;
      encapContentInfo: PCMS_EncapsulatedContentInfo;
      authAttrs: PSTACK_OF_X509_ATTRIBUTE;
      mac: PASN1_OCTET_STRING;
      unauthAttrs: PSTACK_OF_X509_ATTRIBUTE;
  end;

  PCMS_CompressedData = ^CMS_CompressedData;
  CMS_CompressedData = record
    version: TC_LONG;
    compressionAlgorithm: PX509_ALGOR;
    recipientInfos: PSTACK_OF_CMS_RecipientInfo;
    encapContentInfo: PCMS_EncapsulatedContentInfo;
  end;

  CMS_ContentInfo_union = record
    data: PASN1_OCTET_STRING;
    signedData: PCMS_SignedData;
        envelopedData: PCMS_EnvelopedData;
        digestedData: PCMS_DigestedData;
        encryptedData: PCMS_EncryptedData;
        authenticatedData: PCMS_AuthenticatedData;
        compressedData: PCMS_CompressedData;
        other: PASN1_TYPE;
        otherData: Pointer;
  end;

  PCMS_ContentInfo = ^CMS_ContentInfo;
  CMS_ContentInfo = record
     contentType: PASN1_OBJECT;
     d: CMS_ContentInfo_union;
  end;

  PCMS_IssuerAndSerialNumber = ^CMS_IssuerAndSerialNumber;
  CMS_IssuerAndSerialNumber = record
      issuer: PX509_NAME;
    serialNumber: PASN1_INTEGER;
  end;

   CMS_SignerIdentifier_union = record
        issuerAndSerialNumber: PCMS_IssuerAndSerialNumber;
        subjectKeyIdentifier: PASN1_OCTET_STRING;
   end;

   PCMS_SignerIdentifier = ^CMS_SignerIdentifier;
   CMS_SignerIdentifier = record
       _type: TC_INT;
     d: CMS_SignerIdentifier_union;
   end;
   PCMS_RecipientIdentifier = ^CMS_RecipientIdentifier;
   CMS_RecipientIdentifier = CMS_SignerIdentifier;

   CMS_SignerInfo = record
     version: TC_LONG;
     sid: PCMS_SignerIdentifier;
     digestAlgorithm: PX509_ALGOR;
     signedAttrs: PSTACK_OF_X509_ATTRIBUTE;
     signatureAlgorithm: PX509_ALGOR;
     signature: PASN1_OCTET_STRING;
     unsignedAttrs: PSTACK_OF_X509_ATTRIBUTE;
     signer: PX509;
     pkey: PEVP_PKEY;
   end;

  PCMS_KeyTransRecipientInfo = ^CMS_KeyTransRecipientInfo;
  CMS_KeyTransRecipientInfo = record
    version: TC_LONG;
    rid: PCMS_RecipientIdentifier;
    keyEncryptionAlgorithm: PX509_ALGOR;
    encryptedKey: PASN1_OCTET_STRING;
    recip: PX509;
    pkey: EVP_PKEY;
  end;

  PCMS_OriginatorPublicKey = ^CMS_OriginatorPublicKey;
  CMS_OriginatorPublicKey = record
    algorithm: PX509_ALGOR;
    publicKey: PASN1_BIT_STRING;
  end;

  PCMS_OtherKeyAttribute= ^CMS_OtherKeyAttribute;
  CMS_OtherKeyAttribute = record
    keyAttrId: ASN1_OBJECT;
    keyAttr: ASN1_TYPE;
  end;


  PCMS_RecipientKeyIdentifier = ^CMS_RecipientKeyIdentifier;
  CMS_RecipientKeyIdentifier = record
    subjectKeyIdentifier: PASN1_OCTET_STRING;
    date: PASN1_GENERALIZEDTIME;
    other: PCMS_OtherKeyAttribute;
  end;

  CMS_KeyAgreeRecipientIdentifier_union = record
    issuerAndSerialNumber: PCMS_IssuerAndSerialNumber;
    rKeyId: PCMS_RecipientKeyIdentifier;
  end;

  PCMS_KeyAgreeRecipientIdentifier = ^CMS_KeyAgreeRecipientIdentifier;
  CMS_KeyAgreeRecipientIdentifier = record
       _type: TC_INT;
     d: CMS_KeyAgreeRecipientIdentifier_union;
  end;


  PCMS_RecipientEncryptedKey = ^CMS_RecipientEncryptedKey;
  CMS_RecipientEncryptedKey = record
    rid: PCMS_KeyAgreeRecipientIdentifier;
    encryptedKey: PASN1_OCTET_STRING;
  end;


  CMS_OriginatorIdentifierOrKey_union = record
    issuerAndSerialNumber: PCMS_IssuerAndSerialNumber;
    subjectKeyIdentifier: PASN1_OCTET_STRING;
    originatorKey: PCMS_OriginatorPublicKey;
  end;

  PCMS_OriginatorIdentifierOrKey = ^CMS_OriginatorIdentifierOrKey;
  CMS_OriginatorIdentifierOrKey = record
       _type: TC_INT;
     d: CMS_OriginatorIdentifierOrKey_union;
  end;

  PCMS_KeyAgreeRecipientInfo = ^CMS_KeyAgreeRecipientInfo;
  CMS_KeyAgreeRecipientInfo = record
    version: TC_LONG;
    originator: PCMS_OriginatorIdentifierOrKey;
    ukm: PASN1_OCTET_STRING;
    keyEncryptionAlgorithm: PX509_ALGOR;
    recipientEncryptedKeys: PSTACK_OF_CMS_RecipientEncryptedKey;
  end;

  PCMS_KEKIdentifier = ^CMS_KEKIdentifier;
  CMS_KEKIdentifier = record
    keyIdentifier: PASN1_OCTET_STRING;
    date: PASN1_GENERALIZEDTIME;
    other: PCMS_OtherKeyAttribute;
  end;

  PCMS_KEKRecipientInfo = ^CMS_KEKRecipientInfo;
  CMS_KEKRecipientInfo = record
    version: TC_LONG;
    kekid: CMS_KEKIdentifier;
    keyEncryptionAlgorithm: PX509_ALGOR;
    encryptedKey: PASN1_OCTET_STRING;
    key: PAnsiChar;
    keylen: TC_SIZE_T;
  end;

  PCMS_PasswordRecipientInfo = ^CMS_PasswordRecipientInfo;
  CMS_PasswordRecipientInfo = record
    version: TC_LONG;
    keyDerivationAlgorithm: PX509_ALGOR;
    keyEncryptionAlgorithm: PX509_ALGOR;
    encryptedKey: PASN1_OCTET_STRING;
    pass: PAnsiChar;
    passlen: TC_SIZE_T;
  end;

  PCMS_OtherRecipientInfo = ^CMS_OtherRecipientInfo;
  CMS_OtherRecipientInfo = record
    oriType: ASN1_OBJECT;
    oriValue: ASN1_TYPE;
  end;

    CMS_RecipientInfo_union = record
    ktri: PCMS_KeyTransRecipientInfo;
    kari: PCMS_KeyAgreeRecipientInfo;
    kekri: PCMS_KEKRecipientInfo;
    pwri: PCMS_PasswordRecipientInfo;
    ori: PCMS_OtherRecipientInfo;
  end;

  PCMS_RecipientInfo = ^CMS_RecipientInfo;
  CMS_RecipientInfo = record
      _type: TC_INT;
    d: CMS_RecipientInfo_union;
  end;

  PCMS_OtherRevocationInfoFormat = ^CMS_OtherRevocationInfoFormat;
  CMS_OtherRevocationInfoFormat = record
    otherRevInfoFormat: PASN1_OBJECT;
    otherRevInfo: PASN1_TYPE;
  end;

  CMS_RevocationInfoChoice_union = record
    crl: PX509_CRL;
    other: PCMS_OtherRevocationInfoFormat;
  end;

  PCMS_RevocationInfoChoice = ^CMS_RevocationInfoChoice;
  CMS_RevocationInfoChoice = record
      _type: TC_INT;
      d:CMS_RevocationInfoChoice_union;
  end;

  PCMS_OtherCertificateFormat = ^CMS_OtherCertificateFormat;
  CMS_OtherCertificateFormat = record
    otherCertFormat: PASN1_OBJECT;
    otherCert: PASN1_TYPE;
  end;

  CMS_CertificateChoices_union = record
    certificate: PX509;
    extendedCertificate: PASN1_STRING;
    v1AttrCert: PASN1_STRING;
    v2AttrCert: PASN1_STRING;
    other: PCMS_OtherCertificateFormat;
  end;

  PCMS_CertificateChoices = ^CMS_CertificateChoices;
  CMS_CertificateChoices = record
    _type: TC_INT;
    d:CMS_CertificateChoices_union;
  end;

{$ENDREGION}

{$REGION 'DES'}

type
  DES_cblock = array[0..7] of TC_UCHAR;
  const_DES_cblock = array[0..7] of TC_UCHAR;

  DES_key_schedule_union = record
     cblock: DES_cblock;
     deslong: array[0..1] of DES_LONG;
  end;

  PDES_key_schedule = ^DES_key_schedule;
  DES_key_schedule = record
    ks: array[0..15] of DES_key_schedule_union;
  end;

{$ENDREGION}


{$REGION 'ENGINE'}
type
  ENGINE_CB_FUNC = procedure;
  ENGINE_GEN_FUNC_PTR = function: TC_INT; cdecl;
  ENGINE_GEN_INT_FUNC_PTR = function(engine: PENGINE): TC_INT; cdecl;
  ENGINE_CTRL_FUNC_PTR = function(engine: PENGINE; _par1: TC_INT; _par2: TC_LONG; _par3: Pointer; f: ENGINE_CB_FUNC): TC_INT; cdecl;
  ENGINE_LOAD_KEY_PTR = function(engine: PENGINE; buf: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
  ENGINE_SSL_CLIENT_CERT_PTR = function(engine: PENGINE; ssl: PSSL; ca_dn: PSTACK_OF_X509_NAME; var cert: PX509; var key: PEVP_PKEY; var pother: PSTACK_OF_X509; ui_method: PUI_METHOD; callback_data: Pointer): TC_INT; cdecl;
  ENGINE_CIPHERS_PTR =  function(engine: PENGINE; var cipher: PEVP_CIPHER; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_DIGESTS_PTR = function(engine: PENGINE; var md: PEVP_MD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_PKEY_METHS_PTR = function(engine: PENGINE; var meth: PEVP_PKEY_METHOD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_PKEY_ASN1_METHS_PTR = function(engine: PENGINE; var meth: PEVP_PKEY_ASN1_METHOD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
{$ENDREGION}

{$REGION 'RAND'}

    PRAND_METHOD = ^RAND_METHOD;
    RAND_METHOD = record
        seed: procedure(buf: Pointer; num: TC_INT); cdecl;
        bytes: function(buf: PAnsiChar; num: TC_INT): TC_INT; cdecl;
        cleanup: procedure; cdecl;
        add: procedure(buf: Pointer;num: TC_INT;entropy: Double); cdecl;
        pseudorand: function(buf: PAnsiChar; num: TC_INT): TC_INT; cdecl;
        status: function: TC_INT; cdecl;
    end;


{$ENDREGION}

type
  PECDH_METHOD = Pointer;
  PECDSA_METHOD = Pointer;
  PSTORE_METHOD = Pointer;

{$REGION 'CAMELLIA'}
type
    KEY_TABLE_TYPE = array [0..CAMELLIA_TABLE_WORD_LEN-1] of TC_UINT;
    CAMELLIA_BUF = array[0..CAMELLIA_BLOCK_SIZE-1] of AnsiChar;
    CAMELLIA_KEY_union = record
        d: double;
        rd_key: KEY_TABLE_TYPE;
    end;
    
    PCAMELLIA_KEY = ^CAMELLIA_KEY;
    CAMELLIA_KEY = record
        u: CAMELLIA_KEY_union;
        grand_rounds: TC_INT;
    end;    
      
{$ENDREGION}  
  
{$REGION 'COMP'}
type
	PCOMP_CTX = ^COMP_CTX;
	PCOMP_METHOD = ^COMP_METHOD;
	COMP_METHOD = record
		_type: TC_INT;
		name: PAnsiChar;
		init: function(ctx: PCOMP_CTX): TC_INT; cdecl;
		finish: procedure(ctx: PCOMP_CTX); cdecl;
		compress: function(ctx: PCOMP_CTX; _out: PAnsiChar; olen: TC_UINT; _in: PAnsiChar; ilen: TC_UINT): TC_INT; cdecl;
		expand: function(ctx: PCOMP_CTX; _out: PAnsiChar; olen: TC_UINT; _in: PAnsiChar; ilen: TC_UINT): TC_INT; cdecl;
		ctrl: function: TC_LONG; cdecl;
		callback_ctrl: function: TC_LONG; cdecl;
	end;
	
	COMP_CTX = record
		meth: PCOMP_METHOD;
		compress_in: TC_ULONG;
		compress_out: TC_ULONG;
		expand_in: TC_ULONG;
		expand_out: TC_ULONG;
		ex_data: CRYPTO_EX_DATA;
	end;


{$ENDREGION}  
  
implementation

end.
