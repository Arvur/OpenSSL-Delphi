{$I ssl.inc}

unit ssl_types;

interface

uses
  {$IFDEF UNIX}BaseUnix,{$ENDIF}
  ssl_const;

type
    qword = UInt64;
    PVOID = Pointer;
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
    PDES_LONG = ^DES_LONG;
    point_conversion_form_t = byte;
    TC_OSSL_SSIZE_T = TC_LONG;
    IDEA_INT = TC_UINT;
    MD4_LONG = TC_ULONG;
    MD5_LONG = TC_ULONG;
    RC2_INT = TC_UINT;
    RC4_INT = TC_UINT;
    RC5_32_INT = TC_ULONG;
    RIPEMD160_LONG = TC_ULONG;
    SHA_LONG = TC_ULONG;
    SHA_LONG64 = UInt64;

type

  PX509_PUBKEY = ^X509_PUBKEY;
  PPKCS8_PRIV_KEY_INFO = ^PKCS8_PRIV_KEY_INFO;
  PPPKCS8_PRIV_KEY_INFO = ^PPKCS8_PRIV_KEY_INFO;

  PX509_ALGOR  = ^X509_ALGOR;
  PPX509_ALGOR =^PX509_ALGOR;
  PEVP_MD_CTX = ^EVP_MD_CTX;
  PPEVP_MD_CTX = ^PEVP_MD_CTX;

  PENGINE = ^ENGINE;
  PPENGINE = ^PENGINE;
  PRSA_METHOD = ^RSA_METHOD;
  PUI_METHOD = Pointer;
  PSSL = ^SSL;
  PEVP_PKEY = ^EVP_PKEY;
  PX509 = ^X509;
  PEVP_MD = ^EVP_MD;
  PPEVP_MD = ^PEVP_MD;
  PEVP_CIPHER = ^EVP_CIPHER;
  PPEVP_CIPHER = ^PEVP_CIPHER;
  PEVP_PKEY_METHOD = ^EVP_PKEY_METHOD;
  PPEVP_PKEY_METHOD = ^PEVP_PKEY_METHOD;
  PEVP_PKEY_ASN1_METHOD = ^EVP_PKEY_ASN1_METHOD;
  PPEVP_PKEY_ASN1_METHOD = ^PEVP_PKEY_ASN1_METHOD;


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
  PSTACK_OF_X509 = PSTACK_OF;
  PSTACK_OF_X509_NAME = PSTACK_OF;

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

  ENGINE_CB_FUNC = procedure;
  ENGINE_GEN_FUNC_PTR = function: TC_INT; cdecl;
  ENGINE_GEN_INT_FUNC_PTR = function(engine: PENGINE): TC_INT; cdecl;
  ENGINE_CTRL_FUNC_PTR = function(engine: PENGINE; _par1: TC_INT; _par2: TC_LONG; _par3: Pointer; f: ENGINE_CB_FUNC): TC_INT; cdecl;
  ENGINE_LOAD_KEY_PTR = function(engine: PENGINE; buf: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
  ENGINE_SSL_CLIENT_CERT_PTR = function(engine: PENGINE; ssl: PSSL; ca_dn: PSTACK_OF_X509_NAME; var cert: PX509; var key: PEVP_PKEY; var pother: PSTACK_OF_X509; ui_method: PUI_METHOD; callback_data: Pointer): TC_INT; cdecl;
  ENGINE_CIPHERS_PTR =  function(engine: PENGINE; cipher: PPEVP_CIPHER; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_DIGESTS_PTR = function(engine: PENGINE; md: PPEVP_MD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_PKEY_METHS_PTR = function(engine: PENGINE; meth: PPEVP_PKEY_METHOD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE_PKEY_ASN1_METHS_PTR = function(engine: PENGINE; meth: PPEVP_PKEY_ASN1_METHOD; var par1: PC_INT; par2: TC_INT): TC_INT; cdecl;
  ENGINE = record
    id: PAnsiChar;
    name: PAnsiChar;
    rsa_meth: PRSA_METHOD;
    dsa_meth: Pointer;
    dh_meth: Pointer;
    ecdh_meth: Pointer;
    ecdsa_meth: Pointer;
    rand_meth: Pointer;
    store_meth: Pointer;
    ciphers: ENGINE_CIPHERS_PTR;
    digests: ENGINE_DIGESTS_PTR;
    pkey_meths: ENGINE_PKEY_METHS_PTR;
    pkey_asn1_meths: ENGINE_PKEY_ASN1_METHS_PTR;
    _destroy: ENGINE_GEN_INT_FUNC_PTR;
    init: ENGINE_GEN_INT_FUNC_PTR;
    finish: ENGINE_GEN_INT_FUNC_PTR;
    ctrl: ENGINE_CTRL_FUNC_PTR;
    load_privkey: ENGINE_LOAD_KEY_PTR;
    load_pubkey: ENGINE_LOAD_KEY_PTR;
    load_ssl_client_cert: ENGINE_SSL_CLIENT_CERT_PTR;
    cmd_defns: PENGINE_CMD_DEFN;
    flags: TC_INT;
    struct_ref: TC_INT;
    funct_ref: TC_INT;
    ex_data: CRYPTO_EX_DATA;
    prev: PENGINE;
    next: PENGINE;
  end;

  BF_LONG = TC_ULONG;
  PBF_LONG = ^BF_LONG;

  BUF_MEM = record
    length : TC_SIZE_T;
    data : PAnsiChar;
    max: TC_SIZE_T;
  end;
  PBUF_MEM = ^BUF_MEM;

  POBJ_NAME = ^OBJ_NAME;
  OBJ_NAME = record
      _type: TC_INT;
    _alias: TC_INT;
      _name: PAnsiChar;
      _data: PAnsiChar;
  end;
  OBJ_NAME_CALLBACK = procedure(_par1: POBJ_NAME; arg: Pointer); cdecl;
  OBJ_CMP_CALLBACK = function(_par1, _par2: Pointer): TC_INT; cdecl;

  OBJ_hash_func = function(_par1: PAnsiChar): TC_ULONG; cdecl;
  OBJ_cmp_func = function(_par1: PAnsiChar; _par2: PAnsiChar): TC_INT; cdecl;
  OBJ_free_func = procedure(_par1: PAnsiChar; _par2: TC_INT; _par3: PAnsiChar); cdecl;

{$REGION 'CRYPTO'}

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

  CRYPTO_mem_alloc_func = function(_size: TC_SIZE_T): Pointer; cdecl;
  CRYPTO_mem_realloc_func = function(_mem: Pointer; _size: TC_SIZE_T): Pointer; cdecl;
  CRYPTO_mem_free_func = procedure(_mem: pointer); cdecl;

{$ENDREGION}


{$REGION 'ERR'}

  ERR_STATE = record
    tid: CRYPTO_THREADID;
    err_flags: array [0..ERR_NUM_ERRORS-1] of TC_INT;
    err_buffer: array[0..ERR_NUM_ERRORS-1] of TC_ULONG;
    err_data: array[0..ERR_NUM_ERRORS-1] of PAnsiChar;
    err_data_flags: array[0..ERR_NUM_ERRORS-1] of TC_INT;
    err_file: array[0..ERR_NUM_ERRORS-1] of PAnsiChar;
    err_line: array[0..ERR_NUM_ERRORS-1] of TC_INT;
    top,bottom: TC_INT;
  end;
  PERR_STATE = ^ERR_STATE;

  ERR_STRING_DATA = record
      error: TC_LONG;
      _string: PAnsiChar;
  end;
  PERR_STRING_DATA = ^ERR_STRING_DATA;

  ERR_CALLBACK = function(str: PAnsiChar; len: TC_SIZE_T; u: Pointer): TC_INT; cdecl;
  PERR_FNS = Pointer;

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
  PPBIGNUM = ^PBIGNUM;
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
  PPBN_MONT_CTX = ^PBN_MONT_CTX;

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

  PEC_GROUP = ^EC_GROUP;
  PPEC_GROUP = ^PEC_GROUP;

  PEC_METHOD = ^EC_METHOD;

  PEC_POINT = ^EC_POINT;
  EC_POINT = record
    meth: PEC_METHOD;
    X: BIGNUM;
    Y: BIGNUM;
    Z: BIGNUM;
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
  PPEC_EXTRA_DATA = ^PEC_EXTRA_DATA;
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
    order, cofactor: BIGNUM;
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
  PPEC_KEY = ^PEC_KEY;
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

  PEC_PKEY_CTX = ^EC_PKEY_CTX;
  PPEC_PKEY_CTX = ^PEC_PKEY_CTX;
  EC_PKEY_CTX = record
      gen_group: PEC_GROUP;
      md: PEVP_MD;
  end;

  EC_dup_func = function(par: Pointer): Pointer; cdecl;
  EC_free_func = procedure(par: Pointer); cdecl;
  EC_clear_free_func = procedure(par: Pointer); cdecl;


{$ENDREGION}


  PSTACK_OF_IPAddressFamily = PSTACK;
  PSTACK_OF_ASN1_TYPE = PSTACK; // may be ^
  PSTACK_OF_ASN1_OBJECT = PSTACK;
  PSTACK_OF_ASN1_INTEGER = PSTACK_OF;
  PSTACK_OF_GENERAL_NAME = PSTACK;
  PGENERAL_NAMES = PSTACK_OF_GENERAL_NAME;
  PPGENERAL_NAMES = ^PGENERAL_NAMES;
  PSTACK_OF_GENERAL_NAMES = PSTACK_OF;
  PPSTACK_OF_GENERAL_NAMES = ^PSTACK_OF_GENERAL_NAMES;
  PSTACK_OF_ASIdOrRange = PSTACK;
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;
  PSTACK_OF_CONF_VALUE = PSTACK;
  PPSTACK_OF_CONF_VALUE = ^PSTACK_OF_CONF_VALUE;



  BIT_STRING_BITNAME = record
    bitnum : TC_INT;
    lname : PAnsiChar;
    sname : PAnsiChar;
  end;
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;


{$REGION 'BIO'}
  PBIO = ^BIO;
  PPBIO = ^PBIO;
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
  PPASN1_OBJECT = ^PASN1_OBJECT;

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
  PPASN1_ENUMERATED = ^PASN1_ENUMERATED;
  ASN1_BIT_STRING = ASN1_STRING;
  PASN1_BIT_STRING = ^ASN1_BIT_STRING;
  PPASN1_BIT_STRING = ^PASN1_BIT_STRING;
  ASN1_OCTET_STRING = ASN1_STRING;
  PASN1_OCTET_STRING = ^ASN1_OCTET_STRING;
  PPASN1_OCTET_STRING = ^PASN1_OCTET_STRING;
  ASN1_PRINTABLESTRING = ASN1_STRING;
  PASN1_PRINTABLESTRING = ^ASN1_PRINTABLESTRING;
  PPASN1_PRINTABLESTRING = ^PASN1_PRINTABLESTRING;
  ASN1_T61STRING = ASN1_STRING;
  PASN1_T61STRING = ^ASN1_T61STRING;
  PPASN1_T61STRING = ^PASN1_T61STRING;
  ASN1_IA5STRING = ASN1_STRING;
  PASN1_IA5STRING = ^ASN1_IA5STRING;
  PPASN1_IA5STRING = ^PASN1_IA5STRING;
  ASN1_GENERALSTRING = ASN1_STRING;
  PASN1_GENERALSTRING = ^ASN1_GENERALSTRING;
  PPASN1_GENERALSTRING = ^PASN1_GENERALSTRING;
  ASN1_UTCTIME = ASN1_STRING;
  PASN1_UTCTIME = ^ASN1_UTCTIME;
  PPASN1_UTCTIME = ^PASN1_UTCTIME;
  ASN1_GENERALIZEDTIME = ASN1_STRING;
  PASN1_GENERALIZEDTIME = ^ASN1_GENERALIZEDTIME;
  PPASN1_GENERALIZEDTIME = ^PASN1_GENERALIZEDTIME;
  ASN1_TIME = ASN1_STRING;
  PASN1_TIME = ^ASN1_TIME;
  PPASN1_TIME = ^PASN1_TIME;

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
  PPASN1_TYPE = ^PASN1_TYPE;

  AUTHORITY_KEYID = record
    keyid : PASN1_OCTET_STRING;
    issuer : PGENERAL_NAMES;
    serial : PASN1_INTEGER;
  end;
  PAUTHORITY_KEYID = ^AUTHORITY_KEYID;
  PPAUTHORITY_KEYID = ^PAUTHORITY_KEYID;

  PASRange = ^ASRange;
  ASRange = record
    min, max: PASN1_INTEGER;
  end;

  ASIdOrRange_union = record
  case byte of
    0: (id: PASN1_INTEGER);
    1: (range: PASRange);
  end;

  PASIdOrRange = ^ASIdOrRange;
  ASIdOrRange = record
    _type: TC_INT;
    u: ASIdOrRange_union;
  end;

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

  PIPAddressRange = ^IPAddressRange;
  IPAddressRange = record
    min, max: PASN1_BIT_STRING;
  end;

  IPAddressOrRange_union = record
  case byte of
    0: (addressPrefix: PASN1_BIT_STRING);
    1: (addressRange: PIPAddressRange);
  end;

  PIPAddressOrRange = ^IPAddressOrRange;
  IPAddressOrRange = record
    _type: TC_INT;
    u: IPAddressOrRange_union;
  end;

  PSTACK_OF_IPAddressOrRange = PSTACK_OF;
  PIPAddressOrRanges = PSTACK_OF_IPAddressOrRange;

  IPAddressChoice_union = record
  case byte of
    0: (inherit: PASN1_NULL);
    1: (addressesOrRanges: PIPAddressOrRanges);
  end;

  PIPAddressChoice = ^IPAddressChoice;
  IPAddressChoice = record
    _type: TC_INT;
    u: IPAddressChoice_union;
  end;

  PIPAddressFamily = ^IPAddressFamily;
  IPAddressFamily = record
    addressFamily: PASN1_OCTET_STRING;
    ipAddressChoice: PIPAddressChoice;
  end;

  PIPAddrBlocks = PSTACK_OF_IPAddressFamily;

  ASN1_CTX = record
    p : PAnsiChar;   // work char pointer
    eos : TC_INT;    // end of sequence read for indefinite encoding
    error : TC_INT;  // error code to use when returning an error
    inf : TC_INT;    // constructed if 0x20; indefinite is 0x21
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

  void_func = function: pointer;
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
    tag : TC_LONG;            // tag; not used if no tagging
    offset : TC_ULONG;        // Offset of this field in structure
    field_name : PAnsiChar;   // Field name
    item : PASN1_ITEM_EXP;    // Relevant ASN1_ITEM or ASN1_ADB
  end;

  PASN1_TEMPLATE = ^ASN1_TEMPLATE;
  ASN1_ITEM = record
    itype : Char;               // The item type; primitive; SEQUENCE; CHOICE or extern
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
  PPASN1_VALUE = ^PASN1_VALUE;

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

  LHASH_COMP_FN_TYPE = function (const p1;p2 : Pointer) : TC_INT; cdecl;
  LHASH_HASH_FN_TYPE = function(const p1 : Pointer) : TC_ULONG; cdecl;
    LHASH_DOALL_FN_TYPE = procedure(_p: pointer); cdecl;
    LHASH_DOALL_ARG_FN_TYPE = procedure(_p1, _p2: Pointer); cdecl;

  LHASH = record
    b : PPLHASH_NODE;
    comp : LHASH_COMP_FN_TYPE;
    hash : LHASH_HASH_FN_TYPE;
    num_nodes : TC_UINT;
    num_alloc_nodes : TC_UINT;
    p : TC_UINT;
    pmax : TC_UINT;
    up_load : TC_ULONG; 
    down_load : TC_ULONG; 
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
  PLHASH = ^LHASH;
  _LHASH = LHASH;
  P_LHASH = ^_LHASH;

  PLHASH_OF = ^LHASH_OF;
  PPLHASH_OF = ^PLHASH_OF;
  LHASH_OF = record
    dummy: TC_INT;
  end; { record }

{$ENDREGION}

{$REGION 'CONF'}
  CONF_VALUE = record
    section : PAnsiChar;
    name : PAnsiChar;
    value : PAnsiChar;
  end;
  PCONF_VALUE = ^CONF_VALUE;
  PLHASH_OF_CONF_VALUE = PLHASH;

  PCONF_METHOD = ^CONF_METHOD;
  PCONF_IMODULE = ^CONF_IMODULE;
  PCONF_MODULE = ^CONF_MODULE;
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
 
  t_list_cb = function(const  _elem: PAnsiChar; _len: TC_INT; usr: Pointer): TC_INT; cdecl;
  t_conf_init_func = function(md: PCONF_IMODULE; const cnf: PCONF): TC_INT; cdecl;
  t_conf_finish_func = procedure(md: PCONF_IMODULE); cdecl;

  CONF_MODULE = record
    dso: Pointer;
     _name: PAnsiChar;
    init: t_conf_init_func; 
    finish: t_conf_finish_func;
    _links: TC_INT;
    usr_data: Pointer;
  end;
  
  CONF_IMODULE = record
	pmod: PCONF_MODULE;
	 _name: PAnsiChar;
	 _value: PAnsiChar;
	s: TC_ULONG;
	usr_data: Pointer;
  end;  
  
  
{$ENDREGION}

{$REGION 'DH'}

  DH_Callback = procedure(_par1: TC_INT;_par2: TC_INT; _par3: Pointer); cdecl;
  PDH = ^DH;
  PPDH = ^PDH;

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

  PRSA = ^RSA;
  PPRSA = ^PRSA;
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

  PRSA_PKEY_CTX = ^RSA_PKEY_CTX;
  RSA_PKEY_CTX = record
      nbits: TC_INT;
      pub_exp: PBIGNUM;
      gentmp: array[0..1] of TC_INT;
      pad_mode: TC_INT;
      md: PEVP_MD;
      mgf1md: PEVP_MD;
      saltlen: TC_INT;
      tbuf: PAnsiChar;
  end;

  PRSA_PSS_PARAMS = ^RSA_PSS_PARAMS;
  PPRSA_PSS_PARAMS = ^PRSA_PSS_PARAMS;

  RSA_PSS_PARAMS = record
    _hashAlgorithm: PX509_ALGOR;
    _maskGenAlgorithm: PX509_ALGOR;
    _saltLength: PASN1_INTEGER;
    _trailerField: PASN1_INTEGER;
  end; { record }

  RSA_NET_CALLBACK_FUNC = function (_buf: PAnsiChar; _len: TC_INT; const _prompt: PAnsiChar; _verify: TC_INT): TC_INT; cdecl;
{$ENDREGION}


{$REGION 'DSA'}
  PDSA = ^DSA;
  PPDSA = ^PDSA;
  DSA_SIG = record
    r : PBIGNUM;
    s : PBIGNUM;
  end;
  PDSA_SIG = ^DSA_SIG;
  PPDSA_SIG = ^PDSA_SIG;

  DSA_METHOD = record
    name : PAnsiChar;
    dsa_do_sign : function (const dgst : PAnsiChar; dlen : TC_INT; dsa : PDSA) : PDSA_SIG; cdecl;
    dsa_sign_setup : function (dsa : PDSA; ctx_in : PBN_CTX; kinvp, rp : PPBN_CTX) : TC_INT; cdecl;
    dsa_do_verify : function(dgst : PAnsiChar; dgst_len : TC_INT; sig : PDSA_SIG; dsa : PDSA) : TC_INT; cdecl;
    dsa_mod_exp : function(dsa : PDSA; rr, a1, p1, a2, p2, m : PBIGNUM; ctx : PBN_CTX; in_mont : PBN_MONT_CTX) : TC_INT; cdecl;
    bn_mod_exp : function (dsa : PDSA; r, a : PBIGNUM; const p; m : PBIGNUM;  ctx : PBN_CTX; m_ctx : PBN_CTX): TC_INT; cdecl; // Can be null
    init : function (dsa : PDSA) : TC_INT; cdecl;
    finish : function (dsa : PDSA) : TC_INT; cdecl;
    flags : TC_INT;
    app_data : PAnsiChar;
    dsa_paramgen : function (dsa : PDSA; bits : TC_INT; seed : PAnsiChar;  seed_len : TC_INT; counter_ret : PC_INT; h_ret : PC_ULONG;
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

  PEVP_PKEY_CTX = ^EVP_PKEY_CTX;
  PPEVP_PKEY_CTX = ^PEVP_PKEY_CTX;

  EVP_SIGN_METHOD = function(_type: TC_INT; m: PAnsiChar; m_length: TC_UINT; sigret: PAnsiChar; var siglen: TC_UINT; key: Pointer): TC_INT; cdecl;
  EVP_VERIFY_METHOD = function(_type: TC_INT; m: PAnsiChar; m_length: TC_UINT; sigbuf: PAnsiChar; siglen: TC_UINT; key: Pointer): TC_INT; cdecl;
  EVP_PKEY_gen_cb = function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl;

  EVP_PKEY_CTX = record
      pmeth: PEVP_PKEY_METHOD;
      engine: PENGINE;
      pkey: PEVP_PKEY;
      peerkey: PEVP_PKEY;
      operation: TC_INT;
    data: Pointer;
      app_data: Pointer;
      pkey_gencb: EVP_PKEY_gen_cb;
      keygen_info: PC_INT;
    keygen_info_count: TC_INT;
    end;

    EVP_PKEY_METHOD = record
        _pkey_id: TC_INT;
        _flags: TC_INT;

        init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        copy: function(_dst: PEVP_PKEY_CTX; _src: PEVP_PKEY_CTX): TC_INT; cdecl;
        cleanup: procedure(_ctx: PEVP_PKEY_CTX); cdecl;

        paramgen_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        paramgen: function(_ctx: PEVP_PKEY_CTX; _pkey: PEVP_PKEY): TC_INT; cdecl;

        keygen_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        keygen: function(_ctx: PEVP_PKEY_CTX; _pkey: PEVP_PKEY): TC_INT; cdecl;

        sign_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        sign: function(_ctx: PEVP_PKEY_CTX; _sig: PAnsiChar; var _siglen: TC_SIZE_T;const _tbs: PAnsiChar; _tbslen: TC_SIZE_T): TC_INT; cdecl;

        verify_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        verify: function(_ctx: PEVP_PKEY_CTX;const _sig: PAnsiChar; _siglen: TC_SIZE_T; const _tbs: PAnsiChar; _tbslen: TC_SIZE_T): TC_INT; cdecl;

        verify_recover_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        verify_recover: function(_ctx: PEVP_PKEY_CTX;_rout: PAnsiChar; var _routlen: TC_SIZE_T;const _sig: PAnsiChar; _siglen: TC_SIZE_T): TC_INT; cdecl;

        signctx_init: function(_ctx: PEVP_PKEY_CTX; _mctx: PEVP_MD_CTX): TC_INT; cdecl;
        signctx: function(_ctx: PEVP_PKEY_CTX; _sig: PAnsiChar; var siglen: TC_SIZE_T; _mctx: PEVP_MD_CTX): TC_INT; cdecl;

        verifyctx_init: function(_ctx: PEVP_PKEY_CTX; _mctx: PEVP_MD_CTX): TC_INT; cdecl;
        verifyctx: function(_ctx: PEVP_PKEY_CTX; const _sig: PAnsiChar;_siglen: TC_INT;_mctx: PEVP_MD_CTX): TC_INT; cdecl;

        encrypt_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        encrypt: function(_ctx: PEVP_PKEY_CTX; _out: PAnsiChar; var _outlen: TC_SIZE_T;const _in: PAnsiChar; _inlen: TC_SIZE_T): TC_INT; cdecl;

        decrypt_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        decrypt: function(_ctx: PEVP_PKEY_CTX; _out: PAnsiChar; var _outlen: TC_SIZE_T;const _in: PAnsiChar; _inlen: TC_SIZE_T): TC_INT; cdecl;

        derive_init: function(_ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
        derive: function(_ctx: PEVP_PKEY_CTX; _key: PAnsiChar; var _keylen: TC_SIZE_T): TC_INT; cdecl;

        ctrl: function(_ctx: PEVP_PKEY_CTX; _type: TC_INT; _p1: TC_INT; _p2: Pointer): TC_INT; cdecl;
        ctrl_str: function(_ctx: PEVP_PKEY_CTX; const _type: PAnsiChar; const _value: PAnsiChar): TC_INT; cdecl;

    end; { record }



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
  PPSTACK_OF_X509_ATTRIBUTE = ^PSTACK_OF_X509_ATTRIBUTE;

  PPEVP_PKEY = ^PEVP_PKEY;
  EVP_PKEY = record
    _type : TC_INT;
    save_type : TC_INT;
    references : TC_INT;
    ameth : PEVP_PKEY_ASN1_METHOD;
    enigne: PENGINE;
    pkey : EVP_PKEY_union;
    save_parameters: TC_INT;
    attributes : PSTACK_OF_X509_ATTRIBUTE;
  end;

    EVP_PKEY_ASN1_METHOD = record
        _pkey_id: TC_INT;
        _pkey_base_id: TC_INT;
        _pkey_flags: TC_ULONG;

        _pem_str: PAnsiChar;
        _info: PAnsiChar;

        pub_decode: function(_pk: PEVP_PKEY; _pub: PX509_PUBKEY): TC_INT; cdecl;
        pub_encode: function(_pub: PX509_PUBKEY; const _pk: PEVP_PKEY): TC_INT; cdecl;
        pub_cmp: function(const _a: PEVP_PKEY; const _b: PEVP_PKEY): TC_INT; cdecl;
        pub_print: function(_out: PBIO; const _pkey: PEVP_PKEY; _indent: TC_INT;_pctx: PASN1_PCTX): TC_INT; cdecl;

        priv_decode: function(_pk: PEVP_PKEY; _p8inf: PPKCS8_PRIV_KEY_INFO): TC_INT; cdecl;
        priv_encode: function(_p8: PPKCS8_PRIV_KEY_INFO; const _pk: PEVP_PKEY): TC_INT; cdecl;
        priv_print: function(_out: PBIO; const _pkey: PEVP_PKEY; _indent: TC_INT;_pctx: PASN1_PCTX): TC_INT; cdecl;

        pkey_size: function(const _pk: PEVP_PKEY): TC_INT; cdecl;
        pkey_bits: function(const _pk: PEVP_PKEY): TC_INT; cdecl;

        param_decode: function(_pkey: PEVP_PKEY;const _pder: PPAnsiChar; _derlen: TC_INT): TC_INT; cdecl;
        param_encode: function(const _pkey: PEVP_PKEY; _pder: PPAnsiChar): TC_INT; cdecl;
        param_missing: function(const _pk: PEVP_PKEY): TC_INT; cdecl;
        param_copy: function(_to: PEVP_PKEY; const _from: PEVP_PKEY): TC_INT; cdecl;
        param_cmp: function(const _a: PEVP_PKEY; const _b: PEVP_PKEY): TC_INT; cdecl;
        param_print: function(_out: PBIO; const _pkey: PEVP_PKEY; _indent: TC_INT; _pctx: PASN1_PCTX): TC_INT; cdecl;
        sig_print: function(_out: PBIO;const _sigalg: PX509_ALGOR; const _sig: PASN1_STRING;_indent: TC_INT; _pctx: PASN1_PCTX): TC_INT; cdecl;


        pkey_free: procedure(_pkey: PEVP_PKEY); cdecl;
        pkey_ctrl: function(_pkey: PEVP_PKEY; _op: TC_INT; _arg1: TC_LONG; _arg2: Pointer): TC_INT; cdecl;

        old_priv_decode: function(_pkey: Pointer;const _pder: PPAnsiChar; _derlen: TC_INT): TC_INT; cdecl;
        old_priv_encode: function(const _pkey: PEVP_PKEY; _pder: PPAnsiChar): TC_INT; cdecl;
        item_verify: function(_ctx: PEVP_MD_CTX; const _it: PASN1_ITEM; _asn: Pvoid; _a: PX509_ALGOR; _sig: PASN1_BIT_STRING; _pkey: PEVP_PKEY): TC_INT; cdecl;
        item_sign: function(_ctx: PEVP_MD_CTX; const _it: PASN1_ITEM; _asn: Pointer; _alg1: PX509_ALGOR; _alg2: PX509_ALGOR; _sig: PASN1_BIT_STRING): TC_INT; cdecl;
    end; { record }

  PEVP_CIPHER_CTX = ^EVP_CIPHER_CTX;
  EVP_CIPHER = record
    nid : TC_Int;
    block_size : TC_Int;
    key_len : TC_Int;
    iv_len : TC_Int;
    flags : TC_ULONG;
    init : function (ctx : PEVP_CIPHER_CTX; key : PAnsiChar; iv : PAnsiChar; enc : TC_Int): TC_Int; cdecl;
    do_cipher : function (ctx : PEVP_CIPHER_CTX; _out : PAnsiChar; _in : PAnsiChar; inl : TC_SIZE_T) : TC_Int; cdecl;
    cleanup : function (_para1 : PEVP_CIPHER_CTX): TC_Int; cdecl;
    ctx_size : TC_Int;
    set_asn1_parameters : function (_para1 : PEVP_CIPHER_CTX; _para2 : PASN1_TYPE) : TC_Int; cdecl;
    get_asn1_parameters :function (_para1 : PEVP_CIPHER_CTX; _para2 :  PASN1_TYPE) : TC_Int; cdecl;
    ctrl : function (_para1 : PEVP_CIPHER_CTX; _type : TC_Int; arg : TC_Int;  ptr : Pointer): TC_Int; cdecl;
    app_data : Pointer;
  end;

  EVP_CIPHER_DO = procedure(ciph: PEVP_CIPHER; from: PAnsiChar; _to: PAnsiChar; x: Pointer); cdecl;
  EVP_MD_DO = procedure(ciph: PEVP_MD; from: PAnsiChar; _to: PAnsiChar; x: Pointer); cdecl;

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


  EVP_MD_CTX = record
    digest : PEVP_MD;
    engine : PENGINE;
    flags : TC_ULONG;
    md_data : Pointer;
    pctx : PEVP_PKEY_CTX;
    update : function (ctx : PEVP_MD_CTX; const data : Pointer; count : TC_SIZE_T) : TC_INT cdecl;
  end;


  EVP_MD = record
    _type : TC_Int;
    pkey_type : TC_Int;
    md_size : TC_Int;
    flags : TC_ULONG;
    init : function (ctx : PEVP_MD_CTX) : TC_Int; cdecl;
    update : function (ctx : PEVP_MD_CTX; data : Pointer; count : TC_SIZE_T):TC_Int; cdecl;
    _final : function (ctx : PEVP_MD_CTX; md : PAnsiChar) : TC_Int; cdecl;
    copy : function (_to : PEVP_MD_CTX; from : PEVP_MD_CTX ) : TC_Int; cdecl;
    cleanup : function(ctx : PEVP_MD_CTX) : TC_Int; cdecl;
    sign : function(_type : TC_Int; m : PAnsiChar; m_length : TC_UINT;  sigret : PAnsiChar; siglen : TC_UINT; key : Pointer) : TC_Int; cdecl;
    verify : function(_type : TC_Int; m : PAnsiChar; m_length : PAnsiChar;  sigbuf : PAnsiChar; siglen : TC_UINT; key : Pointer) : TC_Int; cdecl;
    required_pkey_type : array [0..4] of TC_Int; // EVP_PKEY_xxx
    block_size : TC_Int;
    ctx_size : TC_Int;
    md_ctrl: function( ctx: PEVP_MD_CTX; cmd: TC_INT; p1: TC_INT; p2: Pointer): TC_INT; cdecl;
  end;

  PEVP_ENCODE_CTX = ^EVP_ENCODE_CTX;
  EVP_ENCODE_CTX = record
    num: TC_INT;
    _length: TC_INT;
    enc_data: array[0..79] of AnsiChar;
    line_num: TC_INT;
    expect_nl: TC_INT;
  end;

  EVP_PBE_KEYGEN = function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TC_INT): TC_INT;
  PEVP_PBE_KEYGEN = ^EVP_PBE_KEYGEN;


{$ENDREGION}



{$REGION 'X509'}

  PPX509 = ^PX509;
  PX509_REQ = ^X509_REQ;
  PX509_CRL = ^X509_CRL;
  PX509_NAME = ^X509_NAME;
  PPX509_NAME = ^PX509_NAME;
  PX509_NAME_ENTRY = ^X509_NAME_ENTRY;
  PPX509_NAME_ENTRY = ^PX509_NAME_ENTRY;
  PX509_REQ_INFO = ^X509_REQ_INFO;
  PPX509_REQ_INFO = ^PX509_REQ_INFO;
  PX509_POLICY_CACHE = ^X509_POLICY_CACHE;
  PX509_CRL_METHOD = Pointer;
  PSTACK_OF_X509_REVOKED = PSTACK_OF;


  PPSTACK_OF_X509 = ^PSTACK_OF_X509;

  PSTACK_OF_X509_NAME_ENTRY = PSTACK_OF;

  PX509_OBJECTS = ^X509_OBJECTS;
  X509_OBJECTS = record
    nid: TC_INT;
    a2i: function: TC_INT; cdecl;
    i2a: function: TC_INT; cdecl;
  end;

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
    canon_enc: PAnsiChar;
    canon_enclen: TC_INT;
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
      0  : (_set: PSTACK_OF_ASN1_TYPE); // 0
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
    attributes: PSTACK_OF_X509_ATTRIBUTE;
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
  PPX509_CINF = ^PX509_CINF;


  X509_CERT_AUX = record
    trust : PSTACK_OF_ASN1_OBJECT;
    reject : PSTACK_OF_ASN1_OBJECT;
    alias : PASN1_UTF8STRING;
    keyid : PASN1_OCTET_STRING;
    other : PSTACK_OF_X509_ALGOR;
  end;
  PX509_CERT_AUX = ^X509_CERT_AUX;
  PPX509_CERT_AUX = ^PX509_CERT_AUX;

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
    crldp: PSTACK_OF;
    altName: PSTACK_OF;
    nc: Pointer;
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
    flags: TC_INT;
    akid: PAUTHORITY_KEYID;
    idp: Pointer;
    idp_flags: TC_INT;
    idp_reason: TC_INT;
    crl_number: PASN1_INTEGER;
    base_crl_number: PASN1_INTEGER;
    sha1_hash: array[0..SHA_DIGEST_LENGTH-1] of AnsiChar;
    issuers: PSTACK_OF;
    meth: PX509_CRL_METHOD;
    meth_data: Pointer;
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
    issuer: PSTACK_OF;
    reason: TC_INT;
    sequence: TC_Int;
  end;
  PX509_REVOKED      = ^X509_REVOKED;
  PPX509_REVOKED     =^PX509_REVOKED;

  PX509_PKEY       = ^X509_PKEY;
  PPX509_PKEY      =^PX509_PKEY;
  X509_PKEY = record
    version: TC_INT;
    enc_algor: PX509_ALGOR;
    enc_pkey: PASN1_OCTET_STRING;
    dec_pkey: PEVP_PKEY;
    key_length: TC_INT;
    key_data: PAnsiChar;
    key_free: TC_INT;
    cipher: EVP_CIPHER_INFO;
    references: TC_INT;
  end;

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

  PX509_CERT_PAIR = ^X509_CERT_PAIR;
  X509_CERT_PAIR = record
    _forward: PX509;
    _reverse: PX509;
  end;
  PPX509_CERT_PAIR = ^PX509_CERT_PAIR;

  PKCS8_PRIV_KEY_INFO = record
        broken: TC_INT;
        version: PASN1_INTEGER;
        pkeyalg: PX509_ALGOR;
        pkey: PASN1_TYPE;
        attributes: PSTACK_OF_X509_ATTRIBUTE;
  end;


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

  PPBEPARAM = ^PBEPARAM;
  PBEPARAM = record
    salt: PASN1_OCTET_STRING;
    iter: PASN1_INTEGER;
  end;

  PPBE2PARAM = ^PBE2PARAM;
  PBE2PARAM = record
    keyfunc: PX509_ALGOR;
    encryption: PX509_ALGOR;
  end;

  PPBKDF2PARAM = ^PBKDF2PARAM;
  PBKDF2PARAM = record
    salt: PASN1_TYPE;
    iter: PASN1_INTEGER;
    keylength: PASN1_INTEGER;
    prf: PX509_ALGOR;
  end;

  EVP_pub_decode_t = function(pk: PEVP_PKEY; pub: PX509_PUBKEY): TC_INT; cdecl;
  EVP_pub_encode_t = function(pub: PX509_PUBKEY;  pk: PEVP_PKEY): TC_INT; cdecl;
  EVP_pub_cmp_t = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TC_INT; cdecl;
  EVP_pub_print_t = function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT; pctx: ASN1_PCTX): TC_INT; cdecl;
  EVP_pkey_size_t = function(const pk: PEVP_PKEY): TC_INT; cdecl;
  EVP_pkey_bits_t = function(const pk: PEVP_PKEY): TC_INT; cdecl;

  EVP_priv_decode_t = function(pk: PEVP_PKEY; p8inf: PPKCS8_PRIV_KEY_INFO): TC_INT; cdecl;
  EVP_priv_encode_t = function(p8: PPKCS8_PRIV_KEY_INFO; const pk : PEVP_PKEY): TC_INT; cdecl;
  EVP_priv_print_t =  function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT; pctx: ASN1_PCTX): TC_INT; cdecl;

  EVP_param_decode_t = function(pkey: PEVP_PKEY;var pder: PAnsiChar; derlen: TC_INT): TC_INT; cdecl;
  EVP_param_encode_t = function(const pkey: PEVP_PKEY; var pder: PAnsiChar): TC_INT; cdecl;
  EVP_param_missing_t = function(const pk: PEVP_PKEY): TC_INT; cdecl;
  EVP_param_copy_t = function(_to: PEVP_PKEY; const _from: PEVP_PKEY): TC_INT; cdecl;
  EVP_param_cmp_t = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TC_INT; cdecl;
  EVP_param_print_t = function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT;   pctx: ASN1_PCTX): TC_INT; cdecl;
  EVP_pkey_free_t = procedure(pkey: PEVP_PKEY); cdecl;
  EVP_pkey_ctrl_t = function(pkey: PEVP_PKEY; op:TC_INT;arg1: TC_LONG; arg2: Pointer): TC_INT; cdecl;
{$ENDREGION}

{$REGION 'X509V3}


  PX509V3_CONF_METHOD = ^X509V3_CONF_METHOD;
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

  POTHERNAME = ^OTHERNAME;
  PPOTHERNAME = ^POTHERNAME;
  OTHERNAME = record
    type_id: PASN1_OBJECT;
    value: PASN1_TYPE;
  end;

  PEDIPARTYNAME = ^EDIPARTYNAME;
  PPEDIPARTYNAME = ^PEDIPARTYNAME;
  EDIPARTYNAME = record
      nameAssigner: PASN1_STRING;
      partyName: PASN1_STRING;
  end;

  GENERAL_NAME_union = record
  case byte of
    0: (ptr: PAnsiChar);
    1: (otherName: POTHERNAME);
      2: (rfc822Name: PASN1_IA5STRING);
      3: (dNSName: PASN1_IA5STRING);
      4: (x400Address: PASN1_TYPE);
      5: (directoryName: PX509_NAME);
      6: (ediPartyName: PEDIPARTYNAME);
      7: (uniformResourceIdentifier: PASN1_IA5STRING);
      8: (iPAddress: PASN1_OCTET_STRING);
      9: (registeredID: PASN1_OBJECT);
      10: (ip: PASN1_OCTET_STRING);
      11: (dirn: PX509_NAME);
      12: (ia5: PASN1_IA5STRING);
    13: (rid: PASN1_OBJECT);
      14: (other: PASN1_TYPE);
  end;

  PGENERAL_NAME = ^GENERAL_NAME;
  PPGENERAL_NAME = ^PGENERAL_NAME;
  GENERAL_NAME = record
    _type: TC_INT;
    d: GENERAL_NAME_union;
  end;
  PX509V3_EXT_METHOD = ^X509V3_EXT_METHOD;

  X509V3_EXT_NEW_func = function: Pointer; cdecl;
  X509V3_EXT_FREE_func = procedure(p: Pointer); cdecl;
  X509V3_EXT_D2I_func = function(_par1: Pointer; var _par2: PAnsiChar; _par3: TC_LONG): Pointer; cdecl;
  X509V3_EXT_I2D_func = function(_par1: Pointer; var _par2: PAnsiChar): TC_INT; cdecl;
  X509V3_EXT_I2V_func = function(method: PX509V3_EXT_METHOD; ext: Pointer; extlist: PSTACK_OF_CONF_VALUE): PSTACK_OF_CONF_VALUE; cdecl;
  X509V3_EXT_V2I_func = function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; values: PSTACK_OF_CONF_VALUE): Pointer; cdecl;
  X509V3_EXT_I2S_func = function(method: PX509V3_EXT_METHOD; ext: Pointer): PAnsiChar; cdecl;
  X509V3_EXT_S2I_func = function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PAnsiChar): Pointer; cdecl;
  X509V3_EXT_I2R_func = function(method: PX509V3_EXT_METHOD; ext: Pointer; _out: PBIO; indent: TC_INT): TC_INT; cdecl;
  X509V3_EXT_R2I_func = function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PAnsiChar): Pointer; cdecl;

  V3_EXT_METHOD = record
    ext_nid: TC_INT;
    ext_flags: TC_INT;
    it: PASN1_ITEM_EXP;
    ext_new: X509V3_EXT_NEW_func;
    ext_free: X509V3_EXT_FREE_func;
    d2i: X509V3_EXT_D2I_func;
    i2d: X509V3_EXT_I2D_func;
    i2s: X509V3_EXT_I2S_func;
    s2i: X509V3_EXT_S2I_func;
    i2v: X509V3_EXT_I2V_func;
    v2i: X509V3_EXT_V2I_func;
    i2r: X509V3_EXT_I2R_func;
    r2i: X509V3_EXT_R2I_func;
    usr_data: Pointer;
  end;
  X509V3_EXT_METHOD = V3_EXT_METHOD;
  PSTACK_OF_X509V3_EXT_METHOD = PSTACK_OF;
  ENUMERATED_NAMES = BIT_STRING_BITNAME;
  PEXTENDED_KEY_USAGE = PSTACK_OF_ASN1_OBJECT;
  PPEXTENDED_KEY_USAGE = ^PEXTENDED_KEY_USAGE;

  PBASIC_CONSTRAINTS = ^BASIC_CONSTRAINTS;
  PPBASIC_CONSTRAINTS = ^PBASIC_CONSTRAINTS;
  BASIC_CONSTRAINTS = record
    ca: TC_INT;
    pathlen: PASN1_INTEGER;
  end;

  PPKEY_USAGE_PERIOD = ^PKEY_USAGE_PERIOD;
  PPPKEY_USAGE_PERIOD = ^PPKEY_USAGE_PERIOD;
  PKEY_USAGE_PERIOD = record
    notBefore: PASN1_GENERALIZEDTIME;
    notAfter: PASN1_GENERALIZEDTIME;
  end;

  PACCESS_DESCRIPTION = ^ACCESS_DESCRIPTION;
  PPACCESS_DESCRIPTION = ^PACCESS_DESCRIPTION;
  ACCESS_DESCRIPTION = record
      method: PASN1_OBJECT;
      location: PGENERAL_NAME;
  end;
  PSTACK_OF_ACCESS_DESCRIPTION = PSTACK_OF;
  PAUTHORITY_INFO_ACCESS = PSTACK_OF_ACCESS_DESCRIPTION;
  PPAUTHORITY_INFO_ACCESS = ^PAUTHORITY_INFO_ACCESS;

  DIST_POINT_NAME_union = record
  case Byte of
      0: (fullname: PGENERAL_NAMES);
      1: (relativename: PSTACK_OF_X509_NAME_ENTRY);
  end;

  PDIST_POINT_NAME = ^DIST_POINT_NAME;
  PPDIST_POINT_NAME = ^PDIST_POINT_NAME;
  DIST_POINT_NAME = record
    _type: TC_INT;
    name: DIST_POINT_NAME_union;
    dpname: PX509_NAME;
  end;

  PDIST_POINT = ^DIST_POINT;
  PPDIST_POINT = ^PDIST_POINT;
  DIST_POINT = record
    distpoint: PDIST_POINT_NAME;
    reasons: PASN1_BIT_STRING;
    CRLissuer: PGENERAL_NAMES;
    dp_reasons: TC_INT;
  end;
  PSTACK_OF_DIST_POINT = PSTACK_OF;
  PCRL_DIST_POINTS = PSTACK_OF_DIST_POINT;
  PPCRL_DIST_POINTS = ^PCRL_DIST_POINTS;

  PSXNETID = ^SXNETID;
  PPSXNETID = ^PSXNETID;
  SXNETID = record
      zone: PASN1_INTEGER;
      user: PASN1_OCTET_STRING;
  end;
  PSTACK_OF_SXNETID = PSTACK_OF;

  PSXNET = ^SXNET;
  PPSXNET = ^PSXNET;
  SXNET = record
      version: PASN1_INTEGER;
      ids: PSTACK_OF_SXNETID;
  end;

  PNOTICEREF = ^NOTICEREF;
  PPNOTICEREF = ^PNOTICEREF;
  NOTICEREF = record
      organization: PASN1_STRING;
      noticenos: PSTACK_OF_ASN1_INTEGER;
  end;

  PUSERNOTICE = ^USERNOTICE;
  PPUSERNOTICE = ^PUSERNOTICE;
  USERNOTICE = record
      noticeref: PNOTICEREF;
      exptext: PASN1_STRING;
  end;

  POLICYQUALINFO_union = record
        cpsuri: PASN1_IA5STRING;
        usernotice: PUSERNOTICE;
        other: PASN1_TYPE;
  end;

  PPOLICYQUALINFO = ^POLICYQUALINFO;
  PPPOLICYQUALINFO = ^PPOLICYQUALINFO;
  POLICYQUALINFO = record
      pqualid: PASN1_OBJECT;
    d: POLICYQUALINFO_union
  end;
  PSTACK_OF_POLICYQUALINFO = PSTACK_OF;

  PPOLICYINFO = ^POLICYINFO;
  PPPOLICYINFO = ^PPOLICYINFO;
  POLICYINFO =  record
      policyid: PASN1_OBJECT;
      qualifiers: PSTACK_OF_POLICYQUALINFO;
  end;
  PSTACK_OF_POLICYINFO = PSTACK_OF;
  PCERTIFICATEPOLICIES = PSTACK_OF_POLICYINFO;
  PPCERTIFICATEPOLICIES = ^PCERTIFICATEPOLICIES;

  PPOLICY_MAPPING = ^POLICY_MAPPING;
  POLICY_MAPPING = record
      issuerDomainPolicy: PASN1_OBJECT;
      subjectDomainPolicy: PASN1_OBJECT;
  end;
  PSTACK_OF_POLICY_MAPPING = PSTACK_OF;

  PGENERAL_SUBTREE = ^GENERAL_SUBTREE;
  GENERAL_SUBTREE = record
      base: PGENERAL_NAME;
      minimum: PASN1_INTEGER;
      maximum: PASN1_INTEGER;
  end;
  PSTACK_OF_GENERAL_SUBTREE = PSTACK_OF;

  PNAME_CONSTRAINTS = ^NAME_CONSTRAINTS;
  NAME_CONSTRAINTS = record
      permittedSubtrees: PSTACK_OF_GENERAL_SUBTREE;
      excludedSubtrees: PSTACK_OF_GENERAL_SUBTREE;
  end;

  PPOLICY_CONSTRAINTS = ^POLICY_CONSTRAINTS;
  POLICY_CONSTRAINTS = record
      requireExplicitPolicy: PASN1_INTEGER;
      inhibitPolicyMapping: PASN1_INTEGER;
  end;

  PPROXY_POLICY = ^PROXY_POLICY;
  PPPROXY_POLICY = ^PPROXY_POLICY;
  PROXY_POLICY = record
    policyLanguage: PASN1_OBJECT;
      policy: PASN1_OCTET_STRING;
  end;

  PPROXY_CERT_INFO_EXTENSION = ^PROXY_CERT_INFO_EXTENSION;
  PPPROXY_CERT_INFO_EXTENSION = ^PPROXY_CERT_INFO_EXTENSION;
  PROXY_CERT_INFO_EXTENSION = record
      pcPathLengthConstraint: PASN1_INTEGER;
      proxyPolicy: PPROXY_POLICY;
  end;

  PISSUING_DIST_POINT = ^ISSUING_DIST_POINT;
  PPISSUING_DIST_POINT = ^PISSUING_DIST_POINT;
  ISSUING_DIST_POINT = record
      distpoint: PDIST_POINT_NAME;
      onlyuser: TC_INT;
      onlyCA: TC_INT;
      onlysomereasons: PASN1_BIT_STRING;
      indirectCRL: TC_INT;
      onlyattr: TC_INT;
  end;



  PX509_PURPOSE = ^X509_PURPOSE;

  X509_CHECK_PURPOSE_FUNC = function(p: PX509_PURPOSE; _x509: PX509; _i: TC_INT): TC_INT; cdecl;
  X509_PURPOSE = record
      purpose: TC_INT;
      trust: TC_INT;
      flags: TC_INT;
      check_purpose: X509_CHECK_PURPOSE_FUNC;
      name: PAnsiChar;
      sname: PAnsiChar;
      usr_data: Pointer;
  end;
  PSTACK_OF_X509_PURPOSE = PSTACK_OF;

  PSTACK_OF_X509_POLICY_NODE = PSTACK_OF;
  PSTACK_OF_OPENSSL_STRING = PSTACK_OF;

  PX509_POLICY_DATA = ^X509_POLICY_DATA;
  X509_POLICY_DATA = record
      flags: TC_UINT;
      valid_policy: PASN1_OBJECT;
      qualifier_set: PSTACK_OF_POLICYQUALINFO;
      expected_policy_set: PSTACK_OF_ASN1_OBJECT;
  end;
  PSTACK_OF_X509_POLICY_DATA = PSTACK_OF;

  X509_POLICY_CACHE = record
      anyPolicy: PX509_POLICY_DATA;
      data: PSTACK_OF_X509_POLICY_DATA;
      any_skip: TC_LONG;
      explicit_skip: TC_LONG;
      map_skip: TC_LONG;
  end;


  PX509_POLICY_NODE = ^X509_POLICY_NODE;
  X509_POLICY_NODE = record
    data: PX509_POLICY_DATA;
      parent: PX509_POLICY_NODE;
      nchild: TC_INT;
  end;

  PX509_POLICY_LEVEL = ^X509_POLICY_LEVEL;
  X509_POLICY_LEVEL = record
      cert: PX509;
      nodes: PSTACK_OF_X509_POLICY_NODE;
      anyPolicy: pX509_POLICY_NODE;
      flags: TC_UINT;
  end;

  PX509_POLICY_TREE = ^X509_POLICY_TREE;
  X509_POLICY_TREE = record
      levels: PX509_POLICY_LEVEL;
      nlevel: TC_INT;
      extra_data: PSTACK_OF_X509_POLICY_DATA;
      auth_policies: PSTACK_OF_X509_POLICY_NODE;
      user_policies: PSTACK_OF_X509_POLICY_NODE;
      flags: TC_UINT;
  end;



{$ENDREGION}

{$REGION 'PEM'}

    pem_password_cb = function(buf: PAnsiString; size: TC_INT; rwflag: TC_INT; userdata: pointer): integer; cdecl;

{$ENDREGION}

{$REGION 'PKCS7'}

  PPKCS7 = ^PKCS7;
  PPPKCS7 = ^PPKCS7;
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
  PPPKCS7_ENVELOPE = ^PPKCS7_ENVELOPE;

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
  PPPKCS7_SIGN_ENVELOPE = ^PPKCS7_SIGN_ENVELOPE;

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
    PPPKCS7_ENCRYPT = ^PPKCS7_ENCRYPT;

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


  BF_KEY = record
    P: array [0..BF_ROUNDS+1] of BF_LONG;
    S: array [0..(4*256)-1] of BF_LONG;
  end;
  PBF_KEY = ^BF_KEY;

{$ENDREGION}

{$REGION 'CMAX'}


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
  case byte  of
    0: (data: PASN1_OCTET_STRING);
    1: (signedData: PCMS_SignedData);
    2: (envelopedData: PCMS_EnvelopedData);
    3: (digestedData: PCMS_DigestedData);
    4: (encryptedData: PCMS_EncryptedData);
    5: (authenticatedData: PCMS_AuthenticatedData);
    6: (compressedData: PCMS_CompressedData);
    7: (other: PASN1_TYPE);
    8: (otherData: Pointer);
  end;

  PCMS_ContentInfo = ^CMS_ContentInfo;
    PPCMS_ContentInfo = ^PCMS_ContentInfo;
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
    case byte of
      0: (issuerAndSerialNumber: PCMS_IssuerAndSerialNumber);
      1: (subjectKeyIdentifier: PASN1_OCTET_STRING);
   end;

   PCMS_SignerIdentifier = ^CMS_SignerIdentifier;
   CMS_SignerIdentifier = record
       _type: TC_INT;
     d: CMS_SignerIdentifier_union;
   end;
   PCMS_RecipientIdentifier = ^CMS_RecipientIdentifier;
   CMS_RecipientIdentifier = CMS_SignerIdentifier;

     PCMS_SignerInfo = ^CMS_SignerInfo;
     PPCMS_SignerInfo = ^PCMS_SignerInfo;
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
   case byte of
    0: (issuerAndSerialNumber: PCMS_IssuerAndSerialNumber);
    1: (rKeyId: PCMS_RecipientKeyIdentifier);
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
   case Byte of
    0: (issuerAndSerialNumber: PCMS_IssuerAndSerialNumber);
    1: (subjectKeyIdentifier: PASN1_OCTET_STRING);
    2: (originatorKey: PCMS_OriginatorPublicKey);
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
  case byte of
    0: (ktri: PCMS_KeyTransRecipientInfo);
    1: (kari: PCMS_KeyAgreeRecipientInfo);
    2: (kekri: PCMS_KEKRecipientInfo);
    3: (pwri: PCMS_PasswordRecipientInfo);
    4: (ori: PCMS_OtherRecipientInfo);
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
   case byte of
    0: (crl: PX509_CRL);
    1: (other: PCMS_OtherRevocationInfoFormat);
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
  case byte of
    0: (certificate: PX509);
    1: (extendedCertificate: PASN1_STRING);
    2: (v1AttrCert: PASN1_STRING);
    3: (v2AttrCert: PASN1_STRING);
    4: (other: PCMS_OtherCertificateFormat);
  end;

  PCMS_CertificateChoices = ^CMS_CertificateChoices;
  CMS_CertificateChoices = record
    _type: TC_INT;
    d:CMS_CertificateChoices_union;
  end;

    CMS_RECEIPTSFROM_union = record
    case byte of
        0: (_allOrFirstTier: TC_LONG);
        1: (_receiptList: PSTACK_OF_GENERAL_NAMES);
    end; { record }

    PCMS_RECEIPTSFROM = ^CMS_RECEIPTSFROM;
    PPCMS_RECEIPTSFROM = ^PCMS_RECEIPTSFROM;
    CMS_RECEIPTSFROM = record
        _type: TC_INT;
        d: CMS_RECEIPTSFROM_union;
    end; { record }

    PCMS_RECEIPTREQUEST = ^CMS_RECEIPTREQUEST;
    PPCMS_RECEIPTREQUEST = ^PCMS_RECEIPTREQUEST;
    CMS_RECEIPTREQUEST = record
        _signedContentIdentifier: PASN1_OCTET_STRING;
        _receiptsFrom: PCMS_ReceiptsFrom;
         _receiptsTo: PSTACK_OF_GENERAL_NAMES;
    end; { record }

{$ENDREGION}

{$REGION 'DES'}


  DES_cblock = array[0..7] of TC_UCHAR;
  PDES_cblock = ^DES_cblock;
  const_DES_cblock = array[0..7] of TC_UCHAR;
  Pconst_DES_cblock = ^const_DES_cblock;
  DES_cblock_array = array of DES_cblock;

  DES_key_schedule_union = record
  case Byte of
     0: (cblock: DES_cblock);
     1: (deslong: array[0..1] of DES_LONG);
  end;

  PDES_key_schedule = ^DES_key_schedule;
  DES_key_schedule = record
    ks: array[0..15] of DES_key_schedule_union;
  end;

{$ENDREGION}


{$REGION 'ENGINE'}
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


  PECDH_METHOD = ^ECDH_METHOD;
  PECDSA_METHOD = ^ECDSA_METHOD;
  PSTORE_METHOD = Pointer;

{$REGION 'CAMELLIA'}

    KEY_TABLE_TYPE = array [0..CAMELLIA_TABLE_WORD_LEN-1] of TC_UINT;
    CAMELLIA_BUF = array[0..CAMELLIA_BLOCK_SIZE-1] of AnsiChar;
    CAMELLIA_KEY_union = record
     case byte of
        0: (d: double);
        1: (rd_key: KEY_TABLE_TYPE);
    end;
    
    PCAMELLIA_KEY = ^CAMELLIA_KEY;
    CAMELLIA_KEY = record
        u: CAMELLIA_KEY_union;
        grand_rounds: TC_INT;
    end;
      
{$ENDREGION}  
  
{$REGION 'COMP'}

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


  SK_POP_FREE_PROC = procedure(_par1: Pointer); cdecl;

  tm = record
    tm_sec: Integer;            // Seconds. [0-60] (1 leap second)
    tm_min: Integer;            // Minutes. [0-59]
    tm_hour: Integer;           // Hours.[0-23]
    tm_mday: Integer;           // Day.[1-31]
    tm_mon: Integer;            // Month.[0-11]
    tm_year: Integer;           // Year since 1900
    tm_wday: Integer;           // Day of week [0-6] (Sunday = 0)
    tm_yday: Integer;           // Days of year [0-365]
    tm_isdst: Integer;          // Daylight Savings flag [-1/0/1]
    tm_gmtoff: LongInt;         // Seconds east of UTC
    tm_zone: PAnsiChar;         // Timezone abbreviation
  end;
  Ptm = ^tm;

{$REGION 'PKCS12'}

    PPKCS12_MAC_DATA = ^PKCS12_MAC_DATA;
    PPPKCS12_MAC_DATA = ^PPKCS12_MAC_DATA;
    PKCS12_MAC_DATA = record    
        dinfo: PX509_SIG;
        salt: PASN1_OCTET_STRING;
        iter: PASN1_INTEGER;    
    end;

    PPKCS12 = ^PKCS12;
    PPPKCS12 = ^PPKCS12;
    PKCS12 = record
        version: PASN1_INTEGER;
        mac: PPKCS12_MAC_DATA;
        authsafes: PPKCS7;
    end;

    PKCS12_BAGS_union = record
    case byte of
     0: (x509cert: PASN1_OCTET_STRING);
     1: (x509crl: PASN1_OCTET_STRING);
     2: (octet: PASN1_OCTET_STRING);
     3: (sdsicert: PASN1_IA5STRING);
     4: (other: PASN1_TYPE);
    end; { record }

    PPKCS12_BAGS = ^PKCS12_BAGS;
    PPPKCS12_BAGS = ^PPKCS12_BAGS;
    PKCS12_BAGS = record
        _type: PASN1_OBJECT;
        value: PKCS12_BAGS_union;
    end; { record }

    PSTACK_OF_PKCS12_SAFEBAG = PSTACK_OF;
    PPSTACK_OF_PKCS12_SAFEBAG = ^PSTACK_OF_PKCS12_SAFEBAG;
    PPKCS12_SAFEBAG = ^PKCS12_SAFEBAG;
    PPPKCS12_SAFEBAG = ^PPKCS12_SAFEBAG;
    PKCS12_SAFEBAG_union = record
        bag: PPKCS12_BAGS;
        keybag: PPKCS8_PRIV_KEY_INFO;
        shkeybag: PX509_SIG;
        safes: PSTACK_OF_PKCS12_SAFEBAG;
        other: PASN1_TYPE;
    end; { record }

    PKCS12_SAFEBAG = record
        _type: PASN1_OBJECT;
        value: PKCS12_SAFEBAG_union;
        attrib: PSTACK_OF_X509_ATTRIBUTE;
    end; { record }
    PSTACK_OF_PKCS7 = PSTACK_OF;
    PPSTACK_OF_PKCS7 = ^PSTACK_OF_PKCS7;

    PPKCS7_ISSUER_AND_SERIAL = ^PKCS7_ISSUER_AND_SERIAL;
    PPPKCS7_ISSUER_AND_SERIAL = ^PPKCS7_ISSUER_AND_SERIAL;
    PKCS7_ISSUER_AND_SERIAL = record
        issuer: PX509_NAME;
        serial: PASN1_INTEGER;
    end; { record }

    PPKCS7_SIGNER_INFO = ^PKCS7_SIGNER_INFO;
    PPPKCS7_SIGNER_INFO = ^PPKCS7_SIGNER_INFO;
    PKCS7_SIGNER_INFO = record
        version: PASN1_INTEGER;
        issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
        digest_alg: PX509_ALGOR;
        auth_attr: PSTACK_OF_X509_ATTRIBUTE;
        digest_enc_alg: PX509_ALGOR;
        enc_digest: PASN1_OCTET_STRING;
        unauth_attr: PSTACK_OF_X509_ATTRIBUTE;
        pkey: PEVP_PKEY;
    end; { record }


    PPKCS7_RECIP_INFO = ^PKCS7_RECIP_INFO;
    PPPKCS7_RECIP_INFO = ^PPKCS7_RECIP_INFO;
    PKCS7_RECIP_INFO = record
        _version: PASN1_INTEGER;
        _issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
        _key_enc_algor: PX509_ALGOR;
        _enc_key: PASN1_OCTET_STRING;
        _cert: PX509;
    end; { record }

    PPPKCS7_SIGNED = ^PPKCS7_SIGNED;
    PSTACK_OF_PKCS7_SIGNED = PSTACK_OF;

    PPPKCS7_ENC_CONTENT = ^PPKCS7_ENC_CONTENT;

    PPKCS7_ENVELOPED = ^PKCS7_ENVELOPED;
    PPPKCS7_ENVELOPED = ^PPKCS7_ENVELOPED;
    PKCS7_ENVELOPED = record
        _version: PASN1_INTEGER;
        recipientinfo: PSTACK_OF_PKCS7_RECIP_INFO;
        _enc_data: PPKCS7_ENC_CONTENT;
    end; { record }

    PKCS7_SIGNEDANDENVELOPED = record
        _version: PASN1_INTEGER;
        _md_algs: PSTACK_OF_X509_ALGOR;
        _cert: PSTACK_OF_X509;
        _crl: PSTACK_OF_X509_CRL;
        _signer_info: PSTACK_OF_PKCS7_SIGNER_INFO;
        _enc_data: PPKCS7_ENC_CONTENT   ;
        _recipientinfo: PSTACK_OF_PKCS7_RECIP_INFO;
    end; { record }

    PPPKCS7_DIGEST = ^PPKCS7_DIGEST;

    PPKCS7_ENCRYPTED = ^PKCS7_ENCRYPTED;
    PPPKCS7_ENCRYPTED = ^PPKCS7_ENCRYPTED;
    PKCS7_ENCRYPTED = record
        _version: PASN1_INTEGER;
        _enc_data: PPKCS7_ENC_CONTENT;
    end; { record }

  PPKCS7_ATTR_SIGN = Pointer;
    PPPKCS7_ATTR_SIGN = ^PPKCS7_ATTR_SIGN;
    PPKCS7_ATTR_VERIFY = Pointer;
    PPPKCS7_ATTR_VERIFY = ^PPKCS7_ATTR_VERIFY;
{$ENDREGION}

{$REGION 'ECDH'}

    ecdh_kdf = function(const _in: Pointer; _inlen: TC_SIZE_T; _out: Pointer; var _outlen: TC_SIZE_T): pointer; cdecl;

    PPECDH_METHOD = ^PECDH_METHOD;
    ECDH_METHOD = record
        _name: PAnsiChar;
      _compute_key: function(_key: Pointer; _outlen: TC_SIZE_T; const _pub_key: PEC_POINT; _ecdh: PEC_KEY; kdf: ecdh_kdf): TC_INT; cdecl;
      _init: function(_eckey: PEC_KEY): TC_INT; cdecl;
      _finish: function(_eckey: PEC_KEY): TC_INT; cdecl;
      _flags: TC_INT;
      _app_data: PAnsiChar;
    end; { record }

{$ENDREGION}

{$REGION 'ECDSA'}

    PECDSA_SIG = ^ECDSA_SIG;
    PPECDSA_SIG = ^PECDSA_SIG;
    ECDSA_SIG = record
        _r: PBIGNUM;
        _s: PBIGNUM;
    end; { record }

    PPECDSA_METHOD = ^PECDSA_METHOD;
    ECDSA_METHOD = record
        _name: PAnsiChar;
        ecdsa_do_sign: function(const _dgst: PAnsiChar; _dgst_len: TC_INT; const _inv: PBIGNUM; const _rp: PBIGNUM; _eckey: PEC_KEY): PECDSA_SIG; cdecl;
        ecdsa_sign_setup: function(_eckey: PEC_KEY; _ctx: PBN_CTX; _kinv: PPBIGNUM ; _r: PPBIGNUM ): TC_INT; cdecl;
        ecdsa_do_verify: function(const _dgst: PAnsiChar; _dgst_len: TC_INT; const _sig: PPECDSA_SIG; _eckey: PPEC_KEY): TC_INT; cdecl;
        init: function(_eckey: PEC_KEY): TC_INT; cdecl;
        finish: function(_eckey: PEC_KEY): TC_INT; cdecl;
        _flags: TC_INT;
        _app_data: PAnsiChar;
    end; { record }

{$ENDREGION}

{$REGION 'HMAC'}
    PHMAC_CTX = ^HMAC_CTX;
    PPHMAC_CTX = ^PHMAC_CTX;
    HMAC_CTX = record
        _md: PEVP_MD;
        _md_ctx: EVP_MD_CTX;
        _i_ctx: EVP_MD_CTX;
        _o_ctx: EVP_MD_CTX;
        _key_length: TC_UINT;
        key: array[0..HMAC_MAX_MD_CBLOCK - 1] of ansichar;
    end; { record }
    
{$ENDREGION}


{$REGION 'IDEA'}

  PIDEA_KEY_SCHEDULE = ^IDEA_KEY_SCHEDULE;
    PPIDEA_KEY_SCHEDULE = ^PIDEA_KEY_SCHEDULE;
    IDEA_KEY_SCHEDULE = record  
     _data: array[0..8,0..5] of IDEA_INT;
    end;

{$ENDREGION}

{$REGION 'MD4'}

    PMD4_CTX = ^MD4_CTX;
    PPMD4_CTX = ^PMD4_CTX;
    MD4_CTX = record
        A,B,C,D: MD4_LONG;
        Nl,Nh: MD4_LONG;
        data: array[0..MD4_LBLOCK - 1] of MD4_LONG;
        _num: TC_UINT;
    end; { record }

{$ENDREGION}

{$REGION 'MD5'}

    PMD5_CTX = ^MD5_CTX;
    PPMD5_CTX = ^PMD5_CTX;
    MD5_CTX = record
        A,B,C,D: MD5_LONG;
        Nl,Nh: MD5_LONG;
        data: array[0..MD5_LBLOCK-1] of MD5_LONG;
        _num: TC_UINT;
    end; { record }

{$ENDREGION}

{$REGION 'MDC2'}

    PMDC2_CTX = ^MDC2_CTX;
    PPMDC2_CTX = ^PMDC2_CTX;
    MDC2_CTX = record
        _num: TC_UINT;
        _data: array[0..MDC2_BLOCK-1] of AnsiChar;
        _h, _hh: DES_cblock;
        _pad_type: TC_INT;
    end; { record }

{$ENDREGION}

{$REGION 'OCSP}

    POCSP_CERTID = ^OCSP_CERTID;
    PPOCSP_CERTID = ^POCSP_CERTID;
    OCSP_CERTID = record
        _hashAlgorithm: PX509_ALGOR;
        _issuerNameHash: PASN1_OCTET_STRING;
        _issuerKeyHash: PASN1_OCTET_STRING;
        _serialNumber: PASN1_INTEGER;
    end; { record }
    PSTACK_OF_OCSP_CERT_ID = PSTACK_OF;

    POCSP_ONEREQ = ^OCSP_ONEREQ;
    PPOCSP_ONEREQ = ^POCSP_ONEREQ;
    OCSP_ONEREQ = record
        _reqCert: POCSP_CERTID;
        _singleRequestExtensions: PSTACK_OF_X509_EXTENSION;
    end; { record }
    PSTACK_OF_OCSP_ONEREQ = PSTACK_OF;

    POCSP_REQINFO = ^OCSP_REQINFO;
    PPOCSP_REQINFO = ^POCSP_REQINFO;
    OCSP_REQINFO = record
        _version: PASN1_INTEGER;
        _requestorName: PGENERAL_NAME;
        _requestList: PSTACK_OF_OCSP_ONEREQ;
        _requestExtensions: PSTACK_OF_X509_EXTENSION;
    end; { record }

    POCSP_SIGNATURE = ^OCSP_SIGNATURE;
    PPOCSP_SIGNATURE = ^POCSP_SIGNATURE;
    OCSP_SIGNATURE = record
        _signatureAlgorithm: PX509_ALGOR;
        _signature: PASN1_BIT_STRING;
        _certs: PSTACK_OF_X509;
    end; { record }

    POCSP_REQUEST = ^OCSP_REQUEST;
    PPOCSP_REQUEST = ^POCSP_REQUEST;
    OCSP_REQUEST = record
        _tbsRequest: POCSP_REQINFO;
        _optionalSignature: POCSP_SIGNATURE; 
    end; { record }

    POCSP_RESPBYTES = ^OCSP_RESPBYTES;
    PPOCSP_RESPBYTES = ^POCSP_RESPBYTES;
    OCSP_RESPBYTES = record
        _responseType: PASN1_OBJECT;
        _response: PASN1_OCTET_STRING;
    end; { record }

    POCSP_RESPONSE = ^OCSP_RESPONSE;
    PPOCSP_RESPONSE = ^POCSP_RESPONSE;
    OCSP_RESPONSE = record
        _responseStatus: PASN1_ENUMERATED;
        _responseBytes: POCSP_RESPBYTES ;
    end; { record }

    OCSP_RESPONDER_ID_union = record
    case byte of
        0: (_byName: PX509_NAME);
        1: (_byKey: PASN1_OCTET_STRING);
    end; { record }

    POCSP_RESPID = ^OCSP_RESPID;
    PPOCSP_RESPID = ^POCSP_RESPID;
    OCSP_RESPID = record
        _type: TC_INT;
        _value: OCSP_RESPONDER_ID_union; 
    end; { record }

    PSTACK_OF_OCSP_RESPID = PSTACK_OF;

    POCSP_REVOKEDINFO = ^OCSP_REVOKEDINFO;
    PPOCSP_REVOKEDINFO = ^POCSP_REVOKEDINFO;
    OCSP_REVOKEDINFO = record
        _revocationTime: PASN1_GENERALIZEDTIME;
        _revocationReason: PASN1_ENUMERATED;
    end; { record }

    OCSP_CERTSTATUS_union = record
    case byte of    
        0: (_good: PASN1_NULL);
        1: (_revoked: POCSP_REVOKEDINFO);
        2: (_unknown: PASN1_NULL);
    end; { record }

    POCSP_CERTSTATUS = ^OCSP_CERTSTATUS;
    PPOCSP_CERTSTATUS = ^POCSP_CERTSTATUS;
    OCSP_CERTSTATUS = record
        _type: TC_INT;
        _value :OCSP_CERTSTATUS_union;
    end;
    
    POCSP_SINGLERESP = ^OCSP_SINGLERESP;
    PPOCSP_SINGLERESP = ^POCSP_SINGLERESP;
    OCSP_SINGLERESP = record
        _certId: POCSP_CERTID;
        _certStatus: POCSP_CERTSTATUS;
        _thisUpdate: PASN1_GENERALIZEDTIME;
        _nextUpdate: PASN1_GENERALIZEDTIME;
        _singleExtensions: PSTACK_OF_X509_EXTENSION;
    end; { record }
    PSTACK_OF_OCSP_SINGLERESP = PSTACK_OF;

    POCSP_RESPDATA = ^OCSP_RESPDATA;
    PPOCSP_RESPDATA = ^POCSP_RESPDATA;
    OCSP_RESPDATA = record
        _version: PASN1_INTEGER;
        _responderId: POCSP_RESPID ;
        _producedAt: PASN1_GENERALIZEDTIME;
        _responses: PSTACK_OF_OCSP_SINGLERESP;
        _responseExtensions: PSTACK_OF_X509_EXTENSION;
    end; { record }

    POCSP_BASICRESP = ^OCSP_BASICRESP;
    PPOCSP_BASICRESP = ^POCSP_BASICRESP;
    OCSP_BASICRESP = record
        _tbsResponseData: POCSP_RESPDATA;
        _signatureAlgorithm: PX509_ALGOR;
        _signature: PASN1_BIT_STRING;
        _certs: PSTACK_OF_X509;
    end; { record }

    POCSP_CRLID = ^OCSP_CRLID;
    PPOCSP_CRLID = ^POCSP_CRLID;
    OCSP_CRLID = record
        _crlUrl: PASN1_IA5STRING;
        _crlNum: PASN1_INTEGER;
        _crlTime: PASN1_GENERALIZEDTIME;
    end; { record }
  
    POCSP_SERVICELOC = ^OCSP_SERVICELOC;
    PPOCSP_SERVICELOC = ^POCSP_SERVICELOC;      
    OCSP_SERVICELOC = record
        _issuer: PX509_NAME;
        _locator: PSTACK_OF_ACCESS_DESCRIPTION;
    end; { record }

    POCSP_REQ_CTX  = ^OCSP_REQ_CTX ;
    PPOCSP_REQ_CTX  = ^POCSP_REQ_CTX ;
    OCSP_REQ_CTX = record
      _state: TC_INT;       
      _iobuf: PAnsiChar;    
      _iobuflen: TC_INT;        
      _io: PBIO;        
      _mem: PBIO;       
      _asn1_len: TC_ULONG;
    end;


{$ENDREGION}

    PRC2_KEY = ^RC2_KEY;
    PPRC2_KEY = ^PRC2_KEY;
    RC2_KEY = record
        _data: array[0..63] of RC2_INT;
    end; { record }

    PRC4_KEY = ^RC4_KEY;
    PPRC4_KEY = ^PRC4_KEY;
    RC4_KEY = record
        _x, _y: RC4_INT;
        _data: array[0..255] of RC4_INT;
    end; { record }

    PRC5_KEY = ^RC5_KEY;
    PPRC5_KEY = ^PRC5_KEY;
    RC5_KEY = record
        _rounds: TC_INT;
        _data: array[0..(2*(RC5_16_ROUNDS+1))-1] of RC5_32_INT;
    end; { record }

    RC5_32_KEY = RC5_KEY;
    PRC5_32_KEY = ^RC5_32_KEY;
    PPRC5_32_KEY = ^PRC5_32_KEY;

    PRIPEMD160_CTX = ^RIPEMD160_CTX;
    PPRIPEMD160_CTX = ^PRIPEMD160_CTX;
    RIPEMD160_CTX = record
      _A,_B,_C,_D,_E: RIPEMD160_LONG;
      _Nl,_Nh: RIPEMD160_LONG;
      _data: array [0..RIPEMD160_LBLOCK-1] of RIPEMD160_LONG;
      _num: TC_UINT;
    end; { record }

    PSHA_CTX = ^SHA_CTX;
    PPSHA_CTX = ^PSHA_CTX;
    SHA_CTX = record
      _h0,_h1,_h2,_h3,_h4: SHA_LONG;
      _Nl,_Nh: SHA_LONG;
      _data: array[0..SHA_LBLOCK-1] of SHA_LONG;
      _num: TC_UINT;
    end; { record }

    PSHA256_CTX = ^SHA256_CTX;
    PPSHA256_CTX = ^PSHA256_CTX;
    SHA256_CTX = record
      _h: array[0..7] of SHA_LONG;
      _Nl,_Nh: SHA_LONG;
      _data: array[0..SHA_LBLOCK-1] of SHA_LONG;
      _num,_md_len: TC_UINT;
    end; { record }

    SHA512_CTX_union = record
    case Byte of
      0: (_d: array [0..SHA_LBLOCK - 1] of SHA_LONG64);
      1: (_p: array [0..SHA512_CBLOCK - 1] of AnsiChar);
    end; { record }

    PSHA512_CTX = ^SHA512_CTX;
    PPSHA512_CTX = ^PSHA512_CTX;
    SHA512_CTX = record
      _h: array[0..7] of SHA_LONG64;
      _Nl, _Nh: SHA_LONG64;
      _u: SHA512_CTX_union;
      _num,_md_len: TC_UINT;
    end; { record }

{$REGION 'SSL'}
 
  PPSSL = ^PSSL;
  PSSL_CIPHER = ^SSL_CIPHER;
  PPSSL_CIPHER = ^PSSL_CIPHER;
  
  PSSL3_ENC_METHOD = Pointer; //^SSL3_ENC_METHOD;
  PPSSL3_ENC_METHOD = ^PSSL3_ENC_METHOD;
  PSSL_SESSION = ^SSL_SESSION;
  PPSSL_SESSION = ^PSSL_SESSION;
  PSSL_METHOD = ^SSL_METHOD;
  PPSSL_METHOD = ^PSSL_METHOD;
  PSRP_CTX = ^SRP_CTX;
  PPSRP_CTX = ^PSRP_CTX;
  PSSL_COMP = ^SSL_COMP;
  PPSSL_COMP = ^PSSL_COMP;
  PSSL_CTX = ^SSL_CTX;
  PPSSL_CTX = ^PSSL_CTX;
  PCERT = pointer;
  PSSL3_BUF_FREELIST = Pointer;
  PSSL2_STATE = Pointer;
  PSSL3_STATE = Pointer;
  PDTLS1_STATE = Pointer;

  SSL_METHOD_CALLBACK_FN = procedure; cdecl;

  PSRTP_PROTECTION_PROFILE = ^SRTP_PROTECTION_PROFILE;
  PPSRTP_PROTECTION_PROFILE = ^PSRTP_PROTECTION_PROFILE;
  SRTP_PROTECTION_PROFILE = record
    _name: PAnsiChar;
    _id: TC_LONG;
  end; { record }

  PSTACK_OF_SSL_CIPHER = PSTACK_OF;
  PSTACK_OF_SRTP_PROTECTION_PROFILE = PSTACK_OF;
  PSTACK_OF_SSL_COMP = PSTACK_OF;
  PLHASH_OF_SSL_SESSION = PLHASH_OF;

  GEN_SESSION_CB = function(const _ssl: PSSL; _id: PAnsiChar; var _id_len: TC_UINT): TC_INT; cdecl;

  TLS_SESSION_TICKET_EXT_CB_FN = function(_s: PSSL; const _data: PAnsiChar; _len: TC_INT; _arg: Pointer): TC_INT; cdecl;
  TLS_SESSION_SECRET_CB_FN = function(_s: PSSL; _secret: Pointer; var _secret_len: TC_INT; _peer_ciphers: PSTACK_OF_SSL_CIPHER; _cipher: PPSSL_CIPHER; _arg: Pointer): TC_INT; cdecl;
  
  PTLS_SESSION_TICKET_EXT = ^TLS_SESSION_TICKET_EXT;
  PPTLS_SESSION_TICKET_EXT = ^PTLS_SESSION_TICKET_EXT;   
  TLS_SESSION_TICKET_EXT = record
    _length: TC_USHORT;
    _data: Pointer;
  end; { record }
  
       
  SSL_CIPHER = record
    _valid: TC_INT;
    _name: PAnsiChar;
    _id: TC_ULONG;
    _algorithm_mkey: TC_ULONG;
    _algorithm_auth: TC_ULONG;
    _algorithm_enc: TC_ULONG;
    _algorithm_mac: TC_ULONG;
    _algorithm_ssl: TC_ULONG;
    _algo_strength: TC_ULONG;
    _algorithm2: TC_ULONG;
    _strength_bits: TC_INT;
    _alg_bits: TC_INT;
  end; { record }
 
  SSL_METHOD = record
    _version: TC_INT;
    ssl_new: function(_s: PSSL): TC_INT; cdecl;
    ssl_clear: procedure(_s: PSSL); cdecl;
    ssl_free: procedure(_s: PSSL); cdecl;
    ssl_accept: function(_s: PSSL): TC_INT; cdecl;
    ssl_connect: function(_s: PSSL): TC_INT; cdecl;
    ssl_read: function(_s: PSSL; _buf: Pointer;_len: TC_INT): TC_INT; cdecl;
    ssl_peek: function(_s: PSSL; _buf: Pointer; _len: TC_INT): TC_INT; cdecl;
    ssl_write: function(_s: PSSL; const _buf: Pointer; len: TC_INT): TC_INT; cdecl;
    ssl_shutdown: function(_s: PSSL): TC_INT; cdecl;
    ssl_renegotiate: function(_s: PSSL): TC_INT; cdecl;
    ssl_renegotiate_check: function(_s: PSSL): TC_INT; cdecl;
    ssl_get_message: function(_s: PSSL; _st1: TC_INT; _stn: TC_INT; _mt: TC_INT; _max: TC_LONG; var _ok: TC_INT): TC_INT; cdecl;
    ssl_read_bytes: function(_s: PSSL; _type: TC_INT; _buf: PAnsiChar; len: TC_INT; _peek: TC_INT): TC_INT; cdecl;
    ssl_write_bytes: function(_s: PSSL; _type: TC_INT; const _buf: Pointer; len: TC_INT): TC_INT; cdecl;
    ssl_dispatch_alert: function(_s: PSSL): TC_INT; cdecl;
    ssl_ctrl: function(_s: PSSL; _cmd: TC_INT; _larg: TC_LONG; _parg: Pointer): TC_LONG; cdecl;
    ssl_ctx_ctrl: function(_ctx: PSSL_CTX; _cmd: TC_INT; _larg: TC_LONG; _parg: Pointer): TC_LONG; cdecl;
    get_cipher_by_char: function(const _ptr: PAnsiChar): PSSL_CIPHER; cdecl;
    put_cipher_by_char: function(const _cipher: PSSL_CIPHER; _ptr: PAnsiChar): TC_INT; cdecl;
    ssl_pending: function(const _s: PSSL): TC_INT; cdecl;
    num_ciphers: function: TC_INT; cdecl;
    get_cipher: function(_ncipher: TC_INT): PSSL_CIPHER; cdecl;
    get_ssl_method: function(_version: TC_INT): PSSL_METHOD; cdecl;
    get_timeout: function: TC_LONG; cdecl;
    ssl3_enc: function: PSSL3_ENC_METHOD;  cdecl;
    ssl_version: function: TC_INT; cdecl;
    ssl_callback_ctrl: function(_s: PSSL; _cb_id: TC_INT; fp: SSL_METHOD_CALLBACK_FN): TC_LONG; cdecl;
    ssl_ctx_callback_ctrl: function(_s: PSSL_CTX; _cb_id: TC_INT; fp: SSL_METHOD_CALLBACK_FN): TC_LONG; cdecl;
  end; { record }


  SSL_SESSION = record
    _ssl_version: TC_INT;  
    _key_arg_length: TC_UINT;
    _key_arg: array[0..SSL_MAX_KEY_ARG_LENGTH-1] of AnsiChar;
    _master_key_length: TC_INT;
    _master_key: array[0..SSL_MAX_MASTER_KEY_LENGTH - 1] of AnsiChar;
    _session_id_length: TC_UINT;
    _session_id: array[0..SSL_MAX_SSL_SESSION_ID_LENGTH - 1] of AnsiChar;
    _sid_ctx_length: TC_UINT;
    _sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH - 1] of AnsiChar;
    _krb5_client_princ_len: TC_UINT;
    _krb5_client_princ: array[0..SSL_MAX_KRB5_PRINCIPAL_LENGTH - 1] of AnsiChar;
    _psk_identity_hint: PAnsiChar;
    _psk_identity: PAnsiChar;
    _not_resumable: TC_INT;
    _peer: PX509;
    _verify_result: TC_LONG; 
    _references: TC_INT;
    _timeout: TC_LONG;
    _time: TC_LONG;
    _compress_meth: TC_UINT;    
    _cipher: PSSL_CIPHER;
    _cipher_id: TC_ULONG;
    _ciphers: PSTACK_OF_SSL_CIPHER;
    _ex_data: PCRYPTO_EX_DATA; 
    _prev, _next: PSSL_SESSION;
    _tlsext_hostname: PAnsiChar;
    _tlsext_ecpointformatlist_length: TC_SIZE_T;
    _tlsext_ecpointformatlist: PAnsiChar;
    _tlsext_ellipticcurvelist_length: TC_SIZE_T;
    _tlsext_ellipticcurvelist: PAnsiChar;
    _tlsext_tick: PAnsiChar;    
    _tlsext_ticklen: TC_SIZE_T;     
    _tlsext_tick_lifetime_hint: TC_LONG;
    _srp_username: PAnsiChar;
  end; { record }

  SRP_CTX = record
    _SRP_cb_arg: Pointer;  
    TLS_ext_srp_username_callback: function(_s: PSSL; var _i: TC_INT; _p: Pointer): TC_INT; cdecl;
    SRP_verify_param_callback: function(_s: PSSL; _p: Pointer): TC_INT; cdecl;
    SRP_give_srp_client_pwd_callback: function(_s: PSSL; _p: Pointer): PAnsiChar; cdecl;
    _login: PAnsiChar;
    _N,_g,_s,_B,_A: PBIGNUM;
    _aa,_bb,_v: PBIGNUM;
    _info: PAnsiChar;
    _strength: TC_INT;
    _srp_Mask: TC_LONG;
  end; { record }

  SSL_COMP = record
    _id: TC_INT;
    _name: PAnsiChar;
{$ifndef OPENSSL_NO_COMP}
    _method: PCOMP_METHOD;
{$else}
    _method: PAnsiChar;
{$endif}
  end; { record }

  SSL_CTX_STATS = record
    _sess_connect: TC_INT;
    _sess_connect_renegotiate: TC_INT;
    _sess_connect_good: TC_INT;
    _sess_accept: TC_INT;
    _sess_accept_renegotiate: TC_INT;
    _sess_accept_good: TC_INT;
    _sess_miss: TC_INT;
    _sess_timeout: TC_INT;
    _sess_cache_full: TC_INT;
    _sess_hit: TC_INT;
    _sess_cb_hit: TC_INT;
  end; { record }

  SSL_CTX = record
    _method: PSSL_METHOD;
    _cipher_list: PSTACK_OF_SSL_CIPHER;
    _cipher_list_by_id: PSTACK_OF_SSL_CIPHER;
    _cert_store: PX509_STORE ;
    _sessions: PLHASH_OF_SSL_SESSION;
    _session_cache_size: TC_ULONG;
    _session_cache_head: PSSL_SESSION;
    _session_cache_tail: PSSL_SESSION;
    _session_cache_mode: TC_INT;
    _session_timeout: TC_LONG;
    new_session_cb: function(_ssl: PSSL; _sess: PSSL_SESSION): TC_INT; cdecl;
    remove_session_cb: procedure(_ctx: PSSL; _sess: PSSL_SESSION); cdecl;
    get_session_cb: function(_ssl: PSSL; _data: PAnsiChar; _len: TC_INT; var _copy: TC_INT): PSSL_SESSION; cdecl;
    _stats: SSL_CTX_STATS;
    _references: TC_INT;
    app_verify_callback: function(_ctx: PX509_STORE_CTX; _p: Pointer): TC_INT; cdecl;
    app_verify_arg: function: Pointer; cdecl;
    _default_passwd_callback: pem_password_cb;
    _default_passwd_callback_userdata: Pointer;
    client_cert_cb: function(_ssl: PSSL; _x509: PPX509; _pkey: PPEVP_PKEY): TC_INT; cdecl;
    app_gen_cookie_cb: function(_ssl: PSSL; _cookie: PAnsiChar; var _cookie_len: TC_INT): TC_INT; cdecl;
    app_verify_cookie_cb: function(_ssl: PSSL; _cookie: PAnsiChar; _cookie_len: TC_UINT): TC_INT; cdecl;
    _ex_data: CRYPTO_EX_DATA;
    _rsa_md5: PEVP_MD;
    _md5: PEVP_MD;  
    _sha1: PEVP_MD;   
    _extra_certs: PSTACK_OF_X509;
    _comp_methods: PSTACK_OF_SSL_COMP;
    info_callback: procedure(const _ssl: PSSL; _type: TC_INT; _val: TC_INT);  cdecl;
    _client_CA: PSTACK_OF_X509_NAME;
    _options: TC_ULONG;
    _mode: TC_ULONG;
    _max_cert_list: TC_LONG;
    _cert: PCERT;
    _read_ahead: TC_INT;
    msg_callback: procedure(_write_p: TC_INT; _version: TC_INT; _content_type: TC_INT; const _buf: Pointer; _len: TC_SIZE_T; _ssl: PSSL;  _arg: Pointer); cdecl;
    _msg_callback_arg: Pointer;
    _verify_mode: TC_INT;
    _sid_ctx_length: TC_UINT;
    _sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH - 1] of AnsiChar;
    default_verify_callback: function(_ok: TC_INT; _ctx: PX509_STORE_CTX): TC_INT; cdecl;
    _generate_session_id: GEN_SESSION_CB;
    _param: PX509_VERIFY_PARAM;
    _purpose: TC_INT;
    _trust: TC_INT;
    _quiet_shutdown: TC_INT;
    _max_send_fragment: TC_UINT;
    _client_cert_engine: PENGINE;
    tlsext_servername_callback: function(_s: PSSL; _i: PC_INT; _p: Pointer): TC_INT; cdecl;
    _tlsext_servername_arg: Pointer;
    _tlsext_tick_key_name: array[0..15] of ansichar;
    _tlsext_tick_hmac_key: array[0..15] of ansichar;
    _tlsext_tick_aes_key: array[0..15] of ansichar;
    tlsext_ticket_key_cb: function(_ssl: PSSL; _name: PAnsiChar; _iv: PAnsiChar; _ectx: PEVP_CIPHER_CTX; _hctx: PHMAC_CTX; _enc: TC_INT): TC_INT; cdecl;
    tlsext_status_cb: function(_ssl: PSSL; _arg: Pointer): TC_INT; cdecl;
    _tlsext_status_arg: Pointer;
    tlsext_opaque_prf_input_callback: function(_s: PSSL; _peerinput: Pointer; _len: TC_SIZE_T; _arg: Pointer): TC_INT; cdecl;
    _tlsext_opaque_prf_input_callback_arg: Pointer;

    _psk_identity_hint: PAnsiChar;
    psk_client_callback: function(_ssl: PSSL; const _hint: PAnsiChar; _identity: PAnsiChar; _max_identity_len: TC_UINT; _psk: PAnsiChar; _max_psk_len: TC_UINT): TC_UINT; cdecl;
    psk_server_callback: function(_ssl: PSSL; const _identity: PAnsiChar; _psk: PAnsiChar; _max_psk_len: TC_UINT): TC_UINT; cdecl;

    _freelist_max_len: TC_UINT;
    _wbuf_freelist: PSSL3_BUF_FREELIST;
    _rbuf_freelist: PSSL3_BUF_FREELIST;
    _srp_ctx: SRP_CTX; 
    next_protos_advertised_cb: function(_s: PSSL; const _buf: PPAnsiChar; _len: PC_UINT; _arg: PAnsiChar): TC_INT; cdecl;
    _next_protos_advertised_cb_arg: Pointer;
    next_proto_select_cb: function(_s: PSSL; _out: PPAnsiChar; _outlen: PAnsiChar; const _in: PAnsiChar; _inlen: TC_UINT; _arg: Pointer): TC_INT; cdecl;
    _next_proto_select_cb_arg: Pointer;
    _srtp_profiles: PSTACK_OF_SRTP_PROTECTION_PROFILE;  
  end; { record }

  PKSSL_CTX = Pointer;

  SSL = record
    _version: TC_INT;
    _type: TC_INT; 
    _method: PSSL_METHOD;
{$IFNDEF NO_BIO}
    _rbio: PBIO;
    _wbio: PBIO;
    _bbio: PBIO;
{$else}
    _rbio: PAnsiChar;
    _wbio: PAnsiChar; 
    _bbio: PAnsiChar;
{$endif}
    _rwstate: TC_INT;
    _in_handshake: TC_INT;
    handshake_func: function(_s: PSSL): TC_INT; cdecl;
    _server: TC_INT;
    _new_session: TC_INT;
    _quiet_shutdown: TC_INT;
    _shutdown: TC_INT;
    _state: TC_INT;
    _rstate: TC_INT;
    _init_buf: PBUF_MEM;
    _init_msg: Pointer;
    _init_num: TC_INT;
    _init_off: TC_INT;
    _packet: PAnsiChar;
    _packet_length: TC_UINT;

    _s2: PSSL2_STATE;
    _s3: PSSL3_STATE;
    _d1: PDTLS1_STATE;
    _read_ahead: TC_INT;

    msg_callback: procedure(_write_p: TC_INT; _version: TC_INT; _content_type: TC_INT; const _buf: Pointer; _len: TC_SIZE_T; _ssl: PSSL; _arg: Pointer); cdecl;
    _msg_callback_arg: Pointer;

    _hit: TC_INT;

    _param: PX509_VERIFY_PARAM;

    _purpose: TC_INT;
    _trust: TC_INT;

    _cipher_list: PSTACK_OF_SSL_CIPHER;
    _cipher_list_by_id: PSTACK_OF_SSL_CIPHER;

    _mac_flags: TC_INT; 
    _enc_read_ctx: PEVP_CIPHER_CTX;
    _read_hash: PEVP_MD_CTX;
{$ifndef OPENSSL_NO_COMP}
    _expand: PCOMP_CTX;
{$else}
    _expand: PAnsiChar;
{$endif}
    _enc_write_ctx: PEVP_CIPHER_CTX;
    _write_hash: PEVP_MD_CTX;
{$ifndef OPENSSL_NO_COMP}
    _compress: PCOMP_CTX;
{$else}
    _compress: PAnsiChar;   
{$endif}

    _cert: PCERT;

    _sid_ctx_length: TC_INT;
    _sid_ctx: array[0..SSL_MAX_SID_CTX_LENGTH - 1] of ansichar;

    _session: PSSL_SESSION;
    _generate_session_id: GEN_SESSION_CB;

    _verify_mode: TC_INT;   
    verify_callback: function(_ok: TC_INT; _ctx: PX509_STORE_CTX): TC_INT; cdecl;
    info_callback: procedure(const _ssl: PSSL; _type: TC_INT; _val: TC_INT); cdecl;

    _error: TC_INT;
    _error_code: TC_INT;

{$ifndef OPENSSL_NO_KRB5}
    _kssl_ctx: PKSSL_CTX;    
{$endif}

{$ifndef OPENSSL_NO_PSK}
    psk_client_callback: function(_ssl: PSSL; const _hint: PAnsiChar; _identity: PAnsiChar; _max_identity_len: TC_UINT; _psk: PAnsiChar; _max_psk_len: TC_UINT): TC_UINT; cdecl;
    psk_server_callback: function(_ssl: PSSL; const _identity: PAnsiChar; _psk: PAnsiChar; _max_psk_len: TC_UINT): TC_INT; cdecl;
{$endif}

    _ctx: PSSL_CTX;
    _debug: TC_INT; 

    _verify_result: TC_LONG;
    _ex_data: CRYPTO_EX_DATA;

    _client_CA: PSTACK_OF_X509_NAME;

    _references: TC_INT;
    _options: TC_ULONG;
    _mode: TC_ULONG;
    _max_cert_list: TC_LONG;
    _first_packet: TC_INT;
    _client_version: TC_INT;
    _max_send_fragment: TC_UINT;

{$ifndef OPENSSL_NO_TLSEXT}
    tlsext_debug_cb: procedure(_s: PSSL; _client_server: TC_INT; _type: TC_INT; _data: PAnsiChar; _len: TC_INT; _arg: Pointer); cdecl;
    _tlsext_debug_arg: Pointer;
    _tlsext_hostname: PAnsiChar;
    _servername_done: TC_INT;
    _tlsext_status_type: TC_INT;
    _tlsext_status_expected: TC_INT;
    _tlsext_ocsp_ids: PSTACK_OF_OCSP_RESPID;
    _tlsext_ocsp_exts: PX509_EXTENSIONS;
    _tlsext_ocsp_resp: PAnsiChar;
    _tlsext_ocsp_resplen: TC_INT;
    _tlsext_ticket_expected: TC_INT;
{$ifndef OPENSSL_NO_EC}
    _tlsext_ecpointformatlist_length: TC_SIZE_T;
    _tlsext_ecpointformatlist: PAnsiChar; 
    _tlsext_ellipticcurvelist_length: TC_SIZE_T;
    _tlsext_ellipticcurvelist: PAnsiChar; 
{$endif}

    _tlsext_opaque_prf_input: Pointer;
    _tlsext_opaque_prf_input_len: TC_SIZE_T;

    _tlsext_session_ticket: PTLS_SESSION_TICKET_EXT;

    _tls_session_ticket_ext_cb: TLS_SESSION_TICKET_EXT_CB_FN;
    _tls_session_ticket_ext_cb_arg: Pointer;

    _tls_session_secret_cb: TLS_SESSION_SECRET_CB_FN;
    _tls_session_secret_cb_arg: Pointer;

    _initial_ctx: PSSL_CTX;
{$endif}

{$ifndef OPENSSL_NO_NEXTPROTONEG}
     _next_proto_negotiated: PAnsiChar;
    _ext_proto_negotiated_len: PAnsiChar;
{$endif}


    _srtp_profiles: PSTACK_OF_SRTP_PROTECTION_PROFILE;
    _srtp_profile: PSRTP_PROTECTION_PROFILE;

    _tlsext_heartbeat: TC_UINT;  
    _tlsext_hb_pending: TC_UINT;
    _tlsext_hb_seq: TC_UINT;

  _renegotiate: TC_INT;

{$ifndef OPENSSL_NO_SRP}
    _srp_ctx: SRP_CTX; 
{$endif}
  end; { record }



{$ENDREGION}
implementation

end.