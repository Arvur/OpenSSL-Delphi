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
  TC_ULONG = LongWord;
  PC_ULONG = ^TC_ULONG;
  TC_ULONGLONG = qword;
  TC_time_t = TC_LONG;

  BN_ULONG = TC_ULONGLONG;
  PBN_ULONG = ^BN_ULONG;

  BIGNUM = record
    d : PBN_ULONG;
    top : TC_INT;
    dmax : TC_INT;
    neg : TC_INT;
    flags : TC_INT;
  end;
  PBIGNUM = ^BIGNUM;

  buf_mem_st = record
    length : TC_INT;
    data : PAnsiChar;
    max: TC_INT;
  end;
  BUF_MEM = buf_mem_st;
  PBUF_MEM = ^BUF_MEM;


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

  EC_builtin_curve = record
    nid : TC_INT;
    comment : PAnsiChar;
  end;

  EC_builtin_curves = array[0..0] of EC_builtin_curve;
  PEC_builtin_curves = ^EC_builtin_curves;

  EC_GROUP = Pointer;
  PEC_KEY = Pointer;

  PENGINE = Pointer;

  BN_MONT_CTX = record
    ri : TC_INT;
    n0 : BN_ULONG;
    flags : TC_INT;
  end;
  PBN_MONT_CTX = ^BN_MONT_CTX;

  STACK = record
    num : TC_INT;
    data : PAnsiChar;
    sorted : TC_INT;
    num_alloc : TC_INT;
    comp : function (_para1: PPAnsiChar; _para2: PPAnsiChar):  TC_INT; cdecl;
  end;
  PSTACK          = ^STACK;

  STACK_OF_IPAddressFamily = record
    _stack: stack;
  end;
  PSTACK_OF_IPAddressFamily = ^STACK_OF_IPAddressFamily;

  PSTACK_OF_ASN1_TYPE = ^PSTACK;
  PSTACK_OF_ASN1_OBJECT = PSTACK;
  PSTACK_OF_GENERAL_NAME = PSTACK;
  PGENERAL_NAMES = PSTACK_OF_GENERAL_NAME;
  PSTACK_OF_ASIdOrRange = PSTACK;
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;
  PSTACK_OF_CONF_VALUE = PSTACK;

  CRYPTO_EX_DATA = record
    sk : PSTACK;
    dummy : TC_INT;
  end;

  PBN_CTX = Pointer;//^BN_CTX;
  PPBN_CTX = ^PBN_CTX;

  PBN_BLINDING = pointer;


{$REGION 'BIO'}
  PBIO = ^BIO;
  PBIO_METHOD = ^BIO_METHOD;

  Pbio_info_cb = procedure (_para1 : PBIO; _para2 : TC_INT; _para3 : PAnsiChar;
     _para4 : TC_INT; _para5, _para6 : TC_LONG); cdecl;

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

{$REGION 'RSA'}
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
    // If this is non-NULL, it is used to generate DSA parameters
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

{$REGION 'DH'}

  PDH = ^DH;

  EVP_PKEY_union = record
    case byte of
      0: (ptr : PAnsiChar);
      1: (rsa : PRSA);    // RSA
      2: (dsa : PDSA);    // DSA
      3: (dh :PDH);       // DH
      4: (ec : PEC_KEY);  // ECC
  end;

  DH = record
    // The first parameter is used to pickup errors where
    // this is passed instead of aEVP_PKEY, it is set to 0
    pad : TC_INT;
    version : TC_LONG;
    meth : PRSA_METHOD;
    // functional reference if 'meth' is ENGINE-provided
    engine: PENGINE;
    n : PBIGNUM;
    e : PBIGNUM;
    d : PBIGNUM;
    p : PBIGNUM;
    q : PBIGNUM;
    dmp1 : PBIGNUM;
    dmq1 : PBIGNUM;
    iqmp : PBIGNUM;
    // be careful using this if the RSA structure is shared
    ex_data : CRYPTO_EX_DATA;
    references : TC_INT;
    flags : TC_INT;
    // Used to cache montgomery values
    _method_mod_n : BN_MONT_CTX;
    _method_mod_p : BN_MONT_CTX;
    _method_mod_q : BN_MONT_CTX;
    // all BIGNUM values are actually in the following data, if it is not NULL
    bignum_data : PAnsiChar;
    blinding : PBN_BLINDING;
    mt_blinding : PBN_BLINDING;
  end;
{$ENDREGION}

{$REGION 'EVP'}

  PEVP_MD = ^EVP_MD;
  PEVP_PKEY_CTX = pointer;


  STACK_OF_X509_ATTRIBUTE = record
    _stack: STACK;
  end;
  PSTACK_OF_X509_ATTRIBUTE = ^STACK_OF_X509_ATTRIBUTE;


  PEVP_PKEY_ASN1_METHOD = pointer;

  {$EXTERNALSYM EVP_PKEY}
  EVP_PKEY = record
    _type : TC_INT;
    save_type : TC_INT;
    references : TC_INT;
    ameth : PEVP_PKEY_ASN1_METHOD;
    pkey : EVP_PKEY_union;
    attributes : PSTACK_OF_X509_ATTRIBUTE;
  end;
  PEVP_PKEY = ^EVP_PKEY;

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

  STACK_OF_X509_REVOKED = record
    _stack: stack;
  end;
  PSTACK_OF_X509_REVOKED = ^STACK_OF_X509_REVOKED;

  STACK_OF_X509_NAME_ENTRY = record
    _stack: stack;
  end;
  PSTACK_OF_X509_NAME_ENTRY = ^STACK_OF_X509_NAME_ENTRY;

  STACK_OF_X509 = record
    _stack: STACK;
  end;
  PSTACK_OF_X509 = ^STACK_OF_X509;

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
implementation

end.
