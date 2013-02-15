unit ssl_const;

interface

const
  NID_undef = 0;
  NID_rsaEncryption = 6;
  NID_rsa = 19;
  NID_dhKeyAgreement = 28;
  NID_dsaWithSHA = 66;
  NID_dsa_2 = 67;
  NID_dsaWithSHA1_2 = 70;
  NID_dsaWithSHA1 = 113;
  NID_dsa = 116;
  NID_hmac = 855;
  NID_cmac = 894;
  NID_X9_62_id_ecPublicKey = 408;

const
  ASIdentifierChoice_inherit = 0;
  ASIdentifierChoice_asIdsOrRanges = 1;

  IPAddressOrRange_addressPrefix = 0;
  IPAddressOrRange_addressRange = 1;

  IPAddressChoice_inherit = 0;
  IPAddressChoice_addressesOrRanges = 1;

  SHA_LBLOCK = 16;
  SHA_CBLOCK = 64;
  SHA_DIGEST_LENGTH = 20;
  SHA_LAST_BLOCK = (SHA_CBLOCK - 8);
  SHA256_CBLOCK = (SHA_LBLOCK * 4);
  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;
  SHA512_CBLOCK = (SHA_LBLOCK * 8);

  EVP_MAX_MD_SIZE = 64;
  EVP_MAX_KEY_LENGTH = 32;
  EVP_MAX_IV_LENGTH = 16;
  EVP_MAX_BLOCK_LENGTH = 32;

{$REGION 'AES'}
const
  AES_ENCRYPT    = 1;
  AES_DECRYPT    = 0;

  AES_MAXNR = 14;
  AES_BLOCK_SIZE = 16;

{$ENDREGION}

{$REGION 'BlowFish'}
const
    BF_ENCRYPT  = 1;
    BF_DECRYPT  = 0;
    BF_LONG_LOG2 = 3;
    BF_ROUNDS    = 16;
    BF_BLOCK    = 8;

{$ENDREGION}

{$REGION 'ASN'}
const
 V_ASN1_UNIVERSAL               = $00;
 V_ASN1_APPLICATION             = $40;
 V_ASN1_CONTEXT_SPECIFIC        = $80;
 V_ASN1_PRIVATE                 = $c0;

 V_ASN1_CONSTRUCTED         = $20;
 V_ASN1_PRIMITIVE_TAG       = $1f;
 V_ASN1_PRIMATIVE_TAG       = $1f;

 V_ASN1_APP_CHOOSE      = -2;
 V_ASN1_OTHER           = -3;
 V_ASN1_ANY             = -4;

 V_ASN1_NEG         = $100;

 V_ASN1_UNDEF                = -1;
 V_ASN1_EOC                  = 0;
 V_ASN1_BOOLEAN              = 1;
 V_ASN1_INTEGER              = 2;
 V_ASN1_NEG_INTEGER          = (2  or  V_ASN1_NEG);
 V_ASN1_BIT_STRING           = 3;
 V_ASN1_OCTET_STRING         = 4;
 V_ASN1_NULL                 = 5;
 V_ASN1_OBJECT               = 6;
 V_ASN1_OBJECT_DESCRIPTOR    = 7;
 V_ASN1_EXTERNAL             = 8;
 V_ASN1_REAL                 = 9;
 V_ASN1_ENUMERATED           = 10;
 V_ASN1_NEG_ENUMERATED       = (10  or  V_ASN1_NEG);
 V_ASN1_UTF8STRING           = 12;
 V_ASN1_SEQUENCE             = 16;
 V_ASN1_SET                  = 17;
 V_ASN1_NUMERICSTRING        = 18;
 V_ASN1_PRINTABLESTRING      = 19;
 V_ASN1_T61STRING            = 20;
 V_ASN1_TELETEXSTRING        = 20;
 V_ASN1_VIDEOTEXSTRING       = 21;
 V_ASN1_IA5STRING            = 22;
 V_ASN1_UTCTIME              = 23;
 V_ASN1_GENERALIZEDTIME      = 24;
 V_ASN1_GRAPHICSTRING        = 25;
 V_ASN1_ISO64STRING          = 26;
 V_ASN1_VISIBLESTRING        = 26;
 V_ASN1_GENERALSTRING        = 27;
 V_ASN1_UNIVERSALSTRING      = 28;
 V_ASN1_BMPSTRING            = 30;

 B_ASN1_NUMERICSTRING   = $0001;
 B_ASN1_PRINTABLESTRING = $0002;
 B_ASN1_T61STRING       = $0004;
 B_ASN1_TELETEXSTRING   = $0004;
 B_ASN1_VIDEOTEXSTRING  = $0008;
 B_ASN1_IA5STRING       = $0010;
 B_ASN1_GRAPHICSTRING   = $0020;
 B_ASN1_ISO64STRING     = $0040;
 B_ASN1_VISIBLESTRING   = $0040;
 B_ASN1_GENERALSTRING   = $0080;
 B_ASN1_UNIVERSALSTRING = $0100;
 B_ASN1_OCTET_STRING    = $0200;
 B_ASN1_BIT_STRING      = $0400;
 B_ASN1_BMPSTRING       = $0800;
 B_ASN1_UNKNOWN         = $1000;
 B_ASN1_UTF8STRING      = $2000;
 B_ASN1_UTCTIME         = $4000;
 B_ASN1_GENERALIZEDTIME = $8000;
 B_ASN1_SEQUENCE        = $10000;

 MBSTRING_FLAG      = $1000;
 MBSTRING_UTF8      = (MBSTRING_FLAG);
 MBSTRING_ASC       = (MBSTRING_FLAG or 1);
 MBSTRING_BMP       = (MBSTRING_FLAG or 2);
 MBSTRING_UNIV      = (MBSTRING_FLAG or 4);

 SMIME_OLDMIME      = $400;
 SMIME_CRLFEOL      = $800;
 SMIME_STREAM       = $1000;

 ASN1_OBJECT_FLAG_DYNAMIC         = $01;
 ASN1_OBJECT_FLAG_CRITICAL        = $02;
 ASN1_OBJECT_FLAG_DYNAMIC_STRINGS = $04;
 ASN1_OBJECT_FLAG_DYNAMIC_DATA    = $08;
 ASN1_STRING_FLAG_BITS_LEFT       = $08;
 ASN1_STRING_FLAG_NDEF            = $010;
 ASN1_STRING_FLAG_CONT            = $020;
 ASN1_STRING_FLAG_MSTRING         = $040 ;

 ASN1_LONG_UNDEF    = $7fffffff;

 STABLE_FLAGS_MALLOC    = $01;
 STABLE_NO_MASK         = $02;
 DIRSTRING_TYPE         = (B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING);
 PKCS9STRING_TYPE       = (DIRSTRING_TYPE or B_ASN1_IA5STRING);
 
 ub_name                    = 32768;
 ub_common_name             = 64;
 ub_locality_name           = 128;
 ub_state_name              = 128;
 ub_organization_name       = 64;
 ub_organization_unit_name  = 64;
 ub_title                   = 64;
 ub_email_address           = 128;
 
 ASN1_STRFLGS_ESC_2253      = 1;
 ASN1_STRFLGS_ESC_CTRL      = 2;
 ASN1_STRFLGS_ESC_MSB       = 4;
 ASN1_STRFLGS_ESC_QUOTE     = 8;

 CHARTYPE_PRINTABLESTRING   = $10;
 CHARTYPE_FIRST_ESC_2253        = $20;
 CHARTYPE_LAST_ESC_2253     = $40;

 ASN1_STRFLGS_UTF8_CONVERT  = $10;
 ASN1_STRFLGS_IGNORE_TYPE   = $20;
 ASN1_STRFLGS_DUMP_ALL      = $80;
 ASN1_STRFLGS_DUMP_UNKNOWN  = $100;
 ASN1_STRFLGS_DUMP_DER      = $200;
 ASN1_STRFLGS_RFC2253   = (ASN1_STRFLGS_ESC_2253  or  ASN1_STRFLGS_ESC_CTRL  or  ASN1_STRFLGS_ESC_MSB  or  ASN1_STRFLGS_UTF8_CONVERT  or  ASN1_STRFLGS_DUMP_UNKNOWN  or  ASN1_STRFLGS_DUMP_DER);

 ASN1_PCTX_FLAGS_SHOW_ABSENT            = $001  ;
 ASN1_PCTX_FLAGS_SHOW_SEQUENCE          = $002;
 ASN1_PCTX_FLAGS_SHOW_SSOF              = $004;
 ASN1_PCTX_FLAGS_SHOW_TYPE              = $008;
 ASN1_PCTX_FLAGS_NO_ANY_TYPE            = $010;
 ASN1_PCTX_FLAGS_NO_MSTRING_TYPE        = $020;
 ASN1_PCTX_FLAGS_NO_FIELD_NAME          = $040;
 ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
 ASN1_PCTX_FLAGS_NO_STRUCT_NAME         = $100;

 ASN1_F_A2D_ASN1_OBJECT                      = 100;
 ASN1_F_A2I_ASN1_ENUMERATED                  = 101;
 ASN1_F_A2I_ASN1_INTEGER                     = 102;
 ASN1_F_A2I_ASN1_STRING                      = 103;
 ASN1_F_APPEND_EXP                           = 176;
 ASN1_F_ASN1_BIT_STRING_SET_BIT              = 183;
 ASN1_F_ASN1_CB                              = 177;
 ASN1_F_ASN1_CHECK_TLEN                      = 104;
 ASN1_F_ASN1_COLLATE_PRIMITIVE               = 105;
 ASN1_F_ASN1_COLLECT                         = 106;
 ASN1_F_ASN1_D2I_EX_PRIMITIVE                = 108;
 ASN1_F_ASN1_D2I_FP                          = 109;
 ASN1_F_ASN1_D2I_READ_BIO                    = 107;
 ASN1_F_ASN1_DIGEST                          = 184;
 ASN1_F_ASN1_DO_ADB                          = 110;
 ASN1_F_ASN1_DUP                             = 111;
 ASN1_F_ASN1_ENUMERATED_SET                  = 112;
 ASN1_F_ASN1_ENUMERATED_TO_BN                = 113;
 ASN1_F_ASN1_EX_C2I                          = 204;
 ASN1_F_ASN1_FIND_END                        = 190;
 ASN1_F_ASN1_GENERALIZEDTIME_ADJ             = 216;
 ASN1_F_ASN1_GENERALIZEDTIME_SET             = 185;
 ASN1_F_ASN1_GENERATE_V3                     = 178;
 ASN1_F_ASN1_GET_OBJECT                      = 114;
 ASN1_F_ASN1_HEADER_NEW                      = 115;
 ASN1_F_ASN1_I2D_BIO                         = 116;
 ASN1_F_ASN1_I2D_FP                          = 117;
 ASN1_F_ASN1_INTEGER_SET                     = 118;
 ASN1_F_ASN1_INTEGER_TO_BN                   = 119;
 ASN1_F_ASN1_ITEM_D2I_FP                     = 206;
 ASN1_F_ASN1_ITEM_DUP                        = 191;
 ASN1_F_ASN1_ITEM_EX_COMBINE_NEW             = 121;
 ASN1_F_ASN1_ITEM_EX_D2I                     = 120;
 ASN1_F_ASN1_ITEM_I2D_BIO                    = 192;
 ASN1_F_ASN1_ITEM_I2D_FP                     = 193;
 ASN1_F_ASN1_ITEM_PACK                       = 198;
 ASN1_F_ASN1_ITEM_SIGN                       = 195;
 ASN1_F_ASN1_ITEM_SIGN_CTX                   = 220;
 ASN1_F_ASN1_ITEM_UNPACK                     = 199;
 ASN1_F_ASN1_ITEM_VERIFY                     = 197;
 ASN1_F_ASN1_MBSTRING_NCOPY                  = 122;
 ASN1_F_ASN1_OBJECT_NEW                      = 123;
 ASN1_F_ASN1_OUTPUT_DATA                     = 214;
 ASN1_F_ASN1_PACK_STRING                     = 124;
 ASN1_F_ASN1_PCTX_NEW                        = 205;
 ASN1_F_ASN1_PKCS5_PBE_SET                   = 125;
 ASN1_F_ASN1_SEQ_PACK                        = 126;
 ASN1_F_ASN1_SEQ_UNPACK                      = 127;
 ASN1_F_ASN1_SIGN                            = 128;
 ASN1_F_ASN1_STR2TYPE                        = 179;
 ASN1_F_ASN1_STRING_SET                      = 186;
 ASN1_F_ASN1_STRING_TABLE_ADD                = 129;
 ASN1_F_ASN1_STRING_TYPE_NEW                 = 130;
 ASN1_F_ASN1_TEMPLATE_EX_D2I                 = 132;
 ASN1_F_ASN1_TEMPLATE_NEW                    = 133;
 ASN1_F_ASN1_TEMPLATE_NOEXP_D2I              = 131;
 ASN1_F_ASN1_TIME_ADJ                        = 217;
 ASN1_F_ASN1_TIME_SET                        = 175;
 ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING        = 134;
 ASN1_F_ASN1_TYPE_GET_OCTETSTRING            = 135;
 ASN1_F_ASN1_UNPACK_STRING                   = 136;
 ASN1_F_ASN1_UTCTIME_ADJ                     = 218;
 ASN1_F_ASN1_UTCTIME_SET                     = 187;
 ASN1_F_ASN1_VERIFY                          = 137;
 ASN1_F_B64_READ_ASN1                        = 209;
 ASN1_F_B64_WRITE_ASN1                       = 210;
 ASN1_F_BIO_NEW_NDEF                         = 208;
 ASN1_F_BITSTR_CB                            = 180;
 ASN1_F_BN_TO_ASN1_ENUMERATED                = 138;
 ASN1_F_BN_TO_ASN1_INTEGER                   = 139;
 ASN1_F_C2I_ASN1_BIT_STRING                  = 189;
 ASN1_F_C2I_ASN1_INTEGER                     = 194;
 ASN1_F_C2I_ASN1_OBJECT                      = 196;
 ASN1_F_COLLECT_DATA                         = 140;
 ASN1_F_D2I_ASN1_BIT_STRING                  = 141;
 ASN1_F_D2I_ASN1_BOOLEAN                     = 142;
 ASN1_F_D2I_ASN1_BYTES                       = 143;
 ASN1_F_D2I_ASN1_GENERALIZEDTIME             = 144;
 ASN1_F_D2I_ASN1_HEADER                      = 145;
 ASN1_F_D2I_ASN1_INTEGER                     = 146;
 ASN1_F_D2I_ASN1_OBJECT                      = 147;
 ASN1_F_D2I_ASN1_SET                         = 148;
 ASN1_F_D2I_ASN1_TYPE_BYTES                  = 149;
 ASN1_F_D2I_ASN1_UINTEGER                    = 150;
 ASN1_F_D2I_ASN1_UTCTIME                     = 151;
 ASN1_F_D2I_AUTOPRIVATEKEY                   = 207;
 ASN1_F_D2I_NETSCAPE_RSA                     = 152;
 ASN1_F_D2I_NETSCAPE_RSA_2                   = 153;
 ASN1_F_D2I_PRIVATEKEY                       = 154;
 ASN1_F_D2I_PUBLICKEY                        = 155;
 ASN1_F_D2I_RSA_NET                          = 200;
 ASN1_F_D2I_RSA_NET_2                        = 201;
 ASN1_F_D2I_X509                             = 156;
 ASN1_F_D2I_X509_CINF                        = 157;
 ASN1_F_D2I_X509_PKEY                        = 159;
 ASN1_F_I2D_ASN1_BIO_STREAM                  = 211;
 ASN1_F_I2D_ASN1_SET                         = 188;
 ASN1_F_I2D_ASN1_TIME                        = 160;
 ASN1_F_I2D_DSA_PUBKEY                       = 161;
 ASN1_F_I2D_EC_PUBKEY                        = 181;
 ASN1_F_I2D_PRIVATEKEY                       = 163;
 ASN1_F_I2D_PUBLICKEY                        = 164;
 ASN1_F_I2D_RSA_NET                          = 162;
 ASN1_F_I2D_RSA_PUBKEY                       = 165;
 ASN1_F_LONG_C2I                             = 166;
 ASN1_F_OID_MODULE_INIT                      = 174;
 ASN1_F_PARSE_TAGGING                        = 182;
 ASN1_F_PKCS5_PBE2_SET_IV                    = 167;
 ASN1_F_PKCS5_PBE_SET                        = 202;
 ASN1_F_PKCS5_PBE_SET0_ALGOR                 = 215;
 ASN1_F_PKCS5_PBKDF2_SET                     = 219;
 ASN1_F_SMIME_READ_ASN1                      = 212;
 ASN1_F_SMIME_TEXT                           = 213;
 ASN1_F_X509_CINF_NEW                        = 168;
 ASN1_F_X509_CRL_ADD0_REVOKED                = 169;
 ASN1_F_X509_INFO_NEW                        = 170;
 ASN1_F_X509_NAME_ENCODE                     = 203;
 ASN1_F_X509_NAME_EX_D2I                     = 158;
 ASN1_F_X509_NAME_EX_NEW                     = 171;
 ASN1_F_X509_NEW                             = 172;
 ASN1_F_X509_PKEY_NEW                        = 173;

//* Reason codes. */
 ASN1_R_ADDING_OBJECT                                       = 171;
 ASN1_R_ASN1_PARSE_ERROR                                    = 203;
 ASN1_R_ASN1_SIG_PARSE_ERROR                                = 204;
 ASN1_R_AUX_ERROR                                           = 100;
 ASN1_R_BAD_CLASS                                           = 101;
 ASN1_R_BAD_OBJECT_HEADER                                   = 102;
 ASN1_R_BAD_PASSWORD_READ                                   = 103;
 ASN1_R_BAD_TAG                                             = 104;
 ASN1_R_BMPSTRING_IS_WRONG_LENGTH                           = 214;
 ASN1_R_BN_LIB                                              = 105;
 ASN1_R_BOOLEAN_IS_WRONG_LENGTH                             = 106;
 ASN1_R_BUFFER_TOO_SMALL                                    = 107;
 ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER                     = 108;
 ASN1_R_CONTEXT_NOT_INITIALISED                             = 217;
 ASN1_R_DATA_IS_WRONG                                       = 109;
 ASN1_R_DECODE_ERROR                                        = 110;
 ASN1_R_DECODING_ERROR                                      = 111;
 ASN1_R_DEPTH_EXCEEDED                                      = 174;
 ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED                   = 198;
 ASN1_R_ENCODE_ERROR                                        = 112;
 ASN1_R_ERROR_GETTING_TIME                                  = 173;
 ASN1_R_ERROR_LOADING_SECTION                               = 172;
 ASN1_R_ERROR_PARSING_SET_ELEMENT                           = 113;
 ASN1_R_ERROR_SETTING_CIPHER_PARAMS                         = 114;
 ASN1_R_EXPECTING_AN_INTEGER                                = 115;
 ASN1_R_EXPECTING_AN_OBJECT                                 = 116;
 ASN1_R_EXPECTING_A_BOOLEAN                                 = 117;
 ASN1_R_EXPECTING_A_TIME                                    = 118;
 ASN1_R_EXPLICIT_LENGTH_MISMATCH                            = 119;
 ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED                        = 120;
 ASN1_R_FIELD_MISSING                                       = 121;
 ASN1_R_FIRST_NUM_TOO_LARGE                                 = 122;
 ASN1_R_HEADER_TOO_LONG                                     = 123;
 ASN1_R_ILLEGAL_BITSTRING_FORMAT                            = 175;
 ASN1_R_ILLEGAL_BOOLEAN                                     = 176;
 ASN1_R_ILLEGAL_CHARACTERS                                  = 124;
 ASN1_R_ILLEGAL_FORMAT                                      = 177;
 ASN1_R_ILLEGAL_HEX                                         = 178;
 ASN1_R_ILLEGAL_IMPLICIT_TAG                                = 179;
 ASN1_R_ILLEGAL_INTEGER                                     = 180;
 ASN1_R_ILLEGAL_NESTED_TAGGING                              = 181;
 ASN1_R_ILLEGAL_NULL                                        = 125;
 ASN1_R_ILLEGAL_NULL_VALUE                                  = 182;
 ASN1_R_ILLEGAL_OBJECT                                      = 183;
 ASN1_R_ILLEGAL_OPTIONAL_ANY                                = 126;
 ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE                    = 170;
 ASN1_R_ILLEGAL_TAGGED_ANY                                  = 127;
 ASN1_R_ILLEGAL_TIME_VALUE                                  = 184;
 ASN1_R_INTEGER_NOT_ASCII_FORMAT                            = 185;
 ASN1_R_INTEGER_TOO_LARGE_FOR_LONG                          = 128;
 ASN1_R_INVALID_BMPSTRING_LENGTH                            = 129;
 ASN1_R_INVALID_DIGIT                                       = 130;
 ASN1_R_INVALID_MIME_TYPE                                   = 205;
 ASN1_R_INVALID_MODIFIER                                    = 186;
 ASN1_R_INVALID_NUMBER                                      = 187;
 ASN1_R_INVALID_OBJECT_ENCODING                             = 216;
 ASN1_R_INVALID_SEPARATOR                                   = 131;
 ASN1_R_INVALID_TIME_FORMAT                                 = 132;
 ASN1_R_INVALID_UNIVERSALSTRING_LENGTH                      = 133;
 ASN1_R_INVALID_UTF8STRING                                  = 134;
 ASN1_R_IV_TOO_LARGE                                        = 135;
 ASN1_R_LENGTH_ERROR                                        = 136;
 ASN1_R_LIST_ERROR                                          = 188;
 ASN1_R_MIME_NO_CONTENT_TYPE                                = 206;
 ASN1_R_MIME_PARSE_ERROR                                    = 207;
 ASN1_R_MIME_SIG_PARSE_ERROR                                = 208;
 ASN1_R_MISSING_EOC                                         = 137;
 ASN1_R_MISSING_SECOND_NUMBER                               = 138;
 ASN1_R_MISSING_VALUE                                       = 189;
 ASN1_R_MSTRING_NOT_UNIVERSAL                               = 139;
 ASN1_R_MSTRING_WRONG_TAG                                   = 140;
 ASN1_R_NESTED_ASN1_STRING                                  = 197;
 ASN1_R_NON_HEX_CHARACTERS                                  = 141;
 ASN1_R_NOT_ASCII_FORMAT                                    = 190;
 ASN1_R_NOT_ENOUGH_DATA                                     = 142;
 ASN1_R_NO_CONTENT_TYPE                                     = 209;
 ASN1_R_NO_DEFAULT_DIGEST                                   = 201;
 ASN1_R_NO_MATCHING_CHOICE_TYPE                             = 143;
 ASN1_R_NO_MULTIPART_BODY_FAILURE                           = 210;
 ASN1_R_NO_MULTIPART_BOUNDARY                               = 211;
 ASN1_R_NO_SIG_CONTENT_TYPE                                 = 212;
 ASN1_R_NULL_IS_WRONG_LENGTH                                = 144;
 ASN1_R_OBJECT_NOT_ASCII_FORMAT                             = 191;
 ASN1_R_ODD_NUMBER_OF_CHARS                                 = 145;
 ASN1_R_PRIVATE_KEY_HEADER_MISSING                          = 146;
 ASN1_R_SECOND_NUMBER_TOO_LARGE                             = 147;
 ASN1_R_SEQUENCE_LENGTH_MISMATCH                            = 148;
 ASN1_R_SEQUENCE_NOT_CONSTRUCTED                            = 149;
 ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG                        = 192;
 ASN1_R_SHORT_LINE                                          = 150;
 ASN1_R_SIG_INVALID_MIME_TYPE                               = 213;
 ASN1_R_STREAMING_NOT_SUPPORTED                             = 202;
 ASN1_R_STRING_TOO_LONG                                     = 151;
 ASN1_R_STRING_TOO_SHORT                                    = 152;
 ASN1_R_TAG_VALUE_TOO_HIGH                                  = 153;
 ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
 ASN1_R_TIME_NOT_ASCII_FORMAT                               = 193;
 ASN1_R_TOO_LONG                                            = 155;
 ASN1_R_TYPE_NOT_CONSTRUCTED                                = 156;
 ASN1_R_UNABLE_TO_DECODE_RSA_KEY                            = 157;
 ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY                    = 158;
 ASN1_R_UNEXPECTED_EOC                                      = 159;
 ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH                     = 215;
 ASN1_R_UNKNOWN_FORMAT                                      = 160;
 ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM                    = 161;
 ASN1_R_UNKNOWN_OBJECT_TYPE                                 = 162;
 ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE                             = 163;
 ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM                         = 199;
 ASN1_R_UNKNOWN_TAG                                         = 194;
 ASN1_R_UNKOWN_FORMAT                                       = 195;
 ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE                     = 164;
 ASN1_R_UNSUPPORTED_CIPHER                                  = 165;
 ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM                    = 166;
 ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE                         = 167;
 ASN1_R_UNSUPPORTED_TYPE                                    = 196;
 ASN1_R_WRONG_PUBLIC_KEY_TYPE                               = 200;
 ASN1_R_WRONG_TAG                                           = 168;
 ASN1_R_WRONG_TYPE                                          = 169;
 
 
 ASN1_ITYPE_PRIMITIVE       = $0;
 ASN1_ITYPE_SEQUENCE        = $1;
 ASN1_ITYPE_CHOICE          = $2;
 ASN1_ITYPE_COMPAT          = $3;
 ASN1_ITYPE_EXTERN          = $4;
 ASN1_ITYPE_MSTRING         = $5;
 ASN1_ITYPE_NDEF_SEQUENCE   = $6;
 
 
{$ENDREGION}

{$REGION 'BIO'}
const
  BIO_F_ACPT_STATE            = 100;
  BIO_F_BIO_ACCEPT            = 101;
  BIO_F_BIO_BER_GET_HEADER    = 102;
  BIO_F_BIO_CALLBACK_CTRL     = 131;
  BIO_F_BIO_CTRL              = 103;
  BIO_F_BIO_GETHOSTBYNAME     = 120;
  BIO_F_BIO_GETS              = 104;
  BIO_F_BIO_GET_ACCEPT_SOCKET = 105;
  BIO_F_BIO_GET_HOST_IP       = 106;
  BIO_F_BIO_GET_PORT          = 107;
  BIO_F_BIO_MAKE_PAIR         = 121;
  BIO_F_BIO_NEW               = 108;
  BIO_F_BIO_NEW_FILE          = 109;
  BIO_F_BIO_NEW_MEM_BUF       = 126;
  BIO_F_BIO_NREAD             = 123;
  BIO_F_BIO_NREAD0            = 124;
  BIO_F_BIO_NWRITE            = 125;
  BIO_F_BIO_NWRITE0           = 122;
  BIO_F_BIO_PUTS              = 110;
  BIO_F_BIO_READ              = 111;
  BIO_F_BIO_SOCK_INIT         = 112;
  BIO_F_BIO_WRITE             = 113;
  BIO_F_BUFFER_CTRL           = 114;
  BIO_F_CONN_CTRL             = 127;
  BIO_F_CONN_STATE            = 115;
  BIO_F_DGRAM_SCTP_READ       = 132;
  BIO_F_FILE_CTRL             = 116;
  BIO_F_FILE_READ             = 130;
  BIO_F_LINEBUFFER_CTRL       = 129;
  BIO_F_MEM_READ              = 128;
  BIO_F_MEM_WRITE             = 117;
  BIO_F_SSL_NEW               = 118;
  BIO_F_WSASTARTUP            = 119;

  BIO_R_ACCEPT_ERROR                          = 100;
  BIO_R_BAD_FOPEN_MODE                        = 101;
  BIO_R_BAD_HOSTNAME_LOOKUP                   = 102;
  BIO_R_BROKEN_PIPE                           = 124;
  BIO_R_CONNECT_ERROR                         = 103;
  BIO_R_EOF_ON_MEMORY_BIO                     = 127;
  BIO_R_ERROR_SETTING_NBIO                    = 104;
  BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105;
  BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET   = 106;
  BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET     = 107;
  BIO_R_INVALID_ARGUMENT                      = 125;
  BIO_R_INVALID_IP_ADDRESS                    = 108;
  BIO_R_IN_USE                                = 123;
  BIO_R_KEEPALIVE                             = 109;
  BIO_R_NBIO_CONNECT_ERROR                    = 110;
  BIO_R_NO_ACCEPT_PORT_SPECIFIED              = 111;
  BIO_R_NO_HOSTNAME_SPECIFIED                 = 112;
  BIO_R_NO_PORT_DEFINED                       = 113;
  BIO_R_NO_PORT_SPECIFIED                     = 114;
  BIO_R_NO_SUCH_FILE                          = 128;
  BIO_R_NULL_PARAMETER                        = 115;
  BIO_R_TAG_MISMATCH                          = 116;
  BIO_R_UNABLE_TO_BIND_SOCKET                 = 117;
  BIO_R_UNABLE_TO_CREATE_SOCKET               = 118;
  BIO_R_UNABLE_TO_LISTEN_SOCKET               = 119;
  BIO_R_UNINITIALIZED                         = 120;
  BIO_R_UNSUPPORTED_METHOD                    = 121;
  BIO_R_WRITE_TO_READ_ONLY_BIO                = 126;
  BIO_R_WSASTARTUP                            = 122;


  BIO_BIND_NORMAL                 = 0;
  BIO_BIND_REUSEADDR              = 2;
  BIO_BIND_REUSEADDR_IF_UNUSED    = 1;
  BIO_CB_CTRL                     = $06;
  BIO_CB_FREE                     = $01;
  BIO_CB_GETS                     = $05;
  BIO_CB_PUTS                     = $04;
  BIO_CB_READ                     = $02;
  BIO_CB_RETURN                   = $80;
  BIO_CB_WRITE                    = $03;
  BIO_CLOSE                       = $01;
  BIO_CONN_S_BEFORE               = 1;
  BIO_CONN_S_BLOCKED_CONNECT      = 7;
  BIO_CONN_S_CONNECT              = 5;
  BIO_CONN_S_CREATE_SOCKET        = 4;
  BIO_CONN_S_GET_IP               = 2;
  BIO_CONN_S_GET_PORT             = 3;
  BIO_CONN_S_NBIO                 = 8;
  BIO_CONN_S_OK                   = 6;
  BIO_CTRL_DUP                    = 12;
  BIO_CTRL_EOF                    = 2;
  BIO_CTRL_FLUSH                  = 11;
  BIO_CTRL_GET                    = 5;
  BIO_CTRL_GET_CALLBACK           = 15;
  BIO_CTRL_GET_CLOSE              = 8;
  BIO_CTRL_INFO                   = 3;
  BIO_CTRL_PENDING                = 10;
  BIO_CTRL_POP                    = 7;
  BIO_CTRL_PUSH                   = 6;
  BIO_CTRL_RESET                  = 1;
  BIO_CTRL_SET                    = 4;
  BIO_CTRL_SET_CALLBACK           = 14;
  BIO_CTRL_SET_CLOSE              = 9;
  BIO_CTRL_SET_FILENAME           = 30;
  BIO_CTRL_DGRAM_CONNECT          = 31;  
  BIO_CTRL_DGRAM_SET_CONNECTED    = 32;                                             
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33; //* setsockopt, essentially */
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34; //* getsockopt, essentially */
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35; //* setsockopt, essentially */
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36; //* getsockopt, essentially */

  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37; //* flag whether the last */
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38; //* I/O operation tiemd out */
  BIO_CTRL_DGRAM_MTU_DISCOVER       = 39; //* set DF bit on egress packets */
  BIO_CTRL_DGRAM_QUERY_MTU          = 40; //* as kernel for current MTU */
  BIO_CTRL_DGRAM_GET_MTU            = 41; //* get cached value for MTU */
  BIO_CTRL_DGRAM_SET_MTU            = 42; //* set cached value for
  BIO_CTRL_DGRAM_MTU_EXCEEDED       = 43; //* check whether the MTU
  BIO_CTRL_DGRAM_GET_PEER           = 46;
  BIO_CTRL_DGRAM_SET_PEER           = 44; //* Destination for the data */
  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   = 45; //* Next DTLS handshake timeout to

  BIO_CTRL_WPENDING                 = 13;
  BIO_C_DESTROY_BIO_PAIR            = 139;
  BIO_C_DO_STATE_MACHINE            = 101;
  BIO_C_FILE_SEEK                   = 128;
  BIO_C_FILE_TELL                   = 133;
  BIO_C_GET_ACCEPT                  = 124;
  BIO_C_GET_BIND_MODE               = 132;
  BIO_C_GET_BUFF_NUM_LINES          = 116;
  BIO_C_GET_BUF_MEM_PTR             = 115;
  BIO_C_GET_CIPHER_CTX              = 129;
  BIO_C_GET_CIPHER_STATUS           = 113;
  BIO_C_GET_CONNECT                 = 123;
  BIO_C_GET_FD                      = 105;
  BIO_C_GET_FILE_PTR                = 107;
  BIO_C_GET_MD                      = 112;
  BIO_C_GET_MD_CTX                  = 120;
  BIO_C_GET_PROXY_PARAM             = 121;
  BIO_C_GET_READ_REQUEST            = 141;
  BIO_C_GET_SOCKS                   = 134;
  BIO_C_GET_SSL                     = 110;
  BIO_C_GET_SSL_NUM_RENEGOTIATES    = 126;
  BIO_C_GET_WRITE_BUF_SIZE          = 137;
  BIO_C_GET_WRITE_GUARANTEE         = 140;
  BIO_C_MAKE_BIO_PAIR               = 138;
  BIO_C_SET_ACCEPT                  = 118;
  BIO_C_SET_BIND_MODE               = 131;
  BIO_C_SET_BUFF_READ_DATA          = 122;
  BIO_C_SET_BUFF_SIZE               = 117;
  BIO_C_SET_BUF_MEM                 = 114;
  BIO_C_SET_BUF_MEM_EOF_RETURN      = 130;
  BIO_C_SET_CONNECT                 = 100;
  BIO_C_SET_FD                      = 104;
  BIO_C_SET_FILENAME                = 108;
  BIO_C_SET_FILE_PTR                = 106;
  BIO_C_SET_MD                      = 111;
  BIO_C_SET_NBIO                    = 102;
  BIO_C_SET_PROXY_PARAM             = 103;
  BIO_C_SET_SOCKS                   = 135;
  BIO_C_SET_SSL                     = 109;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES   = 125;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_SET_WRITE_BUF_SIZE          = 136;
  BIO_C_SHUTDOWN_WR                 = 142;
  BIO_C_SSL_MODE                    = 119;
  BIO_FLAGS_BASE64_NO_NL            = $100;
  BIO_FLAGS_IO_SPECIAL              = $04;
  BIO_FLAGS_READ                    = $01;
  BIO_FLAGS_WRITE                   = $02;
  BIO_FLAGS_RWS                     = BIO_FLAGS_READ or
                          BIO_FLAGS_WRITE or
                          BIO_FLAGS_IO_SPECIAL;
  BIO_FLAGS_SHOULD_RETRY            = $08;
  BIO_FP_APPEND                     = $08;
  BIO_FP_READ                       = $02;
  BIO_FP_TEXT                       = $10;
  BIO_FP_WRITE                      = $04;
  BIO_GHBN_CTRL_CACHE_SIZE          = 3;
  BIO_GHBN_CTRL_FLUSH               = 5;
  BIO_GHBN_CTRL_GET_ENTRY           = 4;
  BIO_GHBN_CTRL_HITS                = 1;
  BIO_GHBN_CTRL_MISSES              = 2;
  BIO_NOCLOSE                       = $00;
  BIO_RR_CONNECT                    = $02;
  BIO_RR_SSL_X509_LOOKUP            = $01;
  BIO_TYPE_ACCEPT                   = 13 or $0400 or $0100;
  BIO_TYPE_BASE64                   = 11 or $0200;
  BIO_TYPE_BER                      = 18 or $0200;
  BIO_TYPE_BIO                      = 19 or $0400;
  BIO_TYPE_BUFFER                   = 9 or $0200;
  BIO_TYPE_CIPHER                   = 10 or $0200;
  BIO_TYPE_CONNECT                  = 12 or $0400 or $0100;
  BIO_TYPE_DESCRIPTOR               = $0100;
  BIO_TYPE_FD                       = 4 or $0400 or $0100;
  BIO_TYPE_FILE                     = 2 or $0400;
  BIO_TYPE_FILTER                   = $0200;
  BIO_TYPE_MD                       = 8 or $0200;
  BIO_TYPE_MEM                      = 1 or $0400;
  BIO_TYPE_NBIO_TEST                = 16 or $0200;
  BIO_TYPE_NONE                     = 0;
  BIO_TYPE_NULL                     = 6 or $0400;
  BIO_TYPE_NULL_FILTER              = 17 or $0200;
  BIO_TYPE_PROXY_CLIENT             = 14 or $0200;
  BIO_TYPE_PROXY_SERVER             = 15 or $0200;
  BIO_TYPE_SOCKET                   = 5 or $0400 or $0100;
  BIO_TYPE_SOURCE_SINK              = $0400;
  BIO_TYPE_SSL                      = 7 or $0200;
  BIO_TYPE_LINEBUFFER               = 20 or $0200;
  BIO_TYPE_DGRAM                    = 21 or $0400 or $0100;
  BIO_TYPE_COMP                     = 23 or $0200;

{$ENDREGION}

{$REGION 'BN'}

 BN_BITS        = 128;
 BN_BYTES       = 8;
 BN_BITS2       = 64;
 BN_BITS4       = 32;
 BN_MASK2       = $ffffffffffffffff;
 BN_MASK2l      = $ffffffff;
 BN_MASK2h      = $ffffffff00000000;
 BN_MASK2h1     = $ffffffff80000000;
 BN_TBIT        = $8000000000000000;
 BN_DEC_CONV    = 10000000000000000000;
 BN_DEC_FMT1    = '%lu';
 BN_DEC_FMT2    = '%019lu';
 BN_DEC_NUM     = 19;
 BN_HEX_FMT1    = '%lX';
 BN_HEX_FMT2    = '%016lX';


{$ENDREGION}

implementation

end.
