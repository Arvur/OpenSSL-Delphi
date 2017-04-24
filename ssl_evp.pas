{$I ssl.inc}
unit ssl_evp;

interface

uses ssl_types, ssl_const;

var

  EVP_MD_type: function(const md: PEVP_MD): TC_INT; cdecl = nil;
  EVP_MD_pkey_type: function(const md: PEVP_MD): TC_INT; cdecl = nil;
  EVP_MD_size: function(const md: PEVP_MD): TC_INT; cdecl = nil;
  EVP_MD_block_size: function(const md: PEVP_MD): TC_INT; cdecl = nil;
  EVP_MD_flags: function(const md: PEVP_MD): TC_ULONG; cdecl = nil;

  EVP_MD_CTX_md: function(const ctx: PEVP_MD_CTX): PEVP_MD; cdecl = nil;

  EVP_CIPHER_nid: function(const cipher: PEVP_CIPHER): TC_INT; cdecl = nil;

  EVP_CIPHER_block_size: function(const cipher: PEVP_CIPHER): TC_INT; cdecl = nil;
  EVP_CIPHER_key_length: function(const cipher: PEVP_CIPHER): TC_INT; cdecl = nil;
  EVP_CIPHER_iv_length: function(const cipher: PEVP_CIPHER): TC_INT; cdecl = nil;
  EVP_CIPHER_flags: function(const cipher: PEVP_CIPHER): TC_ULONG; cdecl = nil;

  EVP_CIPHER_CTX_cipher: function(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER;
  EVP_CIPHER_CTX_nid: function(const ctx: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_block_size: function(const ctx: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_key_length: function(const ctx: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_iv_length: function(const ctx: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_copy: function(_out: PEVP_CIPHER_CTX; _in: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_get_app_data: function(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = nil;
  EVP_CIPHER_CTX_set_app_data: procedure(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl = nil;
  EVP_CIPHER_CTX_flags: function(const ctx: PEVP_CIPHER_CTX): TC_ULONG;
  BIO_set_md: procedure(bp: PBIO; const md: PEVP_MD); cdecl = nil;

  EVP_Cipher: function(c: PEVP_CIPHER_CTX; _out: PAnsiChar; const _in: PAnsiChar; inl: TC_UINT): TC_INT; cdecl = nil;

  EVP_MD_CTX_init: procedure(ctx: PEVP_MD_CTX); cdecl = nil;
  EVP_MD_CTX_cleanup: function(ctx: PEVP_MD_CTX): TC_INT; cdecl = nil;
  EVP_MD_CTX_create: function: PEVP_MD_CTX; cdecl = nil;
  EVP_MD_CTX_destroy: procedure(ctx: PEVP_MD_CTX); cdecl = nil;

  EVP_MD_CTX_copy_ex: function(_out: EVP_MD_CTX;const _in: EVP_MD_CTX): TC_INT; cdecl = nil;
  EVP_MD_CTX_set_flags: procedure(ctx: PEVP_MD_CTX; flags: TC_INT); cdecl = nil;
  EVP_MD_CTX_clear_flags: procedure(ctx: PEVP_MD_CTX; flags: TC_INT); cdecl = nil;
  EVP_MD_CTX_test_flags: function(const ctx: PEVP_MD_CTX; flags: TC_INT): TC_INT; cdecl = nil;
  EVP_DigestInit_ex: function(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): TC_INT; cdecl = nil;
  EVP_DigestUpdate: function(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; cdecl = nil;
  EVP_DigestFinal_ex: function(ctx: PEVP_MD_CTX;md: PAnsiChar;var s: TC_UINT): TC_INT; cdecl = nil;
  EVP_Digest: function(const data: Pointer; count: TC_SIZE_T;   md: PAnsiChar; var size: TC_INT; const _type: PEVP_MD; impl: PENGINE): TC_INT; cdecl = nil;

  EVP_MD_CTX_copy: function(_out: EVP_MD_CTX;const _in: EVP_MD_CTX): TC_INT; cdecl = nil;
  EVP_DigestInit: function(ctx: PEVP_MD_CTX; const _type: PEVP_MD): TC_INT; cdecl = nil;
  EVP_DigestFinal: function(ctx: PEVP_MD_CTX;md: PAnsiChar;var s: TC_INT): TC_INT; cdecl = nil;

  EVP_read_pw_string: function(buf: PAnsiChar;length: TC_INT; prompt: PAnsiChar;verify: TC_INT): TC_INT; cdecl = nil;
  EVP_read_pw_string_min: function(buf: PAnsiChar;minlen: TC_INT;maxlen: TC_INT;prompt: PAnsiChar;verify: TC_INT): TC_INT; cdecl = nil;

  EVP_set_pw_prompt: procedure(prompt: PAnsiChar); cdecl = nil;
  EVP_get_pw_prompt: function: PAnsiChar; cdecl = nil;

  EVP_BytesToKey: function(const _type: PEVP_CIPHER;const md: PEVP_MD; const salt: PAnsiChar; const data: PAnsiChar; datal: TC_INT; count: TC_INT; key: PAnsiChar;iv: PAnsiChar): TC_INT;cdecl = nil;

  EVP_CIPHER_CTX_set_flags: procedure(ctx: PEVP_CIPHER_CTX; flags: TC_INT); cdecl = nil;
  EVP_CIPHER_CTX_clear_flags: procedure(ctx: PEVP_CIPHER_CTX; flags: TC_INT); cdecl = nil;

  EVP_CIPHER_CTX_test_flags: function(const ctx: PEVP_CIPHER_CTX;flags: TC_INT): TC_INT; cdecl = nil;

  EVP_EncryptInit: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; const key: PAnsiChar; const iv: PAnsiChar): TC_INT; cdecl = nil;
  EVP_EncryptInit_ex: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; impl: PENGINE;   const key: PAnsiChar; const iv: PAnsiChar): TC_INT; cdecl = nil;

  EVP_EncryptUpdate: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; cdecl = nil;
  EVP_EncryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;
  EVP_EncryptFinal: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;

  EVP_DecryptInit: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; const key: PAnsiChar; const iv: PAnsiChar): TC_INT; cdecl = nil;
  EVP_DecryptInit_ex: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; impl: PENGINE; const key: PAnsiChar; const iv: PAnsiChar): TC_INT; cdecl = nil;
  EVP_DecryptUpdate: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; cdecl = nil;
  EVP_DecryptFinal: function(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;
  EVP_DecryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;

  EVP_CipherInit: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; const key: PAnsiChar;const iv: PAnsiChar; enc: TC_INT): TC_INT; cdecl = nil;
  EVP_CipherInit_ex: function(ctx: PEVP_CIPHER_CTX;const cipher: PEVP_CIPHER; impl: PENGINE; const key: PAnsiChar;const iv: PAnsiChar; enc: TC_INT): TC_INT; cdecl = nil;
  EVP_CipherUpdate: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; var inl: TC_INT): TC_INT; cdecl = nil;
  EVP_CipherFinal: function(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;
  EVP_CipherFinal_ex: function(ctx: PEVP_CIPHER_CTX; outm: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;

  EVP_SignFinal: function(ctx: PEVP_MD_CTX;md: PAnsiChar;var s: TC_INT; pkey: PEVP_PKEY): TC_INT; cdecl = nil;

  EVP_VerifyFinal: function(ctx: PEVP_MD_CTX;const sigbuf: PAnsiChar; siglen: TC_UINT;pkey: PEVP_PKEY): TC_INT; cdecl = nil;

  EVP_DigestSignInit: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_DigestSignFinal: function(ctx: PEVP_MD_CTX; sigret: PAnsiChar; var siglen: TC_SIZE_T): TC_INT; cdecl = nil;

  EVP_DigestVerifyInit: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const _type: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_DigestVerifyFinal: function(ctx: PEVP_MD_CTX; sig: PAnsiChar; siglen: TC_SIZE_T): TC_INT; cdecl = nil;

  EVP_OpenInit: function(ctx: PEVP_CIPHER_CTX;const _type: PEVP_CIPHER; ek: PAnsiChar; ekl:  TC_INT; const iv: PAnsiChar;  priv: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_OpenFinal: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;

  EVP_SealInit: function(ctx: PEVP_CIPHER_CTX; const _type: PEVP_CIPHER; ek: PPAnsiChar; var ekl: TC_INT; iv: PAnsiChar; pubk: PPEVP_PKEY; npubk: TC_INT): TC_INT; cdecl = nil;
  EVP_SealFinal: function(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar;var outl: TC_INT): TC_INT; cdecl = nil;

  EVP_EncodeInit: procedure(ctx: PEVP_ENCODE_CTX); cdecl = nil;
  EVP_EncodeUpdate: procedure(ctx: PEVP_ENCODE_CTX;_out: PAnsiChar;var outl: TC_INT; const _in: PAnsiChar;var inl: TC_INT); cdecl = nil;
  EVP_EncodeFinal: procedure(ctx: PEVP_ENCODE_CTX;_out: PAnsiChar;var outl: TC_INT); cdecl = nil;

  EVP_EncodeBlock: function(t: PAnsiChar; f: PAnsiChar; n: TC_INT): TC_INT; cdecl = nil;

  EVP_DecodeInit: procedure(ctx: PEVP_ENCODE_CTX); cdecl = nil;

  EVP_DecodeUpdate: function(ctx: PEVP_ENCODE_CTX;_out: PAnsiChar;var outl: TC_INT; const _in: PAnsiChar; var inl: TC_INT): TC_INT; cdecl = nil;
  EVP_DecodeFinal: function(ctx: PEVP_ENCODE_CTX; _out: PAnsiChar; var outl: TC_INT): TC_INT; cdecl = nil;
  EVP_DecodeBlock: function(t: PAnsiChar; f: PAnsiChar; n: TC_INT): TC_INT; cdecl = nil;

  EVP_CIPHER_CTX_init: procedure(a: PEVP_CIPHER_CTX); cdecl = nil;
  EVP_CIPHER_CTX_free: procedure(a: PEVP_CIPHER_CTX); cdecl = nil;
  EVP_CIPHER_CTX_new: function: PEVP_CIPHER_CTX; cdecl = nil;
  EVP_CIPHER_CTX_cleanup: function(a: PEVP_CIPHER_CTX): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_set_key_length: function(x: PEVP_CIPHER_CTX; keylen: TC_INT): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_set_padding: function(c: PEVP_CIPHER_CTX; pad: TC_INT): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_ctrl: function(ctx: PEVP_CIPHER_CTX; _type: TC_INT; arg: TC_INT; ptr: Pointer): TC_INT; cdecl = nil;
  EVP_CIPHER_CTX_rand_key: function(ctx: PEVP_CIPHER_CTX; key: PAnsiChar): TC_INT; cdecl = nil;

  BIO_f_md: function: PBIO_METHOD; cdecl = nil;
  BIO_f_base64: function: PBIO_METHOD; cdecl = nil;
  BIO_f_cipher: function: PBIO_METHOD; cdecl = nil;
  BIO_f_reliable: function: PBIO_METHOD; cdecl = nil;

  BIO_set_cipher: procedure(bp: PBIO; c: PEVP_CIPHER; const k: PAnsiChar; const i: PAnsiChar; enc: TC_INT);

  EVP_md_null: function: PEVP_MD; cdecl = nil;
  EVP_md2: function: PEVP_MD; cdecl = nil;
  EVP_md4: function: PEVP_MD; cdecl = nil;
  EVP_md5: function: PEVP_MD; cdecl = nil;
  EVP_sha: function: PEVP_MD; cdecl = nil;
  EVP_sha1: function: PEVP_MD; cdecl = nil;
  EVP_dss: function: PEVP_MD; cdecl = nil;
  EVP_dss1: function: PEVP_MD; cdecl = nil;
  EVP_ecdsa: function: PEVP_MD; cdecl = nil;
  EVP_sha224: function: PEVP_MD; cdecl = nil;
  EVP_sha256: function: PEVP_MD; cdecl = nil;
  EVP_sha384: function: PEVP_MD; cdecl = nil;
  EVP_sha512: function: PEVP_MD; cdecl = nil;
  EVP_mdc2: function: PEVP_MD; cdecl = nil;
  EVP_ripemd160: function: PEVP_MD; cdecl = nil;
  EVP_whirlpool: function: PEVP_MD; cdecl = nil;
  EVP_dev_crypto_md5: function: PEVP_MD; cdecl = nil;

  EVP_enc_null: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_desx_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_dev_crypto_des_ede3_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_dev_crypto_rc4: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc4: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc4_40: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc4_hmac_md5: function: PEVP_CIPHER; cdecl = nil;
  EVP_idea_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_idea_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_idea_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_idea_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_40_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_64_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc2_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_bf_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_bf_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_bf_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_bf_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_cast5_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_cast5_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_cast5_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_cast5_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc5_32_12_16_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc5_32_12_16_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc5_32_12_16_cfb64: function: PEVP_CIPHER; cdecl = nil;
  EVP_rc5_32_12_16_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ctr: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_gcm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ccm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_xts: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ctr: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_gcm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ccm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ctr: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_gcm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ccm: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_xts: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cbc_hmac_sha1: function: PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cbc_hmac_sha1: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_ofb: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb1: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb8: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_ofb: function: PEVP_CIPHER; cdecl = nil;

  EVP_seed_ecb: function: PEVP_CIPHER; cdecl = nil;
  EVP_seed_cbc: function: PEVP_CIPHER; cdecl = nil;
  EVP_seed_cfb128: function: PEVP_CIPHER; cdecl = nil;
  EVP_seed_ofb: function: PEVP_CIPHER; cdecl = nil;

  OPENSSL_add_all_algorithms_noconf: procedure; cdecl = nil;
  OPENSSL_add_all_algorithms_conf: procedure; cdecl = nil;

  OpenSSL_add_all_ciphers: procedure; cdecl = nil;
  OpenSSL_add_all_digests: procedure; cdecl = nil;

  EVP_add_cipher: function(const cipher: PEVP_CIPHER): TC_INT; cdecl = nil;
  EVP_add_digest: function(const digest: PEVP_MD): TC_INT;

  EVP_get_cipherbyname: function(name: PAnsiChar): PEVP_CIPHER; cdecl = nil;
  EVP_get_digestbyname: function(name: PAnsiChar): PEVP_MD; cdecl = nil;
  EVP_cleanup: procedure; cdecl = nil;

  EVP_CIPHER_do_all: procedure( fn: EVP_CIPHER_DO; arg: Pointer); cdecl = nil;
  EVP_CIPHER_do_all_sorted: procedure( fn: EVP_CIPHER_DO; arg: Pointer); cdecl = nil;

  EVP_MD_do_all: procedure( fn: EVP_MD_DO; arg: Pointer); cdecl = nil;
  EVP_MD_do_all_sorted: procedure( fn: EVP_MD_DO; arg: Pointer); cdecl = nil;

  EVP_PKEY_decrypt_old: function(dec_key: PAnsiChar; const enc_key: PAnsiChar; enc_key_len: TC_INT; private_key: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_encrypt_old: function(enc_key: PAnsiChar; const key: PAnsiChar; key_len: TC_INT; pub_key: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_type: function(_type: TC_INT): TC_INT; cdecl = nil;
  EVP_PKEY_id: function(const pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_base_id: function(const pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_bits: function(pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_size: function(pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_set_type: function(pkey: PEVP_PKEY;_type: TC_INT): TC_INT; cdecl = nil;
  EVP_PKEY_set_type_str: function(pkey: PEVP_PKEY; str: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
  EVP_PKEY_assign: function(pkey: PEVP_PKEY;_type: TC_INT; key: Pointer): TC_INT; cdecl = nil;
  EVP_PKEY_get0: function(pkey: PEVP_PKEY): Pointer; cdecl = nil;

  EVP_PKEY_set1_RSA: function(pkey: PEVP_PKEY; key: PRSA): TC_INT; cdecl = nil;
  EVP_PKEY_get1_RSA: function(pkey: PEVP_PKEY): PRSA; cdecl = nil;

  EVP_PKEY_set1_DSA: function(pkey: PEVP_PKEY; key: PDSA): TC_INT; cdecl = nil;
  EVP_PKEY_get1_DSA: function(pkey: PEVP_PKEY):PDSA; cdecl = nil;
  EVP_PKEY_set1_DH: function(pkey: PEVP_PKEY; key: PDH): TC_INT; cdecl = nil;
  EVP_PKEY_get1_DH: function(pkey: PEVP_PKEY): PDH; cdecl = nil;
  EVP_PKEY_set1_EC_KEY: function(pkey: PEVP_PKEY; key: PEC_KEY): TC_INT; cdecl = nil;
  EVP_PKEY_get1_EC_KEY: function(pkey: PEVP_PKEY): PEC_KEY; cdecl = nil;

  EVP_PKEY_new: function: PEVP_PKEY; cdecl = nil;
  EVP_PKEY_free: procedure(pkey: PEVP_PKEY); cdecl = nil;

  d2i_PublicKey: function(_type: TC_INT; a: PPEVP_PKEY; pp: PPAnsiChar; _length: TC_LONG): PEVP_PKEY; cdecl = nil;
  i2d_PublicKey: function(a: PEVP_PKEY; pp: PPAnsiChar): TC_INT; cdecl = nil;

  d2i_PrivateKey: function(_type: TC_INT; a: PPEVP_PKEY; pp: PPAnsiChar;   _length: TC_LONG): PEVP_PKEY; cdecl = nil;
  d2i_AutoPrivateKey: function(a: PPEVP_PKEY; pp: PPAnsiChar; _length: TC_LONG): PEVP_PKEY; cdecl = nil;
  i2d_PrivateKey: function(a: PEVP_PKEY; pp: PPAnsiChar): TC_INT; cdecl = nil;

  EVP_PKEY_copy_parameters: function(_to: PEVP_PKEY; const _from: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_missing_parameters: function(const pkey: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_save_parameters: function(pkey: PEVP_PKEY; mode: TC_INT): TC_INT; cdecl = nil;
  EVP_PKEY_cmp_parameters: function(const a: PEVP_PKEY; const b: PEVP_PKEY): TC_INT; cdecl = nil;

  EVP_PKEY_cmp: function(const a: PEVP_PKEY; const b: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_print_public: function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT; pctx: ASN1_PCTX): TC_INT; cdecl = nil;
  EVP_PKEY_print_private: function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT; pctx: ASN1_PCTX): TC_INT; cdecl = nil;
  EVP_PKEY_print_params: function(_out: PBIO; const pkey: PEVP_PKEY; indent: TC_INT; pctx: ASN1_PCTX): TC_INT; cdecl = nil;
  EVP_PKEY_get_default_digest_nid: function(pkey: PEVP_PKEY; var pnid: TC_INT): TC_INT; cdecl = nil;
  EVP_CIPHER_type: function(const ctx: PEVP_CIPHER): TC_INT; cdecl = nil;
  EVP_CIPHER_param_to_asn1: function(c: PEVP_CIPHER_CTX; _type: PASN1_TYPE): TC_INT; cdecl = nil;
  EVP_CIPHER_asn1_to_param: function(c: PEVP_CIPHER_CTX; _type: PASN1_TYPE): TC_INT; cdecl = nil;
  EVP_CIPHER_set_asn1_iv: function(c: PEVP_CIPHER_CTX;_type: PASN1_TYPE): TC_INT; cdecl = nil;
  EVP_CIPHER_get_asn1_iv: function(c: PEVP_CIPHER_CTX;_type: PASN1_TYPE): TC_INT; cdecl = nil;
  PKCS5_PBE_keyivgen: function(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TC_INT; param : PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TC_INT): TC_INT; cdecl = nil;
  PKCS5_PBKDF2_HMAC_SHA1: function(const pass: PAnsiChar; passlen: TC_INT;  const salt: PAnsiChar; saltlen: TC_INT; iter: TC_INT;  keylen: TC_INT; _out: PAnsiChar): TC_INT; cdecl = nil;
  PKCS5_PBKDF2_HMAC: function(const pass: PAnsiChar; passlen: TC_INT; const salt: PAnsiChar; saltlen: TC_INT;  iter: TC_INT; const digest: PEVP_MD; keylen: TC_INT; _out: PAnsiChar): TC_INT; cdecl = nil;
  PKCS5_v2_PBE_keyivgen: function(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TC_INT; param : PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TC_INT): TC_INT; cdecl = nil;

  PKCS5_PBE_add: procedure; cdecl = nil;

  EVP_PBE_CipherInit: function(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TC_INT; param : PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TC_INT): TC_INT; cdecl = nil;

  EVP_PBE_alg_add_type: function(pbe_type: TC_INT;  pbe_nid: TC_INT;  cipher_nid: TC_INT;  md_nid: TC_INT; keygen: EVP_PBE_KEYGEN): TC_INT; cdecl = nil;
  EVP_PBE_alg_add: function(nid: TC_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: EVP_PBE_KEYGEN): TC_INT; cdecl = nil;
  EVP_PBE_find: function(_type: TC_INT; pbe_nid: TC_INT;    var pcnid: TC_INT; var pmnid: TC_INT; pkeygen: PEVP_PBE_KEYGEN): TC_INT; cdecl = nil;

  EVP_PBE_cleanup: procedure; cdecl = nil;

  EVP_PKEY_asn1_get_count: function: TC_INT; cdecl = nil;
  EVP_PKEY_asn1_get0: function(idx: TC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_find: function(pe: PPENGINE; _type: TC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_find_str: function(pe: PPENGINE; const str: PAnsiChar; len: TC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_add0: function(const ameth: PEVP_PKEY_ASN1_METHOD): TC_INT; cdecl = nil;
  EVP_PKEY_asn1_add_alias: function(_to: TC_INT; _from: TC_INT): TC_INT; cdecl = nil;
  EVP_PKEY_asn1_get0_info: function(var ppkey_id: TC_INT; var pkey_base_id: TC_INT; var ppkey_flags: TC_INT; pinfo: PPAnsiChar; ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TC_INT; cdecl = nil;

  EVP_PKEY_get0_asn1: function(pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_new: function(id: TC_INT; flags: TC_INT; pem_str: PAnsiChar; info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_copy: procedure(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl = nil;
  EVP_PKEY_asn1_free: procedure(ameth: PEVP_PKEY_ASN1_METHOD); cdecl = nil;

  EVP_PKEY_asn1_set_public: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pub_decode: EVP_pub_decode_t;   pub_encode: EVP_pub_encode_t;   pub_cmp: EVP_pub_cmp_t; pub_print: EVP_pub_print_t; pkey_size: EVP_pkey_size_t; pkey_bits: EVP_pkey_bits_t); cdecl = nil;
  EVP_PKEY_asn1_set_private: procedure(ameth: PEVP_PKEY_ASN1_METHOD; priv_decode: EVP_priv_decode_t; priv_encode: EVP_priv_encode_t;    priv_print: EVP_priv_print_t); cdecl = nil;

  EVP_PKEY_asn1_set_param: procedure(ameth: PEVP_PKEY_ASN1_METHOD; param_decode: EVP_param_decode_t; param_encode: EVP_param_encode_t; param_missing: EVP_param_missing_t; param_copy: EVP_param_copy_t; param_cmp:  EVP_param_cmp_t; param_print: EVP_param_print_t); cdecl = nil;

  EVP_PKEY_asn1_set_free: procedure(ameth: PEVP_PKEY_ASN1_METHOD;   pkey_free: EVP_pkey_free_t); cdecl = nil;
  EVP_PKEY_asn1_set_ctrl: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_ctrl: EVP_pkey_ctrl_t); cdecl = nil;


  EVP_PKEY_meth_find: function(_type: TC_INT): PEVP_PKEY_METHOD; cdecl = nil;
  EVP_PKEY_meth_new: function(id: TC_INT; flags: TC_INT): PEVP_PKEY_METHOD; cdecl = nil;

  EVP_PKEY_meth_get0_info: procedure(var ppkey_id: TC_INT; var pflags: TC_INT; const meth: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_copy: procedure(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_free: procedure(pmeth: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_add0: function(const pmeth: PEVP_PKEY_METHOD): TC_INT; cdecl = nil;

  EVP_PKEY_CTX_new: function(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_new_id: function(id: TC_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_dup: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_free: procedure(ctx: PEVP_PKEY_CTX); cdecl = nil;

  EVP_PKEY_CTX_set0_keygen_info: procedure(ctx: PEVP_PKEY_CTX; var dat: TC_INT; datlen: TC_INT); cdecl = nil;
  EVP_PKEY_CTX_set_data: procedure(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;
  EVP_PKEY_CTX_set_app_data: procedure(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;

  EVP_PKEY_CTX_ctrl: function(ctx: PEVP_PKEY_CTX; keytype: TC_INT; optype: TC_INT; cmd: TC_INT; p1: TC_INT; p2: Pointer): TC_INT; cdecl = nil;
  EVP_PKEY_CTX_ctrl_str: function(ctx: PEVP_PKEY_CTX; _type: PAnsiChar; value: PAnsiChar): TC_INT; cdecl = nil;
  EVP_PKEY_CTX_get_operation: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;


  EVP_PKEY_new_mac_key: function(_type: TC_INT; e: PENGINE; const key: PAnsiChar; keylen: TC_INT): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_get_data: function(ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;
  EVP_PKEY_CTX_get0_pkey: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_get0_peerkey: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_get_app_data: function(ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;

  EVP_PKEY_sign_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_sign: function(ctx: PEVP_PKEY_CTX;    sig: PAnsiChar; var siglen: TC_SIZE_T; tbs: PAnsiChar; tbslen: TC_SIZE_T): TC_INT; cdecl = nil;
  EVP_PKEY_verify_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_verify: function(ctx: PEVP_PKEY_CTX;  const sig: PAnsiChar; siglen: TC_SIZE_T;    tbs: PAnsiChar; tbslen: TC_SIZE_T): TC_INT; cdecl = nil;
  EVP_PKEY_verify_recover_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_verify_recover: function(ctx: PEVP_PKEY_CTX;  rout: PAnsiChar; var routlen: TC_SIZE_T;    const sig: PAnsiChar; siglen: TC_SIZE_T): TC_INT; cdecl = nil;
  EVP_PKEY_encrypt_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_encrypt: function(ctx: PEVP_PKEY_CTX; _out: PAnsiChar; var outlen: TC_SIZE_T; const _in: PAnsiChar; inlen: TC_SIZE_T): TC_INT; cdecl = nil;
  EVP_PKEY_decrypt_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_decrypt: function(ctx: PEVP_PKEY_CTX; _out: PAnsiChar; var outlen: TC_SIZE_T; const _in: PAnsiChar; inlen: TC_SIZE_T): TC_INT; cdecl = nil;

  EVP_PKEY_derive_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_derive_set_peer: function(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_derive: function(ctx: PEVP_PKEY_CTX; key: PAnsiChar; keylen: TC_SIZE_T): TC_INT; cdecl = nil;


  EVP_PKEY_paramgen_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_paramgen: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TC_INT; cdecl = nil;
  EVP_PKEY_keygen_init: function(ctx: PEVP_PKEY_CTX): TC_INT; cdecl = nil;
  EVP_PKEY_keygen: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TC_INT; cdecl = nil;

  EVP_PKEY_CTX_set_cb: procedure(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl = nil;
  EVP_PKEY_CTX_get_cb: function(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl = nil;

  EVP_PKEY_CTX_get_keygen_info: function(ctx: PEVP_PKEY_CTX; idx:TC_INT): TC_INT; cdecl = nil;
  ERR_load_EVP_strings: procedure; cdecl = nil;


function EVP_get_digestbynid(a: TC_INT): PEVP_MD; inline;
function EVP_get_digestbyobj(a: PASN1_OBJECT): PEVP_MD; inline;
function EVP_get_cipherbynid(a: TC_INT): PEVP_CIPHER; inline;
function EVP_get_cipherbyobj(a: PASN1_OBJECT): PEVP_MD; inline;
function EVP_MD_nid(e: PEVP_MD): TC_INT; inline;
function EVP_MD_name(e: PEVP_MD): AnsiString; inline;
function EVP_MD_CTX_size(e: PEVP_MD_CTX): TC_INT; inline;
function EVP_MD_CTX_block_size(e: PEVP_MD_CTX): TC_INT; inline;
function EVP_MD_CTX_type(e: PEVP_MD_CTX): TC_INT; inline;
function EVP_CIPHER_name(e: PEVP_CIPHER): AnsiString; inline;
function EVP_CIPHER_mode(e: PEVP_CIPHER): TC_ULONG; inline;
function EVP_CIPHER_CTX_type(e: PEVP_CIPHER_CTX): TC_INT; inline;
function EVP_CIPHER_CTX_mode(e: PEVP_CIPHER_CTX): TC_ULONG; inline;
function EVP_ENCODE_LENGTH(l: TC_INT): TC_INT; inline;
function EVP_DECODE_LENGTH(l: TC_INT): TC_INT; inline;

function EVP_SignInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): TC_INT; inline;
function EVP_SignInitEx(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): TC_INT; inline;
function EVP_SignUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;

function EVP_VerifyInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): TC_INT; inline;
function EVP_VerifyInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): TC_INT; inline;
function EVP_VerifyUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
function EVP_OpenUpdate(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; inline;
function EVP_SealUpdate(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; inline;
function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;

procedure SSL_InitEVP;

implementation

uses ssl_lib, ssl_objects;

function EVP_get_digestbynid(a: TC_INT): PEVP_MD; inline;
begin
  if Assigned(EVP_get_digestbyname) then
    Result := EVP_get_digestbyname(OBJ_nid2sn(a))
  else
    Result := nil;
end;

function EVP_get_digestbyobj(a: PASN1_OBJECT): PEVP_MD; inline;
begin
  result := EVP_get_digestbynid(OBJ_obj2nid(a))
end;

function EVP_get_cipherbynid(a: TC_INT): PEVP_CIPHER; inline;
begin
  if Assigned(EVP_get_cipherbyname) then
   Result := EVP_get_cipherbyname(OBJ_nid2sn(a))
  else
   Result := nil;
end;

function EVP_get_cipherbyobj(a: PASN1_OBJECT): PEVP_MD; inline;
begin
  Result := EVP_get_digestbynid(OBJ_obj2nid(a));
end;

function EVP_MD_nid(e: PEVP_MD): TC_INT; inline;
begin
  if Assigned(EVP_MD_type) then
   Result := EVP_MD_type(e)
  else
   Result := NID_undef;
end;

function EVP_MD_name(e: PEVP_MD): AnsiString; inline;
begin
  Result := OBJ_nid2sn(EVP_MD_nid(e));
end;

function EVP_MD_CTX_size(e: PEVP_MD_CTX): TC_INT; inline;
begin
  if Assigned(EVP_MD_size) then
   Result := EVP_MD_size(EVP_MD_CTX_md(e))
  else
   Result := 0;
end;

function EVP_MD_CTX_block_size(e: PEVP_MD_CTX): TC_INT; inline;
begin
 if Assigned(EVP_MD_block_size) then
  Result := EVP_MD_block_size(EVP_MD_CTX_md(e))
 else
  Result := 0;
end;

function EVP_MD_CTX_type(e: PEVP_MD_CTX): TC_INT; inline;
begin
 if Assigned(EVP_MD_type) then
   Result := EVP_MD_type(EVP_MD_CTX_md(e))
 else
  Result := 0;
end;

function EVP_CIPHER_name(e: PEVP_CIPHER): AnsiString; inline;
begin
  Result := OBJ_nid2sn(EVP_CIPHER_nid(e));
end;

function EVP_CIPHER_mode(e: PEVP_CIPHER): TC_ULONG; inline;
begin
  Result := EVP_CIPHER_flags(e) and EVP_CIPH_MODE;
end;

function EVP_CIPHER_CTX_type(e: PEVP_CIPHER_CTX): TC_INT; inline;
begin
  Result := EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(e));
end;

function EVP_CIPHER_CTX_mode(e: PEVP_CIPHER_CTX): TC_ULONG; inline;
begin
  Result := EVP_CIPHER_CTX_flags(e) and EVP_CIPH_MODE;
end;

function EVP_ENCODE_LENGTH(l: TC_INT): TC_INT; inline;
begin
  Result := (((l+2) div 3*4)+(l div 48+1)*2+80);
end;

function EVP_DECODE_LENGTH(l: TC_INT): TC_INT; inline;
begin
  Result := ((l+3) div 4*3+80);
end;

function EVP_SignInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): TC_INT; inline;
begin
  Result := EVP_DigestInit(ctx, _type);
end;

function EVP_SignInitEx(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): TC_INT; inline;
begin
  Result := EVP_DigestInit_ex(ctx, _type, impl);
end;

function EVP_SignUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function EVP_VerifyInit_ex(ctx: PEVP_MD_CTX; const _type: PEVP_MD; impl: PENGINE): TC_INT; inline;
begin
  Result := EVP_DigestInit_ex(ctx, _type, impl);
end;

function EVP_VerifyInit(ctx: PEVP_MD_CTX; const _type: PEVP_MD): TC_INT; inline;
begin
  Result := EVP_DigestInit(ctx, _type);
end;

function EVP_VerifyUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
begin
  Result :=EVP_DigestUpdate(ctx, d, cnt);
end;

function EVP_OpenUpdate(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; inline;
begin
  Result := EVP_DecryptUpdate(ctx, _out, outl, _in, inl);
end;

function EVP_SealUpdate(ctx: PEVP_CIPHER_CTX; _out: PAnsiChar; var outl: TC_INT; const _in: PAnsiChar; inl: TC_INT): TC_INT; inline;
begin
  Result := EVP_EncryptUpdate(ctx, _out, outl, _in, inl);
end;

function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX;const d: Pointer; cnt: TC_SIZE_T): TC_INT; inline;
begin
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;


procedure SSL_InitEVP;
begin
  if @EVP_PKEY_assign = nil then
  begin
     @EVP_MD_type:= LoadFunctionCLib('EVP_MD_type');
     @EVP_MD_pkey_type:= LoadFunctionCLib('EVP_MD_pkey_type');
     @EVP_MD_size:= LoadFunctionCLib('EVP_MD_size');
     @EVP_MD_block_size:= LoadFunctionCLib('EVP_MD_block_size');
     @EVP_MD_flags:= LoadFunctionCLib('EVP_MD_flags', False);
     @EVP_MD_CTX_md:= LoadFunctionCLib('EVP_MD_CTX_md');
     @EVP_CIPHER_nid:= LoadFunctionCLib('EVP_CIPHER_nid');
     @EVP_CIPHER_block_size:= LoadFunctionCLib('EVP_CIPHER_block_size');
     @EVP_CIPHER_key_length:= LoadFunctionCLib('EVP_CIPHER_key_length');
     @EVP_CIPHER_iv_length:= LoadFunctionCLib('EVP_CIPHER_iv_length');
     @EVP_CIPHER_flags:= LoadFunctionCLib('EVP_CIPHER_flags');
     @EVP_CIPHER_CTX_cipher:= LoadFunctionCLib('EVP_CIPHER_CTX_cipher');
     @EVP_CIPHER_CTX_nid:= LoadFunctionCLib('EVP_CIPHER_CTX_nid', false);
     @EVP_CIPHER_CTX_block_size:= LoadFunctionCLib('EVP_CIPHER_CTX_block_size');
     @EVP_CIPHER_CTX_key_length:= LoadFunctionCLib('EVP_CIPHER_CTX_key_length');
     @EVP_CIPHER_CTX_iv_length:= LoadFunctionCLib('EVP_CIPHER_CTX_iv_length');
     @EVP_CIPHER_CTX_copy:= LoadFunctionCLib('EVP_CIPHER_CTX_copy', false);
     @EVP_CIPHER_CTX_get_app_data:= LoadFunctionCLib('EVP_CIPHER_CTX_get_app_data');
     @EVP_CIPHER_CTX_set_app_data:= LoadFunctionCLib('EVP_CIPHER_CTX_set_app_data');
     @EVP_CIPHER_CTX_flags:= LoadFunctionCLib('EVP_CIPHER_CTX_flags');
     @BIO_set_md:= LoadFunctionCLib('BIO_set_md', false);
     @EVP_Cipher:= LoadFunctionCLib('EVP_Cipher');
     @EVP_MD_CTX_init:= LoadFunctionCLib('EVP_MD_CTX_init');
     @EVP_MD_CTX_cleanup:= LoadFunctionCLib('EVP_MD_CTX_cleanup');
     @EVP_MD_CTX_create:= LoadFunctionCLib('EVP_MD_CTX_create');
     @EVP_MD_CTX_destroy:= LoadFunctionCLib('EVP_MD_CTX_destroy');
     @EVP_MD_CTX_copy_ex:= LoadFunctionCLib('EVP_MD_CTX_copy_ex');
     @EVP_MD_CTX_set_flags:= LoadFunctionCLib('EVP_MD_CTX_set_flags');
     @EVP_MD_CTX_clear_flags:= LoadFunctionCLib('EVP_MD_CTX_clear_flags');
     @EVP_MD_CTX_test_flags:= LoadFunctionCLib('EVP_MD_CTX_test_flags');
     @EVP_DigestInit_ex:= LoadFunctionCLib('EVP_DigestInit_ex');
     @EVP_DigestUpdate:= LoadFunctionCLib('EVP_DigestUpdate');
     @EVP_DigestFinal_ex:= LoadFunctionCLib('EVP_DigestFinal_ex');
     @EVP_Digest:= LoadFunctionCLib('EVP_Digest');
     @EVP_MD_CTX_copy:= LoadFunctionCLib('EVP_MD_CTX_copy');
     @EVP_DigestInit:= LoadFunctionCLib('EVP_DigestInit');
     @EVP_DigestFinal:= LoadFunctionCLib('EVP_DigestFinal');
     @EVP_read_pw_string:= LoadFunctionCLib('EVP_read_pw_string');
     @EVP_read_pw_string_min:= LoadFunctionCLib('EVP_read_pw_string_min', false);
     @EVP_set_pw_prompt:= LoadFunctionCLib('EVP_set_pw_prompt');
     @EVP_get_pw_prompt:= LoadFunctionCLib('EVP_get_pw_prompt');
     @EVP_BytesToKey:= LoadFunctionCLib('EVP_BytesToKey');
     @EVP_CIPHER_CTX_set_flags:= LoadFunctionCLib('EVP_CIPHER_CTX_set_flags');
     @EVP_CIPHER_CTX_clear_flags:= LoadFunctionCLib('EVP_CIPHER_CTX_clear_flags');
     @EVP_CIPHER_CTX_test_flags:= LoadFunctionCLib('EVP_CIPHER_CTX_test_flags');
     @EVP_EncryptInit:= LoadFunctionCLib('EVP_EncryptInit');
     @EVP_EncryptInit_ex:= LoadFunctionCLib('EVP_EncryptInit_ex');
     @EVP_EncryptUpdate:= LoadFunctionCLib('EVP_EncryptUpdate');
     @EVP_EncryptFinal_ex:= LoadFunctionCLib('EVP_EncryptFinal_ex');
     @EVP_EncryptFinal:= LoadFunctionCLib('EVP_EncryptFinal');
     @EVP_DecryptInit:= LoadFunctionCLib('EVP_DecryptInit');
     @EVP_DecryptInit_ex:= LoadFunctionCLib('EVP_DecryptInit_ex');
     @EVP_DecryptUpdate:= LoadFunctionCLib('EVP_DecryptUpdate');
     @EVP_DecryptFinal:= LoadFunctionCLib('EVP_DecryptFinal');
     @EVP_DecryptFinal_ex:= LoadFunctionCLib('EVP_DecryptFinal_ex');
     @EVP_CipherInit:= LoadFunctionCLib('EVP_CipherInit');
     @EVP_CipherInit_ex:= LoadFunctionCLib('EVP_CipherInit_ex');
     @EVP_CipherUpdate:= LoadFunctionCLib('EVP_CipherUpdate');
     @EVP_CipherFinal:= LoadFunctionCLib('EVP_CipherFinal');
     @EVP_CipherFinal_ex:= LoadFunctionCLib('EVP_CipherFinal_ex');
     @EVP_SignFinal:= LoadFunctionCLib('EVP_SignFinal');
     @EVP_VerifyFinal:= LoadFunctionCLib('EVP_VerifyFinal');
     @EVP_DigestSignInit:= LoadFunctionCLib('EVP_DigestSignInit', False);
     @EVP_DigestSignFinal:= LoadFunctionCLib('EVP_DigestSignFinal', false);
     @EVP_DigestVerifyInit:= LoadFunctionCLib('EVP_DigestVerifyInit', false);
     @EVP_DigestVerifyFinal:= LoadFunctionCLib('EVP_DigestVerifyFinal', false);
     @EVP_OpenInit:= LoadFunctionCLib('EVP_OpenInit');
     @EVP_OpenFinal:= LoadFunctionCLib('EVP_OpenFinal');
     @EVP_SealInit:= LoadFunctionCLib('EVP_SealInit');
     @EVP_SealFinal:= LoadFunctionCLib('EVP_SealFinal');
     @EVP_EncodeInit:= LoadFunctionCLib('EVP_EncodeInit');
     @EVP_EncodeUpdate:= LoadFunctionCLib('EVP_EncodeUpdate');
     @EVP_EncodeFinal:= LoadFunctionCLib('EVP_EncodeFinal');
     @EVP_EncodeBlock:= LoadFunctionCLib('EVP_EncodeBlock');
     @EVP_DecodeInit:= LoadFunctionCLib('EVP_DecodeInit');
     @EVP_DecodeUpdate:= LoadFunctionCLib('EVP_DecodeUpdate');
     @EVP_DecodeFinal:= LoadFunctionCLib('EVP_DecodeFinal');
     @EVP_DecodeBlock:= LoadFunctionCLib('EVP_DecodeBlock');
     @EVP_CIPHER_CTX_init:= LoadFunctionCLib('EVP_CIPHER_CTX_init');
     @EVP_CIPHER_CTX_free:= LoadFunctionCLib('EVP_CIPHER_CTX_free');
     @EVP_CIPHER_CTX_new:= LoadFunctionCLib('EVP_CIPHER_CTX_new');
     @EVP_CIPHER_CTX_cleanup:= LoadFunctionCLib('EVP_CIPHER_CTX_cleanup');
     @EVP_CIPHER_CTX_set_key_length:= LoadFunctionCLib('EVP_CIPHER_CTX_set_key_length');
     @EVP_CIPHER_CTX_set_padding:= LoadFunctionCLib('EVP_CIPHER_CTX_set_padding');
     @EVP_CIPHER_CTX_ctrl:= LoadFunctionCLib('EVP_CIPHER_CTX_ctrl');
     @EVP_CIPHER_CTX_rand_key:= LoadFunctionCLib('EVP_CIPHER_CTX_rand_key');
     @BIO_f_md:= LoadFunctionCLib('BIO_f_md');
     @BIO_f_base64:= LoadFunctionCLib('BIO_f_base64');
     @BIO_f_cipher:= LoadFunctionCLib('BIO_f_cipher');
     @BIO_f_reliable:= LoadFunctionCLib('BIO_f_reliable');
     @BIO_set_cipher:= LoadFunctionCLib('BIO_set_cipher');
     @EVP_md_null:= LoadFunctionCLib('EVP_md_null');
     @EVP_md2:= LoadFunctionCLib('EVP_md2', false);
     @EVP_md4:= LoadFunctionCLib('EVP_md4');
     @EVP_md5:= LoadFunctionCLib('EVP_md5');
     @EVP_sha:= LoadFunctionCLib('EVP_sha');
     @EVP_sha1:= LoadFunctionCLib('EVP_sha1');
     @EVP_dss:= LoadFunctionCLib('EVP_dss');
     @EVP_dss1:= LoadFunctionCLib('EVP_dss1');
     @EVP_ecdsa:= LoadFunctionCLib('EVP_ecdsa');
     @EVP_sha224:= LoadFunctionCLib('EVP_sha224');
     @EVP_sha256:= LoadFunctionCLib('EVP_sha256');
     @EVP_sha384:= LoadFunctionCLib('EVP_sha384');
     @EVP_sha512:= LoadFunctionCLib('EVP_sha512');
     @EVP_mdc2:= LoadFunctionCLib('EVP_mdc2', false);
     @EVP_ripemd160:= LoadFunctionCLib('EVP_ripemd160');
     @EVP_whirlpool:= LoadFunctionCLib('EVP_whirlpool', false);
     @EVP_dev_crypto_md5:= LoadFunctionCLib('EVP_dev_crypto_md5', false);
     @EVP_enc_null:= LoadFunctionCLib('EVP_enc_null');
     @EVP_des_ecb:= LoadFunctionCLib('EVP_des_ecb');
     @EVP_des_ede:= LoadFunctionCLib('EVP_des_ede');
     @EVP_des_ede3:= LoadFunctionCLib('EVP_des_ede3');
     @EVP_des_ede_ecb:= LoadFunctionCLib('EVP_des_ede_ecb');
     @EVP_des_ede3_ecb:= LoadFunctionCLib('EVP_des_ede3_ecb');
     @EVP_des_cfb64:= LoadFunctionCLib('EVP_des_cfb64');
     @EVP_des_cfb1:= LoadFunctionCLib('EVP_des_cfb1');
     @EVP_des_cfb8:= LoadFunctionCLib('EVP_des_cfb8');
     @EVP_des_ede_cfb64:= LoadFunctionCLib('EVP_des_ede_cfb64');
     @EVP_des_ede_cfb1:= LoadFunctionCLib('EVP_des_ede_cfb1', false);
     @EVP_des_ede_cfb8:= LoadFunctionCLib('EVP_des_ede_cfb8', false);
     @EVP_des_ede3_cfb64:= LoadFunctionCLib('EVP_des_ede3_cfb64');
     @EVP_des_ede3_cfb1:= LoadFunctionCLib('EVP_des_ede3_cfb1');
     @EVP_des_ede3_cfb8:= LoadFunctionCLib('EVP_des_ede3_cfb8');
     @EVP_des_ofb:= LoadFunctionCLib('EVP_des_ofb');
     @EVP_des_ede_ofb:= LoadFunctionCLib('EVP_des_ede_ofb');
     @EVP_des_ede3_ofb:= LoadFunctionCLib('EVP_des_ede3_ofb');
     @EVP_des_cbc:= LoadFunctionCLib('EVP_des_cbc');
     @EVP_des_ede_cbc:= LoadFunctionCLib('EVP_des_ede_cbc');
     @EVP_des_ede3_cbc:= LoadFunctionCLib('EVP_des_ede3_cbc');
     @EVP_desx_cbc:= LoadFunctionCLib('EVP_desx_cbc');
     @EVP_dev_crypto_des_ede3_cbc:= LoadFunctionCLib('EVP_dev_crypto_des_ede3_cbc', false);
     @EVP_dev_crypto_rc4:= LoadFunctionCLib('EVP_dev_crypto_rc4', false);
     @EVP_rc4:= LoadFunctionCLib('EVP_rc4');
     @EVP_rc4_40:= LoadFunctionCLib('EVP_rc4_40');
     @EVP_rc4_hmac_md5:= LoadFunctionCLib('EVP_rc4_hmac_md5', false);
     @EVP_idea_ecb:= LoadFunctionCLib('EVP_idea_ecb');
     @EVP_idea_cfb64:= LoadFunctionCLib('EVP_idea_cfb64');
     @EVP_idea_ofb:= LoadFunctionCLib('EVP_idea_ofb');
     @EVP_idea_cbc:= LoadFunctionCLib('EVP_idea_cbc');
     @EVP_rc2_ecb:= LoadFunctionCLib('EVP_rc2_ecb');
     @EVP_rc2_cbc:= LoadFunctionCLib('EVP_rc2_cbc');
     @EVP_rc2_40_cbc:= LoadFunctionCLib('EVP_rc2_40_cbc');
     @EVP_rc2_64_cbc:= LoadFunctionCLib('EVP_rc2_64_cbc');
     @EVP_rc2_cfb64:= LoadFunctionCLib('EVP_rc2_cfb64');
     @EVP_rc2_ofb:= LoadFunctionCLib('EVP_rc2_ofb');
     @EVP_bf_ecb:= LoadFunctionCLib('EVP_bf_ecb');
     @EVP_bf_cbc:= LoadFunctionCLib('EVP_bf_cbc');
     @EVP_bf_cfb64:= LoadFunctionCLib('EVP_bf_cfb64');
     @EVP_bf_ofb:= LoadFunctionCLib('EVP_bf_ofb');
     @EVP_cast5_ecb:= LoadFunctionCLib('EVP_cast5_ecb');
     @EVP_cast5_cbc:= LoadFunctionCLib('EVP_cast5_cbc');
     @EVP_cast5_cfb64:= LoadFunctionCLib('EVP_cast5_cfb64');
     @EVP_cast5_ofb:= LoadFunctionCLib('EVP_cast5_ofb');
     @EVP_rc5_32_12_16_cbc:= LoadFunctionCLib('EVP_rc5_32_12_16_cbc', false);
     @EVP_rc5_32_12_16_ecb:= LoadFunctionCLib('EVP_rc5_32_12_16_ecb', false);
     @EVP_rc5_32_12_16_cfb64:= LoadFunctionCLib('EVP_rc5_32_12_16_cfb64', false);
     @EVP_rc5_32_12_16_ofb:= LoadFunctionCLib('EVP_rc5_32_12_16_ofb', false);
     @EVP_aes_128_ecb:= LoadFunctionCLib('EVP_aes_128_ecb');
     @EVP_aes_128_cbc:= LoadFunctionCLib('EVP_aes_128_cbc');
     @EVP_aes_128_cfb1:= LoadFunctionCLib('EVP_aes_128_cfb1');
     @EVP_aes_128_cfb8:= LoadFunctionCLib('EVP_aes_128_cfb8');
     @EVP_aes_128_cfb128:= LoadFunctionCLib('EVP_aes_128_cfb128');
     @EVP_aes_128_ofb:= LoadFunctionCLib('EVP_aes_128_ofb');
     @EVP_aes_128_ctr:= LoadFunctionCLib('EVP_aes_128_ctr', false);
     @EVP_aes_128_gcm:= LoadFunctionCLib('EVP_aes_128_gcm', false);
     @EVP_aes_128_ccm:= LoadFunctionCLib('EVP_aes_128_ccm', false);
     @EVP_aes_128_xts:= LoadFunctionCLib('EVP_aes_128_xts', false);
     @EVP_aes_192_ecb:= LoadFunctionCLib('EVP_aes_192_ecb');
     @EVP_aes_192_cbc:= LoadFunctionCLib('EVP_aes_192_cbc');
     @EVP_aes_192_cfb1:= LoadFunctionCLib('EVP_aes_192_cfb1');
     @EVP_aes_192_cfb8:= LoadFunctionCLib('EVP_aes_192_cfb8');
     @EVP_aes_192_cfb128:= LoadFunctionCLib('EVP_aes_192_cfb128');
     @EVP_aes_192_ofb:= LoadFunctionCLib('EVP_aes_192_ofb');
     @EVP_aes_192_ctr:= LoadFunctionCLib('EVP_aes_192_ctr', false);
     @EVP_aes_192_gcm:= LoadFunctionCLib('EVP_aes_192_gcm', false);
     @EVP_aes_192_ccm:= LoadFunctionCLib('EVP_aes_192_ccm', false);
     @EVP_aes_256_ecb:= LoadFunctionCLib('EVP_aes_256_ecb');
     @EVP_aes_256_cbc:= LoadFunctionCLib('EVP_aes_256_cbc');
     @EVP_aes_256_cfb1:= LoadFunctionCLib('EVP_aes_256_cfb1');
     @EVP_aes_256_cfb8:= LoadFunctionCLib('EVP_aes_256_cfb8');
     @EVP_aes_256_cfb128:= LoadFunctionCLib('EVP_aes_256_cfb128');
     @EVP_aes_256_ofb:= LoadFunctionCLib('EVP_aes_256_ofb');
     @EVP_aes_256_ctr:= LoadFunctionCLib('EVP_aes_256_ctr', false);
     @EVP_aes_256_gcm:= LoadFunctionCLib('EVP_aes_256_gcm', false);
     @EVP_aes_256_ccm:= LoadFunctionCLib('EVP_aes_256_ccm', false);
     @EVP_aes_256_xts:= LoadFunctionCLib('EVP_aes_256_xts', false);
     @EVP_aes_128_cbc_hmac_sha1:= LoadFunctionCLib('EVP_aes_128_cbc_hmac_sha1', false);
     @EVP_aes_256_cbc_hmac_sha1:= LoadFunctionCLib('EVP_aes_256_cbc_hmac_sha1', false);
     @EVP_camellia_128_ecb:= LoadFunctionCLib('EVP_camellia_128_ecb', false);
     @EVP_camellia_128_cbc:= LoadFunctionCLib('EVP_camellia_128_cbc', false);
     @EVP_camellia_128_cfb1:= LoadFunctionCLib('EVP_camellia_128_cfb1', false);
     @EVP_camellia_128_cfb8:= LoadFunctionCLib('EVP_camellia_128_cfb8', false);
     @EVP_camellia_128_cfb128:= LoadFunctionCLib('EVP_camellia_128_cfb128', false);
     @EVP_camellia_128_ofb:= LoadFunctionCLib('EVP_camellia_128_ofb', false);
     @EVP_camellia_192_ecb:= LoadFunctionCLib('EVP_camellia_192_ecb', false);
     @EVP_camellia_192_cbc:= LoadFunctionCLib('EVP_camellia_192_cbc', false);
     @EVP_camellia_192_cfb1:= LoadFunctionCLib('EVP_camellia_192_cfb1', false);
     @EVP_camellia_192_cfb8:= LoadFunctionCLib('EVP_camellia_192_cfb8', false);
     @EVP_camellia_192_cfb128:= LoadFunctionCLib('EVP_camellia_192_cfb128', false);
     @EVP_camellia_192_ofb:= LoadFunctionCLib('EVP_camellia_192_ofb', false);
     @EVP_camellia_256_ecb:= LoadFunctionCLib('EVP_camellia_256_ecb', false);
     @EVP_camellia_256_cbc:= LoadFunctionCLib('EVP_camellia_256_cbc', false);
     @EVP_camellia_256_cfb1:= LoadFunctionCLib('EVP_camellia_256_cfb1', false);
     @EVP_camellia_256_cfb8:= LoadFunctionCLib('EVP_camellia_256_cfb8', false);
     @EVP_camellia_256_cfb128:= LoadFunctionCLib('EVP_camellia_256_cfb128', false);
     @EVP_camellia_256_ofb:= LoadFunctionCLib('EVP_camellia_256_ofb', false);
     @EVP_seed_ecb:= LoadFunctionCLib('EVP_seed_ecb', false);
     @EVP_seed_cbc:= LoadFunctionCLib('EVP_seed_cbc', false);
     @EVP_seed_cfb128:= LoadFunctionCLib('EVP_seed_cfb128', false);
     @EVP_seed_ofb:= LoadFunctionCLib('EVP_seed_ofb', false);
     @OPENSSL_add_all_algorithms_noconf:= LoadFunctionCLib('OPENSSL_add_all_algorithms_noconf');
     @OPENSSL_add_all_algorithms_conf:= LoadFunctionCLib('OPENSSL_add_all_algorithms_conf');
     @OpenSSL_add_all_ciphers:= LoadFunctionCLib('OpenSSL_add_all_ciphers');
     @OpenSSL_add_all_digests:= LoadFunctionCLib('OpenSSL_add_all_digests');
     @EVP_add_cipher:= LoadFunctionCLib('EVP_add_cipher');
     @EVP_add_digest:= LoadFunctionCLib('EVP_add_digest');
     @EVP_get_cipherbyname:= LoadFunctionCLib('EVP_get_cipherbyname');
     @EVP_get_digestbyname:= LoadFunctionCLib('EVP_get_digestbyname');
     @EVP_cleanup:= LoadFunctionCLib('EVP_cleanup');
     @EVP_CIPHER_do_all:= LoadFunctionCLib('EVP_CIPHER_do_all', false);
     @EVP_CIPHER_do_all_sorted:= LoadFunctionCLib('EVP_CIPHER_do_all_sorted', false);
     @EVP_MD_do_all:= LoadFunctionCLib('EVP_MD_do_all', false);
     @EVP_MD_do_all_sorted:= LoadFunctionCLib('EVP_MD_do_all_sorted', false);
     @EVP_PKEY_decrypt_old:= LoadFunctionCLib('EVP_PKEY_decrypt_old', false);
     @EVP_PKEY_encrypt_old:= LoadFunctionCLib('EVP_PKEY_encrypt_old', false);
     @EVP_PKEY_type:= LoadFunctionCLib('EVP_PKEY_type');
     @EVP_PKEY_id:= LoadFunctionCLib('EVP_PKEY_id', false);
     @EVP_PKEY_base_id:= LoadFunctionCLib('EVP_PKEY_base_id', false);
     @EVP_PKEY_bits:= LoadFunctionCLib('EVP_PKEY_bits');
     @EVP_PKEY_size:= LoadFunctionCLib('EVP_PKEY_size');
     @EVP_PKEY_set_type:= LoadFunctionCLib('EVP_PKEY_set_type', false);
     @EVP_PKEY_set_type_str:= LoadFunctionCLib('EVP_PKEY_set_type_str', false);
     @EVP_PKEY_assign:= LoadFunctionCLib('EVP_PKEY_assign');
     @EVP_PKEY_get0:= LoadFunctionCLib('EVP_PKEY_get0', false);
     @EVP_PKEY_set1_RSA:= LoadFunctionCLib('EVP_PKEY_set1_RSA');
     @EVP_PKEY_get1_RSA:= LoadFunctionCLib('EVP_PKEY_get1_RSA');
     @EVP_PKEY_set1_DSA:= LoadFunctionCLib('EVP_PKEY_set1_DSA');
     @EVP_PKEY_get1_DSA:= LoadFunctionCLib('EVP_PKEY_get1_DSA');
     @EVP_PKEY_set1_DH:= LoadFunctionCLib('EVP_PKEY_set1_DH');
     @EVP_PKEY_get1_DH:= LoadFunctionCLib('EVP_PKEY_get1_DH');
     @EVP_PKEY_set1_EC_KEY:= LoadFunctionCLib('EVP_PKEY_set1_EC_KEY');
     @EVP_PKEY_get1_EC_KEY:= LoadFunctionCLib('EVP_PKEY_get1_EC_KEY');
     @EVP_PKEY_new:= LoadFunctionCLib('EVP_PKEY_new');
     @EVP_PKEY_free:= LoadFunctionCLib('EVP_PKEY_free');
     @d2i_PublicKey:= LoadFunctionCLib('d2i_PublicKey');
     @i2d_PublicKey:= LoadFunctionCLib('i2d_PublicKey');
     @d2i_PrivateKey:= LoadFunctionCLib('d2i_PrivateKey');
     @d2i_AutoPrivateKey:= LoadFunctionCLib('d2i_AutoPrivateKey');
     @i2d_PrivateKey:= LoadFunctionCLib('i2d_PrivateKey');
     @EVP_PKEY_copy_parameters:= LoadFunctionCLib('EVP_PKEY_copy_parameters');
     @EVP_PKEY_missing_parameters:= LoadFunctionCLib('EVP_PKEY_missing_parameters');
     @EVP_PKEY_save_parameters:= LoadFunctionCLib('EVP_PKEY_save_parameters');
     @EVP_PKEY_cmp_parameters:= LoadFunctionCLib('EVP_PKEY_cmp_parameters');
     @EVP_PKEY_cmp:= LoadFunctionCLib('EVP_PKEY_cmp');
     @EVP_PKEY_print_public:= LoadFunctionCLib('EVP_PKEY_print_public', false);
     @EVP_PKEY_print_private:= LoadFunctionCLib('EVP_PKEY_print_private', false);
     @EVP_PKEY_print_params:= LoadFunctionCLib('EVP_PKEY_print_params', false);
     @EVP_PKEY_get_default_digest_nid:= LoadFunctionCLib('EVP_PKEY_get_default_digest_nid', false);
     @EVP_CIPHER_type:= LoadFunctionCLib('EVP_CIPHER_type');
     @EVP_CIPHER_param_to_asn1:= LoadFunctionCLib('EVP_CIPHER_param_to_asn1');
     @EVP_CIPHER_asn1_to_param:= LoadFunctionCLib('EVP_CIPHER_asn1_to_param');
     @EVP_CIPHER_set_asn1_iv:= LoadFunctionCLib('EVP_CIPHER_set_asn1_iv');
     @EVP_CIPHER_get_asn1_iv:= LoadFunctionCLib('EVP_CIPHER_get_asn1_iv');
     @PKCS5_PBE_keyivgen:= LoadFunctionCLib('PKCS5_PBE_keyivgen');
     @PKCS5_PBKDF2_HMAC_SHA1:= LoadFunctionCLib('PKCS5_PBKDF2_HMAC_SHA1');
     @PKCS5_PBKDF2_HMAC:= LoadFunctionCLib('PKCS5_PBKDF2_HMAC', false);
     @PKCS5_v2_PBE_keyivgen:= LoadFunctionCLib('PKCS5_v2_PBE_keyivgen');
     @PKCS5_PBE_add:= LoadFunctionCLib('PKCS5_PBE_add');
     @EVP_PBE_CipherInit:= LoadFunctionCLib('EVP_PBE_CipherInit');
     @EVP_PBE_alg_add_type:= LoadFunctionCLib('EVP_PBE_alg_add_type', false);
     @EVP_PBE_alg_add:= LoadFunctionCLib('EVP_PBE_alg_add');
     @EVP_PBE_find:= LoadFunctionCLib('EVP_PBE_find', false);
     @EVP_PBE_cleanup:= LoadFunctionCLib('EVP_PBE_cleanup');
     @EVP_PKEY_asn1_get_count:= LoadFunctionCLib('EVP_PKEY_asn1_get_count', false);
     @EVP_PKEY_asn1_get0:= LoadFunctionCLib('EVP_PKEY_asn1_get0', false);
     @EVP_PKEY_asn1_find:= LoadFunctionCLib('EVP_PKEY_asn1_find', false);
     @EVP_PKEY_asn1_find_str:= LoadFunctionCLib('EVP_PKEY_asn1_find_str', false);
     @EVP_PKEY_asn1_add0:= LoadFunctionCLib('EVP_PKEY_asn1_add0', false);
     @EVP_PKEY_asn1_add_alias:= LoadFunctionCLib('EVP_PKEY_asn1_add_alias', false);
     @EVP_PKEY_asn1_get0_info:= LoadFunctionCLib('EVP_PKEY_asn1_get0_info', false);
     @EVP_PKEY_get0_asn1:= LoadFunctionCLib('EVP_PKEY_get0_asn1', false);
     @EVP_PKEY_asn1_new:= LoadFunctionCLib('EVP_PKEY_asn1_new', false);
     @EVP_PKEY_asn1_copy:= LoadFunctionCLib('EVP_PKEY_asn1_copy', false);
     @EVP_PKEY_asn1_free:= LoadFunctionCLib('EVP_PKEY_asn1_free', false);
     @EVP_PKEY_asn1_set_public:= LoadFunctionCLib('EVP_PKEY_asn1_set_public', false);
     @EVP_PKEY_asn1_set_private:= LoadFunctionCLib('EVP_PKEY_asn1_set_private', false);
     @EVP_PKEY_asn1_set_param:= LoadFunctionCLib('EVP_PKEY_asn1_set_param', false);
     @EVP_PKEY_asn1_set_free:= LoadFunctionCLib('EVP_PKEY_asn1_set_free', false);
     @EVP_PKEY_asn1_set_ctrl:= LoadFunctionCLib('EVP_PKEY_asn1_set_ctrl', false);
     @EVP_PKEY_meth_find:= LoadFunctionCLib('EVP_PKEY_meth_find', false);
     @EVP_PKEY_meth_new:= LoadFunctionCLib('EVP_PKEY_meth_new', false);
     @EVP_PKEY_meth_get0_info:= LoadFunctionCLib('EVP_PKEY_meth_get0_info', false);
     @EVP_PKEY_meth_copy:= LoadFunctionCLib('EVP_PKEY_meth_copy', false);
     @EVP_PKEY_meth_free:= LoadFunctionCLib('EVP_PKEY_meth_free', false);
     @EVP_PKEY_meth_add0:= LoadFunctionCLib('EVP_PKEY_meth_add0', false);
     @EVP_PKEY_CTX_new:= LoadFunctionCLib('EVP_PKEY_CTX_new', false);
     @EVP_PKEY_CTX_new_id:= LoadFunctionCLib('EVP_PKEY_CTX_new_id', false);
     @EVP_PKEY_CTX_dup:= LoadFunctionCLib('EVP_PKEY_CTX_dup', false);
     @EVP_PKEY_CTX_free:= LoadFunctionCLib('EVP_PKEY_CTX_free', false);
     @EVP_PKEY_CTX_set0_keygen_info:= LoadFunctionCLib('EVP_PKEY_CTX_set0_keygen_info', false);
     @EVP_PKEY_CTX_set_data:= LoadFunctionCLib('EVP_PKEY_CTX_set_data', false);
     @EVP_PKEY_CTX_set_app_data:= LoadFunctionCLib('EVP_PKEY_CTX_set_app_data', false);
     @EVP_PKEY_CTX_ctrl:= LoadFunctionCLib('EVP_PKEY_CTX_ctrl', false);
     @EVP_PKEY_CTX_ctrl_str:= LoadFunctionCLib('EVP_PKEY_CTX_ctrl_str', false);
     @EVP_PKEY_CTX_get_operation:= LoadFunctionCLib('EVP_PKEY_CTX_get_operation', false);
     @EVP_PKEY_new_mac_key:= LoadFunctionCLib('EVP_PKEY_new_mac_key', false);
     @EVP_PKEY_CTX_get_data:= LoadFunctionCLib('EVP_PKEY_CTX_get_data', false);
     @EVP_PKEY_CTX_get0_pkey:= LoadFunctionCLib('EVP_PKEY_CTX_get0_pkey', false);
     @EVP_PKEY_CTX_get0_peerkey:= LoadFunctionCLib('EVP_PKEY_CTX_get0_peerkey', false);
     @EVP_PKEY_CTX_get_app_data:= LoadFunctionCLib('EVP_PKEY_CTX_get_app_data', false);
     @EVP_PKEY_sign_init:= LoadFunctionCLib('EVP_PKEY_sign_init', false);
     @EVP_PKEY_sign:= LoadFunctionCLib('EVP_PKEY_sign', false);
     @EVP_PKEY_verify_init:= LoadFunctionCLib('EVP_PKEY_verify_init', false);
     @EVP_PKEY_verify:= LoadFunctionCLib('EVP_PKEY_verify', false);
     @EVP_PKEY_verify_recover_init:= LoadFunctionCLib('EVP_PKEY_verify_recover_init', false);
     @EVP_PKEY_verify_recover:= LoadFunctionCLib('EVP_PKEY_verify_recover', false);
     @EVP_PKEY_encrypt_init:= LoadFunctionCLib('EVP_PKEY_encrypt_init', false);
     @EVP_PKEY_encrypt:= LoadFunctionCLib('EVP_PKEY_encrypt', false);
     @EVP_PKEY_decrypt_init:= LoadFunctionCLib('EVP_PKEY_decrypt_init', false);
     @EVP_PKEY_decrypt:= LoadFunctionCLib('EVP_PKEY_decrypt', false);
     @EVP_PKEY_derive_init:= LoadFunctionCLib('EVP_PKEY_derive_init', false);
     @EVP_PKEY_derive_set_peer:= LoadFunctionCLib('EVP_PKEY_derive_set_peer', false);
     @EVP_PKEY_derive:= LoadFunctionCLib('EVP_PKEY_derive', false);
     @EVP_PKEY_paramgen_init:= LoadFunctionCLib('EVP_PKEY_paramgen_init', false);
     @EVP_PKEY_paramgen:= LoadFunctionCLib('EVP_PKEY_paramgen', false);
     @EVP_PKEY_keygen_init:= LoadFunctionCLib('EVP_PKEY_keygen_init', false);
     @EVP_PKEY_keygen:= LoadFunctionCLib('EVP_PKEY_keygen', false);
     @EVP_PKEY_CTX_set_cb:= LoadFunctionCLib('EVP_PKEY_CTX_set_cb', false);
     @EVP_PKEY_CTX_get_cb:= LoadFunctionCLib('EVP_PKEY_CTX_get_cb', false);
     @EVP_PKEY_CTX_get_keygen_info:= LoadFunctionCLib('EVP_PKEY_CTX_get_keygen_info', false);
     @ERR_load_EVP_strings:= LoadFunctionCLib('ERR_load_EVP_strings');

     SSL_InitOBJ;
  end;
end;

end.