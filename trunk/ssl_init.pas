unit ssl_init;

interface

procedure SSL_InitLib;

implementation

uses
  ssl_ec, ssl_util, ssl_types, ssl_lib, ssl_evp, ssl_const, ssl_rsa, ssl_dsa, ssl_x509, ssl_bio, ssl_pem, ssl_asn,
  ssl_aes, ssl_bf, ssl_bn, ssl_buffer, ssl_cast, ssl_cmac, ssl_engine, ssl_rand, ssl_camellia, ssl_comp, ssl_des,
  ssl_dh, ssl_err, ssl_objects, ssl_sk, ssl_pkcs12, ssl_pkcs7, ssl_cms, ssl_ecdh, ssl_ecdsa, ssl_hmac, ssl_idea,
  ssl_lhash, ssl_md4, ssl_md5, ssl_ocsp, ssl_mdc2, ssl_rc2, ssl_rc4, ssl_rc5, ssl_ripemd;


procedure SSL_InitLib;
begin
  ssl_util.SSL_InitUtil;
  ssl_err.SSL_InitERR;
  ssl_objects.SSL_InitOBJ;
  ssl_bio.SSL_InitBIO;
  ssl_ec.SSL_InitEC;
  ssl_evp.SSL_InitEVP;
  ssl_rsa.SSL_InitRSA;
  ssl_dsa.SSL_InitDSA;
  ssl_x509.SSL_InitX509;
  ssl_pem.SSL_InitPEM;
  ssl_asn.SSL_InitASN1;
  ssl_aes.SSL_InitAES;
  ssl_bf.SSL_InitBF;
  ssl_bn.SSL_InitBN;
  ssl_buffer.SSL_InitBuffer;
  ssl_cast.SLL_InitCAST;
  ssl_cmac.SSL_InitCMAC;
  ssl_engine.SSL_InitENGINE;
  ssl_rand.SSL_InitRAND;
  ssl_camellia.SSL_InitCAMELLIA;
  ssl_comp.SSL_InitCOMP;
  ssl_des.SSL_InitDES;
  ssl_dh.SSL_InitDH;
  ssl_sk.SSL_initSk;
  ssl_pkcs12.SSL_InitPKCS12;
  ssl_pkcs7.SSL_InitPKCS7;
  ssl_cms.SSL_InitCMS;
  ssl_ecdh.SSL_InitSSLDH;
  ssl_ecdsa.SSL_InitECDSA;
  ssl_hmac.SSL_InitHMAC;
  ssl_idea.SSL_InitIDEA;
  ssl_lhash.SSL_InitLHASH;
  ssl_md4.SSL_InitMD4;
  ssl_md5.SSL_InitMD5;
  ssl_ocsp.SSL_InitOCSP;
  ssl_mdc2.ssl_initmdc2;
  ssl_rc2.SSL_Initrc2;
  ssl_rc4.SSL_Initrc4;
  ssl_rc5.SSL_Initrc5;
  ssl_ripemd.SSL_Initripemd;
end;


end.
