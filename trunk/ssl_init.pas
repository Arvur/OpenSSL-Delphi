unit ssl_init;

interface

procedure SSL_InitLib;

implementation

uses
  ssl_ec, ssl_util, ssl_types, ssl_lib, ssl_evp, ssl_const, ssl_rsa, ssl_dsa, ssl_x509, ssl_bio, ssl_pem, ssl_asn,
  ssl_aes, ssl_bf;


procedure SSL_InitLib;
begin
  ssl_bio.SSL_InitBIO;
  ssl_ec.SSL_InitEC;
  ssl_evp.SSL_InitEVP;
  ssl_rsa.SSL_InitRSA;
  ssl_dsa.SSL_InitDSA;
  ssl_x509.SSL_InitX509;
  ssl_pem.SSL_InitPEM;
  ssl_asn.SSL_InitASN1;
  ssl_aes.SSL_InitAES;
  ssl_bf.SSL_InitBF
end;

end.
