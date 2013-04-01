program mycert;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  ssl_const in '..\ssl_const.pas',
  ssl_rsa in '..\ssl_rsa.pas',
  ssl_types in '..\ssl_types.pas',
  ssl_x509 in '..\ssl_x509.pas',
  ssl_lib in '..\ssl_lib.pas',
  ssl_evp in '..\ssl_evp.pas',
  ssl_err in '..\ssl_err.pas',
  ssl_asn in '..\ssl_asn.pas',
  ssl_bio in '..\ssl_bio.pas',
  ssl_pem in '..\ssl_pem.pas';

function add_ext(cert: PX509; nid: TC_INT; value: PAnsiChar): Boolean;
var ex: PX509_EXTENSION;
    ctx: X509V3_CTX;
begin
  Result := false;
  ctx.db := nil;
  X509V3_set_ctx(ctx, cert, cert, nil, nil, 0);
  ex := X509V3_EXT_conf_nid(nil, @ctx, nid, value);
  if ex <> nil then
  begin
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    Result := True;
  end;

end;

function _OnGetPassword(buf: PAnsiString; size: TC_INT; rwflag: TC_INT; userdata: pointer): integer; cdecl;
var P: AnsiString;
begin

 repeat
  Write('Password: ');
  Readln(P);
  Result := Length(P);
   if Result = 0 then
     writeln('Password is not empty!')
   else
    Break;
 until False;

 if Result > size then
   Result := size;
 if Result > 0 then
    Move(P[1], buf^, Result);
end;


procedure keycallback(p, n: TC_INT; arg: Pointer); cdecl;
var c: AnsiString;
begin
  c := 'B';
  case p of
    0: c := c+'.'#13;
    1: c := c+'+'#13;
    2: c := c+'*'#13;
    3: c := #13#10;
  end;
  write(c);
end;

procedure mkcert(var x509p: PX509; var pkeyp: PEVP_PKEY; bits: TC_INT; serial: TC_INT; days: TC_INT);
var FRSA: PRSA;
   name: PX509_NAME;
begin
 if pkeyp = nil then
 begin
   pkeyp := EVP_PKEY_new;
   SSL_CheckError;
 end;
 if x509p = nil then
  begin
    x509p := X509_new;
    SSL_CheckError;
  end;
  writeln('Generate RSA key, ', bits, ' bits');
  FRSA := RSA_generate_key(bits, $10001, keycallback, nil);
  SSL_CheckError;
  EVP_PKEY_assign_RSA(pkeyp, FRSA);
  SSL_CheckError;
  X509_set_version(x509p, 2);
  Writeln('Set certificate parameters');
  ASN1_INTEGER_set(X509_get_serialNumber(x509p), 1);

  X509_gmtime_adj(x509p.cert_info.validity.notBefore, 0);
  X509_gmtime_adj(x509p.cert_info.validity.notAfter, 60*60*24*days);
  X509_set_pubkey(x509p, pkeyp);
  Name := X509_get_subject_name(x509p);
  X509_NAME_add_entry_by_txt(Name, 'C', MBSTRING_ASC, 'RU', -1, -1, 0);
  X509_NAME_add_entry_by_txt(Name, 'CN', MBSTRING_ASC, 'OpenSSL Group', -1, -1, 0);
  X509_set_issuer_name(x509p, name);
  add_ext(x509p, NID_basic_constraints, 'critical,CA:TRUE');
  add_ext(x509p, NID_key_usage, 'critical,keyCertSign,cRLSign');
  add_ext(x509p, NID_subject_key_identifier, 'hash');
	add_ext(x509p, NID_netscape_cert_type, 'sslCA');

	add_ext(x509p, NID_netscape_comment, 'example comment extension');

  X509_sign(x509p, pkeyp, EVP_sha1);
  SSL_CheckError;
end;

var
  FX509: PX509;
  FKey: PEVP_PKEY;
  FBio: PBIO;
  FFilePath: String;
  FPrivKeyFile, FPubKeyFile, FCertFile: AnsiString;
begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    Writeln('mkcert');
    writeln('DEMO generate self-signed certificate and private key');
    SSL_InitERR;
    SSL_InitEVP;
    SSL_InitRSA;
    SSL_InitX509;
    SSL_InitBIO;
    SSL_InitASN1;
    SSL_InitPEM;

    mkcert(FX509, FKey, 2048, 1, 365);

    FFilePath := ExtractFilePath(ParamStr(0));
    FPrivKeyFile := FFilePath + 'private.pem';
    FPubKeyFile := FFilePath + 'public.pem';
    FCertFile := FFilePath + 'cacert.pem';
    Writeln('Write private key (private.pem), encrypted by AES-129-CBC');
    FBio := BIO_new_file(PAnsiChar(FPrivKeyFile), 'w');
    try
      PEM_write_bio_RSAPrivateKey(FBio, FKey.pkey.rsa, EVP_aes_128_cbc(), nil, 0, _OnGetPassword, nil);
    finally
      BIO_free(FBio);
    end;
    Writeln('Write public key (public.pem)');
    FBio := BIO_new_file(PAnsiChar(FPubKeyFile), 'w');
    try
      PEM_write_bio_PUBKEY(FBio, FKey);
    finally
      BIO_free(FBio);
    end;

    Writeln('Write self-signed certificate (cacert.pem)');
    FBio := BIO_new_file(PAnsiChar(FCertFile), 'w');
    try
      PEM_write_bio_X509(FBio, FX509);
    finally
      BIO_free(FBio);
    end;

    X509_free(FX509);
    EVP_PKEY_free(FKey);

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
