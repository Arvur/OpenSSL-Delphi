program mysign;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  ssl_evp,
  ssl_bio,
  ssl_err,
  ssl_const,
  ssl_types,
  ssl_pem,
  ssl_engine,
  ssl_x509;

var
  certFile: AnsiString;
  PrivKey: AnsiString;
  signFile: AnsiString;
  Path: AnsiString;
  pkey: PEVP_PKEY;
  bp: PBIO;
  md_ctx: EVP_MD_CTX;
  Buf: AnsiString;
  Len: Integer;
  SigBuf: Array [0..4095] of AnsiChar;
  SigLen: Integer;
  InBuf: Array[0..511] of AnsiChar;
  _x509: PX509;
  b64: PBIO;
  a, i : Integer;

function _OnGetPassword(buf: PAnsiString; size: TC_INT; rwflag: TC_INT; userdata: pointer): integer; cdecl;
var P: AnsiString;
begin

 repeat
  Write('Private key password: ');
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


begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    Writeln('DEMO: mysign');

    SSL_InitPEM;
    SSL_InitERR;
    SSL_InitBIO;
    SSL_InitEVP;
    SSL_InitENGINE;
    SSL_InitX509;

    ENGINE_load_builtin_engines;
    OpenSSL_add_all_ciphers;
    OpenSSL_add_all_digests;
    Path := ExtractFilePath(ParamStr(0));
    certFile := Path + 'cacert.pem';
    PrivKey := Path + 'private.pem';
    signFile := Path+'sign.pem';

    if (not FileExists(certFile)) or (not FileExists(PrivKey)) then
     raise Exception.Create('Certificate or Private Key not found. Use mycert.exe first');

    Buf := 'Test string for sign';
    Len := Length(Buf);
    Writeln('Sign test phrase: '+Buf);
{ Sign }
    bp := BIO_new_file(PAnsiChar(PrivKey), 'r');
    SSL_CheckError;
    try
     pkey := PEM_read_bio_PrivateKey(bp, nil, _OnGetPassword, nil);
     SSL_CheckError;
    finally
      BIO_free(bp);
    end;


    EVP_SignInit(@md_ctx, EVP_sha384);
    SSL_CheckError;
    EVP_SignUpdate(@md_ctx, PAnsiChar(buf), len);
    SSL_CheckError;

    EVP_SignFinal(@md_ctx, @SigBuf, SigLen, pkey);
    SSL_CheckError;
    Writeln('Sign size ', SigLen, ' bytes');

    EVP_PKEY_free(pkey);

    bp := BIO_new_file(PAnsiChar(signFile), 'w');

    b64 := BIO_new(BIO_f_base64);
    bp := BIO_push(b64, bp);

    BIO_write(bp, @SigBuf, SigLen);
    BIO_flush(bp);
    Writeln('Bytes written ', BIO_number_written(bp), ' file ', signFile);
    BIO_free_all(bp);
{ End sign }

{ Verify }
    Writeln('Verify sign');
    bp := BIO_new_file(PAnsiChar(certFile), 'r');
    SSL_CheckError;
    try
     _x509 := PEM_read_bio_X509(bp, nil, _OnGetPassword, nil);
     SSL_CheckError;
    finally
      BIO_free(bp);
    end;

    fillchar(md_ctx, SizeOf(md_ctx), 0);

    pkey := X509_get_pubkey(_x509);

    b64 := BIO_new(BIO_f_base64);
    bp := BIO_new_file(PAnsiChar(signFile), 'r');
    SSL_CheckError;
    try
      bp := BIO_push(b64, bp);
      FillChar(SigBuf[0], SizeOf(SigBuf), 0);
      i := 0;
      repeat
       a := BIO_read(bp, @InBuf, 512);
       if a > 0 then
        Move(InBuf[0], SigBuf[i], a);
       inc(i, a);
      until a <= 0;

    finally
      BIO_free_all(bp);
    end;

    EVP_VerifyInit(@md_ctx, EVP_sha384);
    SSL_CheckError;
    EVP_VerifyUpdate(@md_ctx, PAnsiChar(Buf), Len);
    SSL_CheckError;
    EVP_VerifyFinal(@md_ctx, SigBuf, SigLen, pkey);
    SSL_CheckError;
    EVP_PKEY_free(pkey);
    Writeln('Verify Ok');

{ End verify }

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
