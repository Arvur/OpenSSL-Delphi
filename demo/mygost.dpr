program mygost;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  ssl_engine in '..\ssl_engine.pas',
  ssl_err in '..\ssl_err.pas',
  ssl_types in '..\ssl_types.pas',
  ssl_const in '..\ssl_const.pas',
  ssl_lib in '..\ssl_lib.pas',
  ssl_evp in '..\ssl_evp.pas',
  ssl_bio in '..\ssl_bio.pas',
  ssl_pem in '..\ssl_pem.pas',
  ssl_objects in '..\ssl_objects.pas',
  ssl_util in '..\ssl_util.pas',
  ssl_asn in '..\ssl_asn.pas';

var
  GostLib: AnsiString;
  E: PENGINE;


// Callback for keygen
function  EVP_KEYGENCB(ctx: PEVP_PKEY_CTX): TC_INT; cdecl;
begin
  Result := 1;
end;

function EVP_PASS_CB(buf: PAnsiString; size: TC_INT; rwflag: TC_INT; userdata: pointer): integer; cdecl;
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

procedure Encrypt(Src: PAnsiChar; SrcLen: Cardinal; Dst: PAnsiChar; var DstLen: Cardinal; AKey: PEVP_PKEY);
var Ctx: PEVP_PKEY_CTX;
    r: TC_INT;
begin
  Ctx := EVP_PKEY_CTX_new(AKey, nil);
  SSL_CheckError;
  if Ctx <> nil then
   begin
     r := EVP_PKEY_encrypt_init(Ctx);
     SSL_CheckError;
     r := EVP_PKEY_encrypt(Ctx, Dst, DstLen, Src, SrcLen);
     SSL_CheckError;
     if Ctx <> nil then
      EVP_PKEY_CTX_free(Ctx);
   end else
    raise Exception.Create('Error create cipher context');
end;

procedure Decrypt(Src: PAnsiChar; SrcLen: Cardinal; Dst: PAnsiChar; var DstLen: Cardinal; AKey: PEVP_PKEY);
var Ctx: PEVP_PKEY_CTX;
    r: TC_INT;
begin
  Ctx := EVP_PKEY_CTX_new(AKey, nil);
  SSL_CheckError;
  if Ctx <> nil then
   begin
     r := EVP_PKEY_decrypt_init(Ctx);
     SSL_CheckError;
     r := EVP_PKEY_decrypt(Ctx, Dst, DstLen, Src, SrcLen);
     SSL_CheckError;
     if Ctx <> nil then
      EVP_PKEY_CTX_free(Ctx);
   end else
    raise Exception.Create('Error create cipher context');
end;


procedure EncryptDecryptGOST(AKey: PEVP_PKEY);
var Dst, Src: AnsiString;
    inlen: TC_SIZE_T;
    Buf, outBuf: PAnsiChar;
    outlen, tmplen: TC_SIZE_T;
    DecStr: PAnsiChar;
    EncMsg: array of PAnsiChar;
    I: Integer;
begin
 Src := 'Test string for encrypt and decrypt with GOST algorithm and key';
 Writeln;
 Writeln('ENCRYPT test');
 inlen := Length(Src);
 Encrypt(PAnsiChar(Src), inlen, nil, outlen, AKey);
 inlen := Length(Src);
 Writeln('Need ', outlen, ' bytes for encrypt block of 32 bytes');

 try
  Dst := '';


  repeat
   Buf := OpenSSL_malloc(outlen);
   outBuf := PAnsiChar(Copy(Src, 1, 32));
   Encrypt(outBuf, 32, Buf, outlen, AKey);
   Delete(Src, 1, 32);
   SetLength(EncMsg, Length(EncMsg) + 1);
   EncMsg[Length(EncMsg)-1] := Buf;
  until Src = '';
  Writeln('ENCRYPTED Data: ');
  for i := 0 to Length(EncMsg) - 1 do
    Writeln(EncMsg[I]);


  Decrypt(PAnsiChar(EncMsg[0]), Length(EncMsg[0]), nil, outlen, AKey);
  Src := '';
  Buf := OpenSSL_malloc(outlen);
  Src := '';
  for I := 0 to Length(EncMsg) - 1 do
    begin
      FillChar(Buf^, outlen, 0);
      outBuf := EncMsg[I];

      //
      Decrypt(outBuf, 167, Buf, outlen, AKey);
      // 167 WTF????

      Src := Src + Buf;
    end;
  OpenSSL_free(Buf);
  Writeln('DECRYPTED Data: ', Src);

 finally

 end;

end;


procedure GenerateGOST2001Key;
var
  am: PEVP_PKEY_ASN1_METHOD;
  e: PENGINE;
  Ciph: PEVP_CIPHER;
  pkey_id, pkey_base_id, pkey_flags: TC_INT;
  info, pem_str: PAnsiChar;
  ctx: PEVP_PKEY_CTX;
  key: PEVP_PKEY;
  fname: AnsiString;
  bp: PBIO;
begin
  e := nil;
  am := nil;
  am := EVP_PKEY_asn1_find_str(@e, 'GOST2001', -1);
  try
  if am <> nil then
  begin
       Ciph := EVP_camellia_128_cbc;

       EVP_PKEY_asn1_get0_info(pkey_id, pkey_base_id, pkey_flags, @info, @pem_str, am);
       Writeln('NID = ', pkey_id);
       Writeln(OBJ_nid2ln(pkey_id));
       Writeln('ALGORITHM = ', pem_str, ',', info);
       ctx := EVP_PKEY_CTX_new_id(pkey_id, nil);
       SSL_CheckError;
       EVP_PKEY_keygen_init(ctx);
       SSL_CheckError;
       EVP_PKEY_CTX_ctrl_str(ctx, 'paramset', 'XB');

       EVP_PKEY_CTX_set_cb(ctx, EVP_KEYGENCB);
       EVP_PKEY_CTX_set_app_data(ctx, nil);
       SSL_CheckError;
       key := nil;
       EVP_PKEY_keygen(ctx, @key);
       SSL_CheckError;
       fName := ExtractFilePath(ParamStr(0))+'gost.pem';
       bp := BIO_new_file(PAnsiChar(fName), 'wb');
       try
         PEM_write_bio_PrivateKey(bp, key, Ciph, nil, 0, EVP_PASS_CB, nil);
         SSL_CheckError;
         Writeln('GOST 2001 key SIZE = ', EVP_PKEY_bits(key), ' bit');
         Writeln('Saved to ', fname);
         Writeln('Encrypted with ', OBJ_nid2sn(Ciph.nid), ' (', Ciph.nid, ')');
         EncryptDecryptGOST(key);
       finally
         BIO_free(bp);
       end;
       EVP_PKEY_free(key);
       EVP_PKEY_CTX_free(ctx);
  end;
  finally
    ENGINE_free(E);
  end;
end;




begin
  Writeln('mygost');
  Writeln('DEMO load gost.dll');
  try
    SSL_InitERR;
    SSL_InitENGINE;
    SSL_InitBIO;
    SSL_InitEVP;
    SSL_InitPEM;
    SSL_InitOBJ;
    SSL_InitUtil;
    ENGINE_load_builtin_engines;
    ENGINE_load_dynamic;
     GostLib := ExtractFilePath(ParamStr(0))+'gost.dll';
     if FileExists(GostLib) then
      begin
         E := ENGINE_by_id('dynamic');
         if E = nil then
          raise Exception.Create('Dynamic engine not loaded!');
         SSL_CheckError;
         if ENGINE_cmd_is_executable(e, 200) = 1 then
           ENGINE_ctrl_cmd_string(e, 'SO_PATH', PAnsiChar(GostLib), 0);
         SSL_CheckError;
         ENGINE_ctrl_cmd_string(e, 'LIST_ADD', '2', 0);
         ENGINE_ctrl_cmd_string(e, 'LOAD', nil, 0);
         ENGINE_set_default_string(e, 'ALL');
         ENGINE_ctrl_cmd_string(e, 'CRYPT_PARAMS', 'id-Gost28147-89-CryptoPro-B-ParamSet', 0);
         ENGINE_free(e);

         OpenSSL_add_all_ciphers;
         OpenSSL_add_all_digests;

         GenerateGOST2001Key;
      end else
       raise Exception.Create('Library gost.dll not found!');


  except

    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
