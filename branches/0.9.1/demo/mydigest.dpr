program mydigest;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Classes,
  ssl_md5,
  ssl_mdc2,
  ssl_sha,
  ssl_types,
  ssl_err,
  ssl_const,
  ssl_util;

var F: TFileStream;
    Buf: PAnsiChar;
    Dgst: PAnsiChar;
    Len: Integer;
    FName: String;
    _md5: MD5_CTX;
    _mdc2: MDC2_CTX;
    _sha: SHA_CTX;
    _sha256: SHA256_CTX;
    _sha512: SHA512_CTX;

const
  BufSize = 2048;

procedure WriteDigest(ADgst: PAnsiChar; ALen: Word);
var i: Word;
begin
  for i := 0 to ALen - 1 do
    Write(IntToHex(Ord(ADgst[I]), 2));
  Writeln;
end;

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    Writeln('DEMO mydigest');
    if ParamCount = 0 then
     begin
       Writeln('Usage: mydigest.exe filename');
       Halt(1);
     end;
    SSL_InitERR;
    SSL_InitMDC2;
    SSL_InitMD5;
    SSL_Initsha;
    SSL_InitUtil;
    Fname := ParamStr(1);
    Writeln(FName, ' readed');
    F := TFileStream.Create(FName, fmOpenRead);
    try
      Buf := OpenSSL_malloc(BufSize);
      try
       if MD5_Init(@_md5) = 1 then
       begin
         Dgst := OpenSSL_malloc(MD5_DIGEST_LENGTH);
         try
           while F.Position < F.Size do
           begin
             Len := F.Read(Buf^, BufSize);
             MD5_Update(@_md5, Buf, Len);
             Write('Read:', F.Position:10, ' bytes', #13);
           end;
           MD5_Final(Dgst, @_md5);
           Writeln;
           Write('MD5 Digest: ');
           WriteDigest(Dgst, MD5_DIGEST_LENGTH);
         finally
           OpenSSL_free(Dgst);
         end;
         Writeln;
       end;
       F.Position := 0;
       if MDC2_Init(@_mdc2) = 1 then
        begin
          Dgst := OpenSSL_malloc(MDC2_DIGEST_LENGTH);
         try
           while F.Position < F.Size do
           begin
             Len := F.Read(Buf^, BufSize);
             MDC2_Update(@_mdc2, Buf, Len);
             Write('Read:', F.Position:10, ' bytes', #13);
           end;
           MDC2_Final(Dgst, @_mdc2);
           Writeln;
           Write('MDC2 Digest: ');
           WriteDigest(Dgst, MDC2_DIGEST_LENGTH);
         finally
           OpenSSL_free(Dgst);
         end;
         Writeln;

        end;

       F.Position := 0;
       if SHA_Init(@_sha) = 1 then
        begin
          Dgst := OpenSSL_malloc(SHA_DIGEST_LENGTH);
         try
           while F.Position < F.Size do
           begin
             Len := F.Read(Buf^, BufSize);
             SHA_Update(@_SHA, Buf, Len);
             Write('Read:', F.Position:10, ' bytes', #13);
           end;
           SHA_Final(Dgst, @_sha);
           Writeln;
           Write('SHA Digest: ');
           WriteDigest(Dgst, SHA_DIGEST_LENGTH);
         finally
           OpenSSL_free(Dgst);
         end;
         Writeln;

        end;


       F.Position := 0;
       if SHA256_Init(@_sha256) = 1 then
        begin
          Dgst := OpenSSL_malloc(SHA256_DIGEST_LENGTH);
         try
           while F.Position < F.Size do
           begin
             Len := F.Read(Buf^, BufSize);
             SHA256_Update(@_SHA256, Buf, Len);
             Write('Read:', F.Position:10, ' bytes', #13);
           end;
           SHA256_Final(Dgst, @_sha256);
           Writeln;
           Write('SHA256 Digest: ');
           WriteDigest(Dgst, SHA256_DIGEST_LENGTH);
         finally
           OpenSSL_free(Dgst);
         end;
         Writeln;

        end;

       F.Position := 0;
       if SHA512_Init(@_sha512) = 1 then
        begin
          Dgst := OpenSSL_malloc(SHA512_DIGEST_LENGTH);
         try
           while F.Position < F.Size do
           begin
             Len := F.Read(Buf^, BufSize);
             SHA512_Update(@_SHA512, Buf, Len);
             Write('Read:', F.Position:10, ' bytes', #13);
           end;
           SHA512_Final(Dgst, @_sha512);
           Writeln;
           Write('SHA512 Digest: ');
           WriteDigest(Dgst, SHA512_DIGEST_LENGTH);
         finally
           OpenSSL_free(Dgst);
         end;
         Writeln;

        end;


      finally
        OpenSSL_free(Buf);
      end;
    finally
      F.Free;
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
