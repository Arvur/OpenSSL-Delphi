program myprime;

{$APPTYPE CONSOLE}

{$R *.res}


uses
  System.SysUtils,
  ssl_types,
  ssl_bio,
  ssl_bn;

procedure callback(_type, _num: TC_INT; p3: Pointer ); cdecl;
begin
 case _type of
 0: Write('.');
 1: Write('+', #13);
 2: Write('*', #13);
 end;
end;

var r: PBIGNUM;
    bp: PBIO;
    a: TC_INT;
    buf: AnsiString;
    Res: AnsiString;
    num: TC_INT;
begin
  try

    if ParamCount > 0 then
       Num := StrToIntDef(ParamStr(1), 256);
    writeln('Generate a strong prime ', Num, ' bits');
    SSL_InitBN;
    SSL_InitBIO;
    r := BN_generate_prime(nil, Num, 1, nil, nil, callback, nil);
    Buf := BN_bn2hex(r);
    Writeln('BN_bn2hex: ', buf);

    bp := BIO_new(BIO_s_mem);
    BN_print(bp, r);
     Writeln('BN_print: ',BIO_ReadAnsiString(bp));
    BN_free(r);
    { TODO -oUser -cConsole Main : Insert code here }
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
