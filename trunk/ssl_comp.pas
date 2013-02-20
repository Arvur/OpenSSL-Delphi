unit ssl_comp;
interface
uses ssl_types;
var
    COMP_CTX_new: function(meth: PCOMP_METHOD): PCOMP_CTX; cdecl = nil;
    COMP_CTX_free: procedure(ctx: PCOMP_CTX); cdecl = nil;
    COMP_compress_block: function(ctx: PCOMP_CTX; _out: PAnsiChar; olen: TC_INT;_in: PAnsiChar; ilen: TC_INT): TC_INT; cdecl = nil;
    COMP_expand_block:function(ctx: PCOMP_CTX; _out: PAnsiChar; olen: TC_INT;_in: PAnsiChar; ilen: TC_INT): TC_INT; cdecl = nil;
    COMP_rle: function: PCOMP_METHOD; cdecl = nil;
    COMP_zlib: function: PCOMP_METHOD; cdecl = nil;
    COMP_zlib_cleanup: procedure; cdecl = nil;
    BIO_f_zlib: function: PBIO_METHOD; cdecl = nil;

procedure SSL_InitCOMP;
    
implementation
uses ssl_lib;

procedure SSL_InitCOMP;
begin
  if @COMP_CTX_new = nil then
  begin
    @COMP_CTX_new:= LoadFunctionCLib('COMP_CTX_new');
    @COMP_CTX_free:= LoadFunctionCLib('COMP_CTX_free');
    @COMP_compress_block:= LoadFunctionCLib('COMP_compress_block');
    @COMP_expand_block:= LoadFunctionCLib('COMP_expand_block');
    @COMP_rle:= LoadFunctionCLib('COMP_rle');
    @COMP_zlib:= LoadFunctionCLib('COMP_zlib');
    @COMP_zlib_cleanup:= LoadFunctionCLib('COMP_zlib_cleanup');
    @BIO_f_zlib:= LoadFunctionCLib('BIO_f_zlib', false);
  end;
end;

end.