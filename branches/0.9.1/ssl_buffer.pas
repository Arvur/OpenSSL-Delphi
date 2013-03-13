{}
unit ssl_buffer;

interface
uses ssl_types;
var
  BUF_MEM_new: function: PBUF_MEM; cdecl = nil;
  BUF_MEM_free: procedure(a: PBUF_MEM); cdecl = nil;
  BUF_MEM_grow: function(str: PBUF_MEM; len: TC_SIZE_T): TC_INT; cdecl = nil;
  BUF_MEM_grow_clean: function(str: PBUF_MEM; len: TC_SIZE_T): TC_INT; cdecl = nil;
  BUF_strdup: function(str: PAnsiChar): PAnsiChar; cdecl = nil;
  BUF_strndup: function(str: PAnsiChar; siz: TC_SIZE_T): PAnsiChar; cdecl = nil;
  BUF_memdup: function(data: Pointer; siz: TC_SIZE_T): Pointer; cdecl = nil;
  BUF_reverse: procedure(_out: PAnsiChar; _in: PAnsiChar; siz: TC_SIZE_T); cdecl = nil;

  BUF_strlcpy: function(dst: PAnsiChar; src: PAnsiChar; siz: TC_SIZE_T): TC_SIZE_T; cdecl = nil;
  BUF_strlcat: function(dst: PAnsiChar; src: PAnsiChar; siz: TC_SIZE_T): TC_SIZE_T; cdecl = nil;

  ERR_load_BUF_strings: Procedure; cdecl = nil;

procedure SSL_InitBuffer;

implementation
uses ssl_lib;

procedure SSL_InitBuffer;
begin
  if @BUF_MEM_new = nil then
   begin
      @BUF_MEM_new:= LoadFunctionCLib('BUF_MEM_new');
      @BUF_MEM_free:= LoadFunctionCLib('BUF_MEM_free');
      @BUF_MEM_grow:= LoadFunctionCLib('BUF_MEM_grow');
      @BUF_MEM_grow_clean:= LoadFunctionCLib('BUF_MEM_grow_clean');
      @BUF_strdup:= LoadFunctionCLib('BUF_strdup');
      @BUF_strndup:= LoadFunctionCLib('BUF_strndup');
      @BUF_memdup:= LoadFunctionCLib('BUF_memdup');
      @BUF_reverse:= LoadFunctionCLib('BUF_reverse');
      @BUF_strlcpy:= LoadFunctionCLib('BUF_strlcpy');
      @BUF_strlcat:= LoadFunctionCLib('BUF_strlcat');
      @ERR_load_BUF_strings:= LoadFunctionCLib('ERR_load_BUF_strings');

   end;
end;

end.
