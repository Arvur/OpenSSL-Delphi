unit ssl_rand;
interface
uses ssl_types;
var 
    RAND_set_rand_method: function(const meth: PRAND_METHOD): TC_INT; cdecl = nil;
    RAND_get_rand_method: function: PRAND_METHOD; cdecl = nil;
    RAND_set_rand_engine: function(engine: PENGINE): TC_INT; cdecl = nil;
    RAND_SSLeay: function: PRAND_METHOD; cdecl = nil;
    RAND_cleanup: procedure; cdecl = nil;
    RAND_bytes: function(buf: PAnsiChar; num: TC_INT): TC_INT; cdecl = nil;
    RAND_pseudo_bytes: function(buf: PAnsiChar; num: TC_INT): TC_INT; cdecl = nil;
    RAND_seed: procedure(buf: Pointer; num: TC_INT); cdecl = nil;
    RAND_add: procedure(buf: Pointer; num: TC_INT; entropy: double); cdecl = nil;
    RAND_load_file: function(_file: PAnsiChar; max_bytes: TC_LONG): TC_INT; cdecl = nil;
    RAND_write_file: function(_file: PAnsiChar): TC_INT; cdecl = nil;
    RAND_file_name: function(_file: PAnsiChar; num: TC_size_t ): PAnsiChar; cdecl = nil;
    RAND_status: function: TC_INT; cdecl = nil;
    RAND_query_egd_bytes: function(path: PAnsiChar; buf: PAnsiChar; bytes: TC_INT): TC_INT; cdecl = nil;
    RAND_egd: function(path: PAnsiChar): TC_INT; cdecl = nil;
    RAND_egd_bytes: function(path: PAnsiChar; bytes: TC_INT): TC_INT; cdecl = nil;
    RAND_poll: function: TC_INT; cdecl = nil;

    RAND_screen: procedure; cdecl;
//int RAND_event(UINT, WPARAM, LPARAM);

    RAND_set_fips_drbg_type: procedure(_type: TC_INT; flags: TC_INT); cdecl = nil;
    RAND_init_fips: function: TC_INT; cdecl = nil;
    ERR_load_RAND_strings: procedure; cdecl = nil;

procedure SSL_InitRAND; 
    
implementation
uses ssl_lib;

procedure SSL_InitRAND;
begin
  if @RAND_set_rand_method = nil then
   begin 
    @RAND_set_rand_method:= LoadFunctionCLib('RAND_set_rand_method');
    @RAND_get_rand_method:= LoadFunctionCLib('RAND_get_rand_method');
    @RAND_set_rand_engine:= LoadFunctionCLib('RAND_set_rand_engine');
    @RAND_SSLeay:= LoadFunctionCLib('RAND_SSLeay');
    @RAND_cleanup:= LoadFunctionCLib('RAND_cleanup');
    @RAND_bytes:= LoadFunctionCLib('RAND_bytes');
    @RAND_pseudo_bytes:= LoadFunctionCLib('RAND_pseudo_bytes');
    @RAND_seed:= LoadFunctionCLib('RAND_seed');
    @RAND_add:= LoadFunctionCLib('RAND_add');
    @RAND_load_file:= LoadFunctionCLib('RAND_load_file');
    @RAND_write_file:= LoadFunctionCLib('RAND_write_file');
    @RAND_file_name:= LoadFunctionCLib('RAND_file_name');
    @RAND_status:= LoadFunctionCLib('RAND_status');
    @RAND_query_egd_bytes:= LoadFunctionCLib('RAND_query_egd_bytes');
    @RAND_egd:= LoadFunctionCLib('RAND_egd');
    @RAND_egd_bytes:= LoadFunctionCLib('RAND_egd_bytes');
    @RAND_poll:= LoadFunctionCLib('RAND_poll');
    @RAND_screen:= LoadFunctionCLib('RAND_screen');
    @RAND_set_fips_drbg_type:= LoadFunctionCLib('RAND_set_fips_drbg_type', false);
    @RAND_init_fips:= LoadFunctionCLib('RAND_init_fips', false);
    @ERR_load_RAND_strings:= LoadFunctionCLib('ERR_load_RAND_strings');
   end;   
end;

end.
