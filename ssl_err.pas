{$I ssl.inc}
unit ssl_err;

interface
uses sysutils, ssl_types;
var

{
    ERR_add_error_data: procedure(_num: TC_INT; ...); cdecl = nil;
    ERR_add_error_vdata: procedure(_num: TC_INT; va_list args); cdecl = nil;
    ERR_load_strings: procedure(_lib: TC_INT; ERR_STRING_DATA str[]); cdecl = nil;
    ERR_unload_strings: procedure(_lib: TC_INT; ERR_STRING_DATA str[]); cdecl = nil;
    LHASH_OF(ERR_STRING_DATA) *ERR_get_string_table(void);
    LHASH_OF(ERR_STATE) *ERR_get_err_state_table(void);
    ERR_release_err_state_table: procedure(LHASH_OF(ERR_STATE) **hash); cdecl = nil;
 }

    ERR_put_error: procedure(_lib: TC_INT;_func: TC_INT; _reason: TC_INT; const _file: PAnsiChar; _line: TC_INT); cdecl = nil;
    ERR_set_error_data: procedure( _data: PAnsiChar;_flags: TC_INT); cdecl = nil;

    ERR_get_error: function: TC_ULONG; cdecl = nil;
    ERR_get_error_line: function(_file: PPAnsiChar;var _line: TC_INT): TC_ULONG; cdecl = nil;
    ERR_get_error_line_data: function(_file: PPAnsiChar;var _line: TC_INT; _data: PPAnsiChar; var _flags: TC_INT): TC_ULONG; cdecl = nil;
    ERR_peek_error: function: TC_ULONG; cdecl = nil;
    ERR_peek_error_line: function(_file: PPAnsiChar;var _line: TC_INT): TC_ULONG; cdecl = nil;
    ERR_peek_error_line_data: function(_file: PPAnsiChar;var _line: TC_INT; _data: PPAnsiChar;var _flags: TC_INT): TC_ULONG; cdecl = nil;
    ERR_peek_last_error: function: TC_ULONG; cdecl = nil;
    ERR_peek_last_error_line: function(_file: PPAnsiChar; var _line: TC_INT): TC_ULONG; cdecl = nil;
    ERR_peek_last_error_line_data: function(_file: PPAnsiChar;var _line: TC_INT; _data: PPAnsiChar; _flags: TC_INT): TC_ULONG; cdecl = nil;
    ERR_clear_error: procedure; cdecl = nil;
    ERR_error_string: function(e: TC_ULONG; _buf: PAnsiChar): PAnsiChar; cdecl = nil;
    ERR_error_string_n: procedure(e: TC_ULONG;  _buf: PAnsiChar; len: TC_SIZE_T); cdecl = nil;
    ERR_lib_error_string: function(e: TC_ULONG): PAnsiChar; cdecl = nil;
    ERR_func_error_string: function(e: TC_ULONG): PAnsiChar; cdecl = nil;
    ERR_reason_error_string: function(e: TC_ULONG): PAnsiChar; cdecl = nil;
    ERR_print_errors_cb: procedure(cb: ERR_CALLBACK; u: Pointer); cdecl = nil;
    ERR_print_errors: procedure(bp: PBIO); cdecl = nil;
    
    ERR_load_ERR_strings: procedure; cdecl = nil;
    ERR_load_crypto_strings: procedure; cdecl = nil;
    ERR_free_strings: procedure; cdecl = nil;

    ERR_remove_thread_state: procedure(const tid: PCRYPTO_THREADID); cdecl = nil;
    ERR_remove_state: procedure(d: TC_ULONG); cdecl = nil;
    ERR_get_state: function: PERR_STATE; cdecl = nil;

    ERR_get_next_error_library: function: TC_INT; cdecl = nil;

    ERR_set_mark: function: TC_INT; cdecl = nil;
    ERR_pop_to_mark: function: TC_INT; cdecl = nil;

    ERR_get_implementation: function: PERR_FNS; cdecl = nil;
    ERR_set_implementation: function(const fns: PERR_FNS): TC_INT; cdecl = nil;

type
  ESSLError = class(Exception)
  public
    ErrorCode: TC_ULONG;
    Msg: String;
    constructor Create(AErrorCode: TC_ULONG; AMsg: String); overload;
    constructor Create(AErrorCode: TC_ULONG); overload;
  end;

procedure SSL_InitERR;    

function SSL_CheckError(AShowException: Boolean = True): TC_ULONG;

implementation
uses ssl_lib;

function SSL_CheckError(AShowException: Boolean = True): TC_ULONG;
begin
  Result := ERR_get_error;
  ERR_clear_error;
  if (Result <> 0)  and (AShowException) then
    raise ESSLError.Create(Result);
end;


procedure SSL_InitERR;
begin
   if @ERR_get_error = nil then
    begin
       @ERR_put_error:= LoadFunctionCLib('ERR_put_error');
       @ERR_set_error_data:= LoadFunctionCLib('ERR_set_error_data');
       @ERR_get_error:= LoadFunctionCLib('ERR_get_error');
       @ERR_get_error_line:= LoadFunctionCLib('ERR_get_error_line');
       @ERR_get_error_line_data:= LoadFunctionCLib('ERR_get_error_line_data');
       @ERR_peek_error:= LoadFunctionCLib('ERR_peek_error');
       @ERR_peek_error_line:= LoadFunctionCLib('ERR_peek_error_line');
       @ERR_peek_error_line_data:= LoadFunctionCLib('ERR_peek_error_line_data');
       @ERR_peek_last_error:= LoadFunctionCLib('ERR_peek_last_error');
       @ERR_peek_last_error_line:= LoadFunctionCLib('ERR_peek_last_error_line');
       @ERR_peek_last_error_line_data:= LoadFunctionCLib('ERR_peek_last_error_line_data');
       @ERR_clear_error:= LoadFunctionCLib('ERR_clear_error');
       @ERR_error_string:= LoadFunctionCLib('ERR_error_string');
       @ERR_error_string_n:= LoadFunctionCLib('ERR_error_string_n');
       @ERR_lib_error_string:= LoadFunctionCLib('ERR_lib_error_string');
       @ERR_func_error_string:= LoadFunctionCLib('ERR_func_error_string');
       @ERR_reason_error_string:= LoadFunctionCLib('ERR_reason_error_string');
       @ERR_print_errors_cb:= LoadFunctionCLib('ERR_print_errors_cb');
       @ERR_print_errors:= LoadFunctionCLib('ERR_print_errors');
       @ERR_load_ERR_strings:= LoadFunctionCLib('ERR_load_ERR_strings');
       @ERR_load_crypto_strings:= LoadFunctionCLib('ERR_load_crypto_strings');
       @ERR_free_strings:= LoadFunctionCLib('ERR_free_strings');
       @ERR_remove_thread_state:= LoadFunctionCLib('ERR_remove_thread_state', false);
       @ERR_remove_state:= LoadFunctionCLib('ERR_remove_state');
       @ERR_get_state:= LoadFunctionCLib('ERR_get_state');
       @ERR_get_next_error_library:= LoadFunctionCLib('ERR_get_next_error_library');
       @ERR_set_mark:= LoadFunctionCLib('ERR_set_mark');
       @ERR_pop_to_mark:= LoadFunctionCLib('ERR_pop_to_mark');
       @ERR_get_implementation:= LoadFunctionCLib('ERR_get_implementation');
       @ERR_set_implementation:= LoadFunctionCLib('ERR_set_implementation');
       ERR_load_crypto_strings;
    end;
end;


{ ESSLError }

constructor ESSLError.Create(AErrorCode: TC_ULONG; AMsg: String);
begin
 ErrorCode := AErrorCode;
 Msg := AMsg;
 inherited Create(Msg);
end;

constructor ESSLError.Create(AErrorCode: TC_ULONG);
var sMsg: String;
begin
 sMsg := string(ERR_error_string(AErrorCode, nil));
 Create(AErrorCode, sMsg);
end;

end.