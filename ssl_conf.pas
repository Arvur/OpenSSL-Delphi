unit ssl_conf;
{$ifdef fpc}
 {$mode delphi}
{$endif}

interface
uses ssl_types;
const
    CONF_MFLAGS_IGNORE_ERRORS	     = $1;
    CONF_MFLAGS_IGNORE_RETURN_CODES	 = $2;
    CONF_MFLAGS_SILENT		         = $4;
    CONF_MFLAGS_NO_DSO		         = $8;
    CONF_MFLAGS_IGNORE_MISSING_FILE	 = $10;
    CONF_MFLAGS_DEFAULT_SECTION	     = $20;

    CONF_F_CONF_DUMP_FP				     = 104;
    CONF_F_CONF_LOAD				     = 100;
    CONF_F_CONF_LOAD_BIO				 = 102;
    CONF_F_CONF_LOAD_FP				     = 103;
    CONF_F_CONF_MODULES_LOAD			 = 116;
    CONF_F_CONF_PARSE_LIST				 = 119;
    CONF_F_DEF_LOAD					     = 120;
    CONF_F_DEF_LOAD_BIO				     = 121;
    CONF_F_MODULE_INIT				     = 115;
    CONF_F_MODULE_LOAD_DSO				 = 117;
    CONF_F_MODULE_RUN				     = 118;
    CONF_F_NCONF_DUMP_BIO				 = 105;
    CONF_F_NCONF_DUMP_FP				 = 106;
    CONF_F_NCONF_GET_NUMBER				 = 107;
    CONF_F_NCONF_GET_NUMBER_E			 = 112;
    CONF_F_NCONF_GET_SECTION			 = 108;
    CONF_F_NCONF_GET_STRING				 = 109;
    CONF_F_NCONF_LOAD				     = 113;
    CONF_F_NCONF_LOAD_BIO				 = 110;
    CONF_F_NCONF_LOAD_FP				 = 114;
    CONF_F_NCONF_NEW				     = 111;
    CONF_F_STR_COPY					     = 101;

    CONF_R_ERROR_LOADING_DSO			         = 110;
    CONF_R_LIST_CANNOT_BE_NULL			         = 115;
    CONF_R_MISSING_CLOSE_SQUARE_BRACKET		     = 100;
    CONF_R_MISSING_EQUAL_SIGN			         = 101;
    CONF_R_MISSING_FINISH_FUNCTION			     = 111;
    CONF_R_MISSING_INIT_FUNCTION			     = 112;
    CONF_R_MODULE_INITIALIZATION_ERROR		     = 109;
    CONF_R_NO_CLOSE_BRACE				         = 102;
    CONF_R_NO_CONF					             = 105;
    CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE		 = 106;
    CONF_R_NO_SECTION				             = 107;
    CONF_R_NO_SUCH_FILE				             = 114;
    CONF_R_NO_VALUE					             = 108;
    CONF_R_UNABLE_TO_CREATE_NEW_SECTION		     = 103;
    CONF_R_UNKNOWN_MODULE_NAME			         = 113;
    CONF_R_VARIABLE_HAS_NO_VALUE			     = 104;


var
    CONF_set_default_method: function(meth: PCONF_METHOD): TC_INT; cdecl;
    CONF_set_nconf: procedure(_conf: PCONF; hash: PLHASH); cdecl;
    CONF_load: function(_conf: PLHASH; const _file: PAnsiChar; eline: PC_LONG): PLHASH; cdecl;
    CONF_load_bio: function(_conf: PLHASH; bp: PBIO; eline: PC_LONG): PLHASH; cdecl;
    CONF_get_section: function(_conf: PLHASH; const section: PAnsiChar): PSTACK_OF; cdecl;
    CONF_get_string: function(_conf: PLHASH; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
    CONF_get_number: function(_conf: PLHASH;const group: PAnsiChar; const name: PAnsiChar): TC_LONG; cdecl;
    
    CONF_free: procedure(_conf: PLHASH_OF); cdecl;   
    CONF_dump_bio: function(_conf: PLHASH; _out: PBIO): TC_INT; cdecl;

    OPENSSL_config: procedure(const config_name: PAnsiChar); cdecl;
    OPENSSL_no_config: procedure; cdecl;

    NCONF_new: function(meth: PCONF_METHOD): PCONF; cdecl;
    NCONF_default: function: PCONF_METHOD; cdecl;
    NCONF_WIN32: function: PCONF_METHOD; cdecl;
    NCONF_free: procedure(_conf: PCONF); cdecl;
    NCONF_free_data: procedure(_conf: PCONF); cdecl;

    NCONF_load: function(_conf: PCONF; const _file: PAnsiChar; eline: PC_LONG): TC_INT; cdecl;
    NCONF_load_bio: function(_conf: PCONF; bp: PBIO; eline: PC_LONG): TC_INT; cdecl;
    NCONF_get_section: function (const _conf: PCONF; const section: PAnsiChar): PSTACK_OF; cdecl;
    NCONF_get_string: function(const _conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
    NCONF_get_number_e: function(const _conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; _result: PC_LONG): TC_INT; cdecl;
		       
    NCONF_dump_bio: function(const _conf: PCONF; _out: PBIO): TC_INT; cdecl;
  

    CONF_modules_load: function(const cnf: PCONF; const  _appname: PAnsiChar; s: TC_ULONG): TC_INT; cdecl;
    CONF_modules_load_file: function(const  _filename: PAnsiChar; const  _appname: PAnsiChar;  s: TC_ULONG): TC_INT; cdecl = nil;
    CONF_modules_unload: procedure(_all: TC_INT); cdecl = nil;
    CONF_modules_finish: procedure; cdecl = nil;
    CONF_modules_free: procedure; cdecl = nil;
    CONF_module_add: function(const  _name: PAnsiChar; ifunc: t_conf_init_func; ffunc: t_conf_finish_func): TC_INT; cdecl = nil;

    CONF_imodule_get_name: function(const md: PCONF_IMODULE): PAnsiChar; cdecl = nil;
    CONF_imodule_get_value: function(const md: PCONF_IMODULE): PAnsiChar; cdecl = nil;
    CONF_imodule_get_usr_data: function(const md: PCONF_IMODULE): Pointer; cdecl = nil;
    CONF_imodule_set_usr_data: procedure(md: PCONF_IMODULE; usr_data: Pointer); cdecl = nil;
    CONF_imodule_get_module: function(const md: PCONF_IMODULE): PCONF_MODULE; cdecl = nil;
    CONF_imodule_get_flags: function(const md: PCONF_IMODULE): TC_ULONG; cdecl = nil;
    CONF_imodule_set_flags: procedure(md: PCONF_IMODULE; s: TC_ULONG); cdecl = nil;
    CONF_module_get_usr_data: function(pmod: PCONF_MODULE): Pointer; cdecl = nil;
    CONF_module_set_usr_data: procedure(pmod: PCONF_MODULE; usr_data: Pointer); cdecl = nil;

    CONF_get1_default_config_file: function: PAnsiChar; cdecl = nil;

    CONF_parse_list: function(const list: PAnsiChar; sep: TC_INT; nospc: TC_INT; list_cb: t_list_cb; arg: Pointer): TC_INT; cdecl = nil;

    OPENSSL_load_builtin_modules: procedure; cdecl = nil;

    ERR_load_CONF_strings: procedure; cdecl = nil;

procedure SSL_InitCONF;
    
implementation

uses ssl_lib;

procedure SSL_InitCONF;
begin
  if @NCONF_new = nil then
   begin
    @CONF_set_default_method:= LoadFunctionCLib('CONF_set_default_method');
    @CONF_set_nconf:= LoadFunctionCLib('CONF_set_nconf');
    @CONF_load:= LoadFunctionCLib('CONF_load');
    @CONF_load_bio:= LoadFunctionCLib('CONF_load_bio');
    @CONF_get_section:= LoadFunctionCLib('CONF_get_section');
    @CONF_get_string:= LoadFunctionCLib('CONF_get_string');
    @CONF_get_number:= LoadFunctionCLib('CONF_get_number');
    
    @CONF_free:= LoadFunctionCLib('CONF_free');
    @CONF_dump_bio:= LoadFunctionCLib('CONF_dump_bio');

    @OPENSSL_config:= LoadFunctionCLib('OPENSSL_config');
    @OPENSSL_no_config:= LoadFunctionCLib('OPENSSL_no_config');

    @NCONF_new:= LoadFunctionCLib('NCONF_new');
    @NCONF_default:= LoadFunctionCLib('NCONF_default');
    @NCONF_WIN32:= LoadFunctionCLib('NCONF_WIN32');
    @NCONF_free:= LoadFunctionCLib('NCONF_free');
    @NCONF_free_data:= LoadFunctionCLib('NCONF_free_data');

    @NCONF_load:= LoadFunctionCLib('NCONF_load');
    @NCONF_load_bio:= LoadFunctionCLib('NCONF_load_bio');
    @NCONF_get_section:= LoadFunctionCLib('NCONF_get_section');
    @NCONF_get_string:= LoadFunctionCLib('NCONF_get_string');
    @NCONF_get_number_e:= LoadFunctionCLib('NCONF_get_number_e');
		       
    @NCONF_dump_bio:= LoadFunctionCLib('NCONF_dump_bio');
  

    @CONF_modules_load:= LoadFunctionCLib('CONF_modules_load');
    @CONF_modules_load_file:= LoadFunctionCLib('CONF_modules_load_file');
    @CONF_modules_unload:= LoadFunctionCLib('CONF_modules_unload');
    @CONF_modules_finish:= LoadFunctionCLib('CONF_modules_finish');
    @CONF_modules_free:= LoadFunctionCLib('CONF_modules_free');
    @CONF_module_add:= LoadFunctionCLib('CONF_module_add');

    @CONF_imodule_get_name:= LoadFunctionCLib('CONF_imodule_get_name');
    @CONF_imodule_get_value:= LoadFunctionCLib('CONF_imodule_get_value');
    @CONF_imodule_get_usr_data:= LoadFunctionCLib('CONF_imodule_get_usr_data');
    @CONF_imodule_set_usr_data:= LoadFunctionCLib('CONF_imodule_set_usr_data');
    @CONF_imodule_get_module:= LoadFunctionCLib('CONF_imodule_get_module');
    @CONF_imodule_get_flags:= LoadFunctionCLib('CONF_imodule_get_flags');
    @CONF_imodule_set_flags:= LoadFunctionCLib('CONF_imodule_set_flags');
    @CONF_module_get_usr_data:= LoadFunctionCLib('CONF_module_get_usr_data');
    @CONF_module_set_usr_data:= LoadFunctionCLib('CONF_module_set_usr_data');

    @CONF_get1_default_config_file:= LoadFunctionCLib('CONF_get1_default_config_file');

    @CONF_parse_list := LoadFunctionCLib('CONF_parse_list');

    @OPENSSL_load_builtin_modules:= LoadFunctionCLib('OPENSSL_load_builtin_modules');

    @ERR_load_CONF_strings:= LoadFunctionCLib('ERR_load_CONF_strings');
   end;
end;
end.