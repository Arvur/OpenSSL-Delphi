unit ssl_idea;

interface
uses ssl_types;

var
	idea_options: function: PAnsiChar; cdecl = nil;
	idea_ecb_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
	private_idea_set_encrypt_key: procedure(const _key: PAnsiChar; _ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
	idea_set_encrypt_key: procedure(const _key: PAnsiChar; _ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
	idea_set_decrypt_key: procedure(_ek: PIDEA_KEY_SCHEDULE; _dk: PIDEA_KEY_SCHEDULE); cdecl = nil;
	idea_cbc_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _ks: PIDEA_KEY_SCHEDULE; _iv: PAnsiChar; _enc: TC_INT); cdecl = nil;
	idea_cfb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _ks: PIDEA_KEY_SCHEDULE; _iv: PAnsiChar; var _num: TC_INT; _enc: TC_INT); cdecl = nil;
	idea_ofb64_encrypt: procedure(const _in: PAnsiChar; _out: PAnsiChar; _length: TC_LONG; _ks: PIDEA_KEY_SCHEDULE; _iv: PAnsiChar; var _num: TC_INT); cdecl = nil;
	idea_encrypt: procedure(var _in: TC_LONG; _ks: PIDEA_KEY_SCHEDULE); cdecl = nil;

procedure SSL_InitIDEA;

implementation
uses ssl_lib;

procedure SSL_InitIDEA;
begin
	if @idea_options = nil then
		begin
			@idea_options:= LoadFunctionCLib('idea_options');
			@idea_ecb_encrypt:= LoadFunctionCLib('idea_ecb_encrypt');
			@private_idea_set_encrypt_key:= LoadFunctionCLib('private_idea_set_encrypt_key', false);
			@idea_set_encrypt_key:= LoadFunctionCLib('idea_set_encrypt_key');
			@idea_set_decrypt_key:= LoadFunctionCLib('idea_set_decrypt_key');
			@idea_cbc_encrypt:= LoadFunctionCLib('idea_cbc_encrypt');
			@idea_cfb64_encrypt:= LoadFunctionCLib('idea_cfb64_encrypt');
			@idea_ofb64_encrypt:= LoadFunctionCLib('idea_ofb64_encrypt');
			@idea_encrypt:= LoadFunctionCLib('idea_encrypt');
		end;
end;

end.
