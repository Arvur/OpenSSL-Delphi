unit ssl_sha;

interface
uses ssl_types;

var
	SHA_Init: function(_c: PSHA_CTX): TC_INT; cdecl = nil;
	SHA_Update: function(_c: PSHA_CTX; const _data: Pointer; _len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA_Final: function(md: PAnsiChar; c: PSHA_CTX): TC_INT; cdecl = nil;
	SHA: function(const _d: PAnsiChar; n: TC_SIZE_T; md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA_Transform: procedure(c: PSHA_CTX; const data: PAnsiChar); cdecl = nil;
	SHA1_Init: function(c: PSHA_CTX): TC_INT; cdecl = nil;
	SHA1_Update: function(c: PSHA_CTX; const data: Pointer; len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA1_Final: function(md: PAnsiChar; c: PSHA_CTX): TC_INT; cdecl = nil;
	SHA1: function(const d: PAnsiChar; n: TC_SIZE_T; md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA1_Transform: procedure(c: PSHA_CTX; const data: PAnsiChar); cdecl = nil;
	SHA224_Init: function(c: PSHA256_CTX): TC_INT; cdecl = nil;
	SHA224_Update: function(c: PSHA256_CTX; const data: Pointer; len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA224_Final: function(md: PAnsiChar; c: PSHA256_CTX): TC_INT; cdecl = nil;
	SHA224: function(const d: PAnsiChar; n: TC_SIZE_T;md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA256_Init: function(c: PSHA256_CTX): TC_INT; cdecl = nil;
	SHA256_Update: function(c: PSHA256_CTX; const data: Pointer; len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA256_Final: function(md: PAnsiChar; c: PSHA256_CTX): TC_INT; cdecl = nil;
	SHA256: function(const d: PAnsiChar; n: TC_SIZE_T;md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA256_Transform: procedure(c: PSHA256_CTX; const data: PAnsiChar); cdecl = nil;
	SHA384_Init: function(c: PSHA512_CTX): TC_INT; cdecl = nil;
	SHA384_Update: function(c: PSHA512_CTX; const data: Pointer; len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA384_Final: function(md: PAnsiChar; c: PSHA512_CTX): TC_INT; cdecl = nil;
	SHA384: function(const d: PAnsiChar; n: TC_SIZE_T;md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA512_Init: function(c: PSHA512_CTX): TC_INT; cdecl = nil;
	SHA512_Update: function(c: PSHA512_CTX; const data: Pointer; len: TC_SIZE_T): TC_INT; cdecl = nil;
	SHA512_Final: function(md: PAnsiChar; c: PSHA512_CTX): TC_INT; cdecl = nil;
	SHA512: function(const d: PAnsiChar; n: TC_SIZE_T;md: PAnsiChar): PAnsiChar; cdecl = nil;
	SHA512_Transform: procedure(c: PSHA512_CTX; const data: PAnsiChar); cdecl = nil;


procedure SSL_Initsha;

implementation
uses ssl_lib;

procedure SSL_Initsha;
begin
	if @SHA_Init = nil then
		begin
			@SHA_Init:= LoadFunctionCLib('SHA_Init');
			@SHA_Update:= LoadFunctionCLib('SHA_Update');
			@SHA_Final:= LoadFunctionCLib('SHA_Final');
			@SHA:= LoadFunctionCLib('SHA');
			@SHA_Transform:= LoadFunctionCLib('SHA_Transform');
			@SHA1_Init:= LoadFunctionCLib('SHA1_Init');
			@SHA1_Update:= LoadFunctionCLib('SHA1_Update');
			@SHA1_Final:= LoadFunctionCLib('SHA1_Final');
			@SHA1:= LoadFunctionCLib('SHA1');
			@SHA1_Transform:= LoadFunctionCLib('SHA1_Transform');
			@SHA224_Init:= LoadFunctionCLib('SHA224_Init');
			@SHA224_Update:= LoadFunctionCLib('SHA224_Update');
			@SHA224_Final:= LoadFunctionCLib('SHA224_Final');
			@SHA224:= LoadFunctionCLib('SHA224');
			@SHA256_Init:= LoadFunctionCLib('SHA256_Init');
			@SHA256_Update:= LoadFunctionCLib('SHA256_Update');
			@SHA256_Final:= LoadFunctionCLib('SHA256_Final');
			@SHA256:= LoadFunctionCLib('SHA256');
			@SHA256_Transform:= LoadFunctionCLib('SHA256_Transform');
			@SHA384_Init:= LoadFunctionCLib('SHA384_Init');
			@SHA384_Update:= LoadFunctionCLib('SHA384_Update');
			@SHA384_Final:= LoadFunctionCLib('SHA384_Final');
			@SHA384:= LoadFunctionCLib('SHA384');
			@SHA512_Init:= LoadFunctionCLib('SHA512_Init');
			@SHA512_Update:= LoadFunctionCLib('SHA512_Update');
			@SHA512_Final:= LoadFunctionCLib('SHA512_Final');
			@SHA512:= LoadFunctionCLib('SHA512');
			@SHA512_Transform:= LoadFunctionCLib('SHA512_Transform');
		end;
	
end;

end.

