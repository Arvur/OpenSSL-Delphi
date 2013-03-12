unit ssl_md4;

interface
uses ssl_types;

var
	MD4_Init: function(_c: PMD4_CTX): TC_INT; cdecl = nil;
	MD4_Update: function(_c: PMD4_CTX; const _data: Pointer; _len: TC_SIZE_T): TC_INT; cdecl = nil;
	MD4_Final: function(_md: PAnsiChar; _c: PMD4_CTX): TC_INT; cdecl = nil;
	MD4: function(const _d: PAnsiChar; _n: TC_SIZE_T; _md: PAnsiChar): PAnsiChar; cdecl = nil;
	MD4_Transform: procedure(_c: PMD4_CTX; const _b: PAnsiChar); cdecl = nil;

procedure SSL_InitMD4;

implementation
uses ssl_lib;

procedure SSL_InitMD4;
begin
	if @MD4_Init = nil then
		begin
			@MD4_Init:= LoadFunctionCLib('MD4_Init');
			@MD4_Update:= LoadFunctionCLib('MD4_Update');
			@MD4_Final:= LoadFunctionCLib('MD4_Final');
			@MD4:= LoadFunctionCLib('MD4');
			@MD4_Transform:= LoadFunctionCLib('MD4_Transform');
		end;
end;

end.
