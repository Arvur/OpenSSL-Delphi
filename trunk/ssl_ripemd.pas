unit ssl_ripemd;

interface
uses ssl_types;

var
	RIPEMD160_Init: function(_c: PRIPEMD160_CTX): TC_INT; cdecl = nil;
	RIPEMD160_Update: function(_c: PRIPEMD160_CTX; const _data: Pointer; _len: TC_SIZE_T): TC_INT; cdecl = nil;
	RIPEMD160_Final: function(_md: PAnsiChar; _c: PRIPEMD160_CTX): TC_INT; cdecl = nil;
	RIPEMD160: function(const _d: PAnsiChar; _n: TC_SIZE_T; _md: PAnsiChar): PAnsiChar; cdecl = nil;
	RIPEMD160_Transform: procedure(_c: PRIPEMD160_CTX; const _b: PAnsiChar); cdecl = nil;

procedure SSL_Initripemd;

implementation
uses ssl_lib;

procedure SSL_Initripemd;
begin
	if @RIPEMD160_Init = nil then
		begin
			@RIPEMD160_Init:= LoadFunctionCLib('RIPEMD160_Init');
			@RIPEMD160_Update:= LoadFunctionCLib('RIPEMD160_Update');
			@RIPEMD160_Final:= LoadFunctionCLib('RIPEMD160_Final');
			@RIPEMD160:= LoadFunctionCLib('RIPEMD160');
			@RIPEMD160_Transform:= LoadFunctionCLib('RIPEMD160_Transform');
		end;
end;

end.

