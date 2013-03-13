unit ssl_mdc2;

interface
uses ssl_types;

var
	MDC2_Init: function(_c: PMDC2_CTX): TC_INT; cdecl = nil;
	MDC2_Update: function(_c: PMDC2_CTX; const _data: PAnsiChar; _len: TC_SIZE_T): TC_INT; cdecl = nil;
	MDC2_Final: function(_md: PAnsiChar; _c: PMDC2_CTX): TC_INT; cdecl = nil;
	MDC2: function(const _d: PAnsiChar; _n: TC_SIZE_T;_md: PAnsiChar): PAnsiChar; cdecl = nil;
	

procedure SSL_InitMDC2;

implementation
uses ssl_lib;

procedure SSL_InitMDC2;
begin
	if @MDC2_Init = nil then
		begin
			@MDC2_Init:= LoadFunctionCLib('MDC2_Init');
			@MDC2_Update:= LoadFunctionCLib('MDC2_Update');
			@MDC2_Final:= LoadFunctionCLib('MDC2_Final');
			@MDC2:= LoadFunctionCLib('MDC2');
		end;
end;

end.
