unit ssl_bio;

interface
uses ssl_types;

var
  BIO_new: function(_type: PBIO_METHOD): PBIO; cdecl = nil;
  BIO_set: function(a: PBIO; _type: PBIO_METHOD): TC_INT; cdecl = nil;
  BIO_free: function(a: PBIO): TC_INT; cdecl = nil;
  BIO_vfree: procedure(a: PBIO); cdecl = nil;
  BIO_read: function(b: PBIO; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  BIO_gets: function(b: PBIO; buf: PAnsiChar; size: TC_INT): TC_INT; cdecl = nil;
  BIO_write: function(b: PBIO; data: Pointer; len: TC_INT): TC_INT; cdecl = nil;
  BIO_puts: function(bp: PBIO; buf: PAnsiChar): TC_INT; cdecl = nil;
  BIO_indent: function(b: PBIO; indent: TC_INT; max: TC_INT): TC_INT; cdecl = nil;
  BIO_ctrl: function (b: PBIO; cmd: TC_INT; larg: TC_LONG; parg: Pointer): TC_LONG; cdecl = nil;
  BIO_callback_ctrl: function(b:PBIO; cmd: TC_INT; callback: Pbio_info_cb): TC_LONG; cdecl = nil;
  BIO_ptr_ctrl: function(p: PBIO; cmd: TC_INT; larg: TC_LONG): PAnsiChar; cdecl = nil;
  BIO_int_ctrl: function(p: PBIO; cmd: TC_INT; larg: TC_LONG; iarg: TC_INT): TC_LONG; cdecl = nil;
  BIO_push: function(b: PBIO; append: PBIO): PBIO; cdecl = nil;
  BIO_pop: function(b: PBIO): PBIO; cdecl = nil;
  BIO_free_all: procedure(a: PBIO); cdecl = nil;
  BIO_find_type: function(b: PBIO; bio_type: TC_INT): PBIO; cdecl = nil;
  BIO_next: function (b: PBIO): PBIO; cdecl = nil;
  BIO_get_retry_BIO: function(bio: PBIO; reason: TC_INT): PBIO; cdecl = nil;
  BIO_get_retry_reason: function (bio: PBIO): TC_INT; cdecl = nil;
  BIO_dup_chain: function(_in: PBIO): PBIO; cdecl = nil;
  BIO_s_mem: function: PBIO_METHOD; cdecl = nil;
  BIO_new_mem_buf: function(buf: Pointer; len: TC_INT): PBIO; cdecl = nil;
  BIO_s_socket: function: PBIO_METHOD; cdecl = nil;
  BIO_s_connect: function: PBIO_METHOD; cdecl = nil;
  BIO_s_accept: function: PBIO_METHOD; cdecl = nil;
  BIO_s_fd: function: PBIO_METHOD; cdecl = nil;
  BIO_s_log: function: PBIO_METHOD; cdecl = nil;
  BIO_s_bio: function: PBIO_METHOD; cdecl = nil;
  BIO_s_null: function: PBIO_METHOD; cdecl = nil;
  BIO_f_null: function: PBIO_METHOD; cdecl = nil;
  BIO_f_buffer: function: PBIO_METHOD; cdecl = nil;
  BIO_f_linebuffer: function: PBIO_METHOD; cdecl = nil;
  BIO_f_nbio_test: function: PBIO_METHOD; cdecl = nil;
  BIO_s_datagram: function: PBIO_METHOD; cdecl = nil;
  BIO_s_datagram_sctp: function: PBIO_METHOD; cdecl = nil;


implementation

uses ssl_lib;

procedure SSL_InitEVP;
begin
  if @BIO_new = nil then
  begin
    @BIO_new := LoadFunctionCLib('BIO_new');
    @BIO_set := LoadFunctionCLib('BIO_set');
    @BIO_free:= LoadFunctionCLib('BIO_free');
    @BIO_vfree:= LoadFunctionCLib('BIO_vfree');
    @BIO_read:= LoadFunctionCLib('BIO_read');
    @BIO_gets:= LoadFunctionCLib('BIO_gets');
    @BIO_write:= LoadFunctionCLib('BIO_write');
    @BIO_puts:= LoadFunctionCLib('BIO_puts');
    @BIO_indent:= LoadFunctionCLib('BIO_indent');
    @BIO_ctrl:= LoadFunctionCLib('BIO_ctrl');
    @BIO_callback_ctrl:= LoadFunctionCLib('BIO_callback_ctrl');
    @BIO_ptr_ctrl:= LoadFunctionCLib('BIO_ptr_ctrl');
    @BIO_int_ctrl:= LoadFunctionCLib('BIO_int_ctrl');
    @BIO_push:= LoadFunctionCLib('BIO_push');
    @BIO_pop:= LoadFunctionCLib('BIO_pop');
    @BIO_free_all:= LoadFunctionCLib('BIO_free_all');
    @BIO_find_type:= LoadFunctionCLib('BIO_find_type');
    @BIO_next:= LoadFunctionCLib('BIO_next');
    @BIO_get_retry_BIO:= LoadFunctionCLib('BIO_get_retry_BIO');
    @BIO_get_retry_reason:= LoadFunctionCLib('BIO_get_retry_reason');
    @BIO_dup_chain:= LoadFunctionCLib('BIO_dup_chain');
    @BIO_s_mem:= LoadFunctionCLib('BIO_s_mem');
    @BIO_new_mem_buf:= LoadFunctionCLib('BIO_new_mem_buf');
    @BIO_s_socket:= LoadFunctionCLib('BIO_s_socket');
    @BIO_s_connect:= LoadFunctionCLib('BIO_s_connect');
    @BIO_s_accept:= LoadFunctionCLib('BIO_s_accept');
    @BIO_s_fd:= LoadFunctionCLib('BIO_s_fd');
    @BIO_s_log:= LoadFunctionCLib('BIO_s_log');
    @BIO_s_bio:= LoadFunctionCLib('BIO_s_bio');
    @BIO_s_null:= LoadFunctionCLib('BIO_s_null');
    @BIO_f_null:= LoadFunctionCLib('BIO_f_null');
    @BIO_f_buffer:= LoadFunctionCLib('BIO_f_buffer');
    @BIO_f_linebuffer:= LoadFunctionCLib('BIO_f_linebuffer');
    @BIO_f_nbio_test:= LoadFunctionCLib('BIO_f_nbio_test');
    @BIO_s_datagram:= LoadFunctionCLib('BIO_s_datagram');
    @BIO_s_datagram_sctp:= LoadFunctionCLib('BIO_s_datagram_sctp');
  end;
end;
end.
