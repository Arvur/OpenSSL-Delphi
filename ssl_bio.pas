{$I ssl.inc}
unit ssl_bio;

interface
uses {$IFDEF UNIX}cNetDB{$ELSE}winapi.winsock2{$ENDIF}, ssl_types;


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
  BIO_s_file: function: PBIO_METHOD; cdecl = nil;
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

  BIO_new_socket: function(sock: TC_INT;close_flag: TC_INT): PBIO; cdecl = nil;
  BIO_new_dgram: function(fd: TC_INT; close_flag: TC_INT): PBIO; cdecl = nil;
  BIO_sock_error: function(sock: TC_INT): TC_INT; cdecl = nil;
  BIO_socket_ioctl: function(fd: TC_INT; _type: TC_LONG; arg: Pointer): TC_INT; cdecl = nil;
  BIO_socket_nbio: function(fd: TC_INT; mode: TC_INT): TC_INT;
  BIO_get_port: function(str: PAnsiChar; port_ptr: PC_USHORT): TC_INT; cdecl = nil;
  BIO_get_host_ip: function(str: PAnsiChar; ip: PAnsiChar): TC_INT; cdecl = nil;
  BIO_get_accept_socket: function(host_port: PAnsiChar; mode: TC_INT): TC_INT;
  BIO_accept: function(sock: TC_INT; ip_port: PPAnsiChar): TC_INT; cdecl = nil;
  BIO_sock_init: function: TC_INT; cdecl = nil;
  BIO_sock_cleanup: procedure; cdecl = nil;
  BIO_set_tcp_ndelay: function(sock: TC_INT;turn_on: TC_INT): TC_INT; cdecl = nil;

  BIO_asn1_set_prefix: function(b: PBIO; prefix: asn1_ps_func; prefix_free: asn1_ps_func): TC_INT; cdecl = nil;
  BIO_asn1_get_prefix: function(b: pBIO; var pprefix: asn1_ps_func; var pprefix_free: asn1_ps_func): TC_INT; cdecl = nil;
  BIO_asn1_set_suffix: function(b: PBIO; suffix: asn1_ps_func; suffix_free: asn1_ps_func): TC_INT; cdecl = nil;
  BIO_asn1_get_suffix: function(b: PBIO; var psuffix: asn1_ps_func;	var psuffix_free:	asn1_ps_func): TC_INT; cdecl = nil;

  BIO_set_flags: procedure(b: PBIO; flags: TC_INT); cdecl = nil;
  BIO_test_flags: function(b: PBIO; flags: TC_INT):TC_INT; cdecl = nil;
  BIO_clear_flags: procedure(b: PBIO; flags: TC_INT); cdecl = nil;

  BIO_copy_next_retry: procedure(b :PBIO); cdecl = nil;
  BIO_ctrl_get_write_guarantee: function(b: PBIO): TC_size_t; cdecl = nil;
  BIO_ctrl_get_read_request: function(b :PBIO): TC_SIZE_T; cdecl = nil;
  BIO_ctrl_reset_read_request: function(b: PBIO): TC_INT; cdecl = nil;
  BIO_ctrl_pending_f: function(b: PBIO): TC_SIZE_T; cdecl = nil;
  BIO_ctrl_wpending: function(b: PBIO): TC_SIZE_T; cdecl = nil;
  BIO_debug_callback: function(bio: PBIO; cmd: TC_INT; argp: PAnsiChar; argi: TC_INT; argl: TC_LONG; ret: TC_LONG): TC_LONG; cdecl = nil;
  BIO_dgram_non_fatal_error: function(error: TC_INT): TC_INT; cdecl = nil;

  BIO_dump: function(b: PBIO; bytes: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
  BIO_dump_cb: function(cb: pbio_dump_cb; u: Pointer; s: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
  BIO_dump_fp: function(var fp: File; s: PAnsiChar; len: TC_INT): TC_INT; cdecl = nil;
  BIO_dump_indent: function(b: PBIO; bytes: PAnsiChar; len: TC_INT; indent: TC_INT): TC_INT; cdecl = nil;
  BIO_dump_indent_cb: function(cb: pbio_dump_cb; u: Pointer; s: PAnsiChar; len: TC_INT; indent: TC_INT): TC_INT; cdecl = nil;
  BIO_dump_indent_fp: function(var fp: File; s: PAnsiChar; len: TC_INT; indent: TC_INT): TC_INT; cdecl = nil;
  BIO_f_asn1: function: PBIO_METHOD; cdecl = nil;
  BIO_f_base64: function: PBIO_METHOD; cdecl = nil;
  BIO_f_cipher: function: PBIO_METHOD; cdecl = nil;
  BIO_f_md: function: PBIO_METHOD; cdecl = nil;
  BIO_f_reliable: function: PBIO_METHOD; cdecl = nil;
  BIO_fd_non_fatal_error: function(error: TC_INT): TC_INT; cdecl = nil;
  BIO_fd_should_retry: function(i: TC_INT): TC_INT; cdecl = nil;
  BIO_get_callback: function(b: PBIO): Pbio_info_cb; cdecl = nil;
  BIO_get_callback_arg: function(b: PBIO): PAnsiChar; cdecl = nil;
  BIO_get_ex_data: function(bio: PBIO; idx: TC_INT; data: Pointer): TC_INT; cdecl = nil;
  BIO_get_ex_new_index: function(argl: TC_LONG; argp: Pointer; new_func: CRYPTO_EX_new;
      	dup_func: CRYPTO_EX_dup; free_func: CRYPTO_EX_free): TC_INT; cdecl = nil;
  BIO_gethostbyname: function(name: PAnsiChar) : PHostEnt; cdecl = nil;
  BIO_method_name: function(b: PBIO): PAnsiChar; cdecl = nil;
  BIO_method_type: function(b: PBIO): TC_INT; cdecl = nil;
  BIO_new_NDEF: function(_out: PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO;
  BIO_new_PKCS7: function(_out: PBIO; p7: PPKCS7): PBIO;
  BIO_new_accept: function(host_port: PAnsiChar): PBIO; cdecl = nil;
  BIO_new_bio_pair: function (bio1: PPBIO; writebuf1: TC_SIZE_T; bio2: PPBIO; writebuf2: TC_SIZE_T): TC_INT;
  BIO_new_connect: function(host_port: PAnsiChar): PBIO; cdecl = nil;
  BIO_new_fd: function(fd: TC_INT; close_flag: TC_INT): PBIO; cdecl = nil;
  BIO_new_file: function(filename: PAnsiChar; mode: PAnsiChar): PBIO; cdecl = nil;
  BIO_new_fp: function(var stream: FILE; close_flag: TC_INT): PBIO; cdecl = nil;
  BIO_nread0: function(bio: PBIO; buf: PPAnsiChar): TC_INT; cdecl = nil;
  BIO_nread: function(bio: PBIO; buf: PPAnsiChar; num: TC_INT): TC_INT; cdecl = nil;
  BIO_number_read: function(bio: PBIO): TC_ULONG; cdecl = nil;
  BIO_number_written: function(bio: PBIO): TC_ULONG; cdecl = nil;
  BIO_nwrite0: function(bio: PBIO; buf: PPAnsiChar): TC_INT; cdecl = nil;
  BIO_nwrite: function(bio: PBIO; buf: PPAnsiChar; num: TC_INT): TC_INT; cdecl = nil;
  BIO_set_callback: procedure(b: PBIO; cb: Pbio_info_cb); cdecl = nil;
  BIO_set_callback_arg: procedure(b: PBIO; arg: PAnsiChar); cdecl = nil;
  BIO_set_cipher: procedure(b: PBIO; c: PEVP_CIPHER; k: PAnsiChar; i: PAnsiChar; enc: TC_INT); cdecl = nil;
  BIO_set_ex_data: function (bio: PBIO; idx: TC_INT; data: pointer): TC_INT; cdecl = nil;
  BIO_sock_non_fatal_error: function(error: TC_INT): TC_INT; cdecl = nil;
  BIO_sock_should_retry: function(i: TC_INT): TC_INT; cdecl = nil;


function BIO_get_mem_data (bp: PBIO; buf: Pointer): TC_ULONG; inline;
function BIO_reset(bp: PBIO): TC_INT; inline;
function BIO_ReadAnsiString(bp: PBIO): AnsiString;
function BIO_Flush(bp: PBIO): TC_INT; inline;
function BIO_Pending(bp: PBIO): TC_INT; inline;
function BIO_Eof(bp: PBIO): TC_INT; inline;
function BIO_read_filename(b: PBIO; const name: PAnsiChar): TC_INT;

{
 BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms);
int BIO_printf(BIO *bio, const char *format, ...)
	__bio_h__attr__((__format__(__printf__,2,3)));
int BIO_vprintf(BIO *bio, const char *format, va_list args)
	__bio_h__attr__((__format__(__printf__,2,0)));
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	__bio_h__attr__((__format__(__printf__,3,4)));
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	__bio_h__attr__((__format__(__printf__,3,0)));

 }

procedure SSL_InitBIO;

implementation

uses ssl_lib, ssl_const;

procedure SSL_InitBIO;
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
    @BIO_s_file:= LoadFunctionCLib('BIO_s_file');
    @BIO_s_connect:= LoadFunctionCLib('BIO_s_connect');
    @BIO_s_accept:= LoadFunctionCLib('BIO_s_accept');
    @BIO_s_fd:= LoadFunctionCLib('BIO_s_fd');
    @BIO_s_log:= LoadFunctionCLib('BIO_s_log', false);
    @BIO_s_bio:= LoadFunctionCLib('BIO_s_bio');
    @BIO_s_null:= LoadFunctionCLib('BIO_s_null');
    @BIO_f_null:= LoadFunctionCLib('BIO_f_null');
    @BIO_f_buffer:= LoadFunctionCLib('BIO_f_buffer');
    @BIO_f_linebuffer:= LoadFunctionCLib('BIO_f_linebuffer', false);
    @BIO_f_nbio_test:= LoadFunctionCLib('BIO_f_nbio_test');
    @BIO_s_datagram:= LoadFunctionCLib('BIO_s_datagram');
    @BIO_new_socket:= LoadFunctionCLib('BIO_new_socket');
    @BIO_new_dgram:= LoadFunctionCLib('BIO_new_dgram');
    @BIO_sock_error:= LoadFunctionCLib('BIO_sock_error');
    @BIO_socket_ioctl:= LoadFunctionCLib('BIO_socket_ioctl');
    @BIO_socket_nbio:= LoadFunctionCLib('BIO_socket_nbio');
    @BIO_get_port:= LoadFunctionCLib('BIO_get_port');
    @BIO_get_host_ip:= LoadFunctionCLib('BIO_get_host_ip');
    @BIO_get_accept_socket:= LoadFunctionCLib('BIO_get_accept_socket');
    @BIO_accept:= LoadFunctionCLib('BIO_accept');
    @BIO_sock_init:= LoadFunctionCLib('BIO_sock_init');
    @BIO_sock_cleanup:= LoadFunctionCLib('BIO_sock_cleanup');
    @BIO_set_tcp_ndelay:= LoadFunctionCLib('BIO_set_tcp_ndelay');
    @BIO_asn1_set_prefix:= LoadFunctionCLib('BIO_asn1_set_prefix', false);
    @BIO_asn1_get_prefix:= LoadFunctionCLib('BIO_asn1_get_prefix', false);
    @BIO_asn1_set_suffix:= LoadFunctionCLib('BIO_asn1_set_suffix', false);
    @BIO_asn1_get_suffix:= LoadFunctionCLib('BIO_asn1_get_suffix', false);
    @BIO_set_flags:= LoadFunctionCLib('BIO_set_flags');
    @BIO_test_flags:= LoadFunctionCLib('BIO_test_flags');
    @BIO_clear_flags:= LoadFunctionCLib('BIO_clear_flags');
    @BIO_copy_next_retry:= LoadFunctionCLib('BIO_copy_next_retry');
    @BIO_ctrl_get_write_guarantee:= LoadFunctionCLib('BIO_ctrl_get_write_guarantee');
    @BIO_ctrl_get_read_request:= LoadFunctionCLib('BIO_ctrl_get_read_request');
    @BIO_ctrl_reset_read_request:= LoadFunctionCLib('BIO_ctrl_reset_read_request');
    @BIO_ctrl_pending_f:= LoadFunctionCLib('BIO_ctrl_pending');
    @BIO_ctrl_wpending:= LoadFunctionCLib('BIO_ctrl_wpending');
    @BIO_debug_callback:= LoadFunctionCLib('BIO_debug_callback');
    @BIO_dgram_non_fatal_error:= LoadFunctionCLib('BIO_dgram_non_fatal_error');
    @BIO_dump:= LoadFunctionCLib('BIO_dump');
    @BIO_dump_cb:= LoadFunctionCLib('BIO_dump_cb');
    @BIO_dump_fp:= LoadFunctionCLib('BIO_dump_fp');
    @BIO_dump_indent:= LoadFunctionCLib('BIO_dump_indent');
    @BIO_dump_indent_cb:= LoadFunctionCLib('BIO_dump_indent_cb');
    @BIO_dump_indent_fp:= LoadFunctionCLib('BIO_dump_indent_fp');
    @BIO_f_asn1:= LoadFunctionCLib('BIO_f_asn1', false);
    @BIO_f_base64:= LoadFunctionCLib('BIO_f_base64');
    @BIO_f_cipher:= LoadFunctionCLib('BIO_f_cipher');
    @BIO_f_md:= LoadFunctionCLib('BIO_f_md');
    @BIO_f_reliable:= LoadFunctionCLib('BIO_f_reliable');
    @BIO_fd_non_fatal_error:= LoadFunctionCLib('BIO_fd_non_fatal_error');
    @BIO_fd_should_retry:= LoadFunctionCLib('BIO_fd_should_retry');
    @BIO_get_callback:= LoadFunctionCLib('BIO_get_callback');
    @BIO_get_callback_arg:= LoadFunctionCLib('BIO_get_callback_arg');
    @BIO_get_ex_data:= LoadFunctionCLib('BIO_get_ex_data');
    @BIO_get_ex_new_index:= LoadFunctionCLib('BIO_get_ex_new_index');
    @BIO_gethostbyname:= LoadFunctionCLib('BIO_gethostbyname');
    @BIO_method_name:= LoadFunctionCLib('BIO_method_name');
    @BIO_method_type:= LoadFunctionCLib('BIO_method_type');
    @BIO_new_NDEF:= LoadFunctionCLib('BIO_new_NDEF', False);
    @BIO_new_PKCS7:= LoadFunctionCLib('BIO_new_PKCS7', false);
    @BIO_new_accept:= LoadFunctionCLib('BIO_new_accept');
    @BIO_new_bio_pair:= LoadFunctionCLib('BIO_new_bio_pair');
    @BIO_new_connect:= LoadFunctionCLib('BIO_new_connect');
    @BIO_new_fd:= LoadFunctionCLib('BIO_new_fd');
    @BIO_new_file:= LoadFunctionCLib('BIO_new_file');
    @BIO_new_fp:= LoadFunctionCLib('BIO_new_fp');
    @BIO_nread0:= LoadFunctionCLib('BIO_nread0');
    @BIO_nread:= LoadFunctionCLib('BIO_nread');
    @BIO_number_read:= LoadFunctionCLib('BIO_number_read');
    @BIO_number_written:= LoadFunctionCLib('BIO_number_written');
    @BIO_nwrite0:= LoadFunctionCLib('BIO_nwrite0');
    @BIO_nwrite:= LoadFunctionCLib('BIO_nwrite');
    @BIO_set_callback:= LoadFunctionCLib('BIO_set_callback');
    @BIO_set_callback_arg:= LoadFunctionCLib('BIO_set_callback_arg');
    @BIO_set_cipher:= LoadFunctionCLib('BIO_set_cipher');
    @BIO_set_ex_data:= LoadFunctionCLib('BIO_set_ex_data');
    @BIO_sock_non_fatal_error:= LoadFunctionCLib('BIO_sock_non_fatal_error');
    @BIO_sock_should_retry:= LoadFunctionCLib('BIO_sock_should_retry');
  end;
end;

function BIO_reset(bp: PBIO): TC_INT; inline;
begin
  Result := BIO_ctrl(bp, BIO_CTRL_RESET, 0, nil);
end;

function BIO_get_mem_data (bp: PBIO; buf: Pointer): TC_ULONG; inline;
begin
  Result := BIO_ctrl(bp, BIO_CTRL_INFO, 0, buf);
end;

function BIO_Flush(bp: PBIO): TC_INT; inline;
begin
 Result := BIO_ctrl(bp, BIO_CTRL_FLUSH, 0, nil);
end;

function BIO_Pending(bp: PBIO): TC_INT; inline;
begin
 Result := BIO_ctrl(bp, BIO_CTRL_PENDING, 0, nil);
end;

function BIO_Eof(bp: PBIO): TC_INT; inline;
begin
  Result := BIO_ctrl(bp, BIO_CTRL_EOF, 0, nil);
end;

function BIO_ReadAnsiString(bp: PBIO): AnsiString;
var Buf: AnsiString;
    a: TC_INT;
begin
  Result := '';
    SetLength(Buf, 512);
    repeat
     a := BIO_read(bp, @Buf[1], Length(Buf));
     if a > 0 then
      Result := Result + Copy(Buf, 1, a);
    until a <= 0;
  SetLength(Buf, 0);
end;

function BIO_read_filename(b: PBIO; const name: PAnsiChar): TC_INT;
begin
  Result := BIO_ctrl(b, BIO_C_SET_FILENAME, BIO_CLOSE or BIO_FP_READ, Name);
end;

end.