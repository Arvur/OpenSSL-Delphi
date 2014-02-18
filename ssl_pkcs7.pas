{$i ssl.inc}
unit ssl_pkcs7;
interface
uses ssl_types;
var
	PKCS7_ISSUER_AND_SERIAL_new: function: PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
	PKCS7_ISSUER_AND_SERIAL_free: procedure(a: PPKCS7_ISSUER_AND_SERIAL); cdecl = nil;
	d2i_PKCS7_ISSUER_AND_SERIAL: function(a: PPPKCS7_ISSUER_AND_SERIAL; _in: PPAnsiChar; len: TC_LONG): PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
	i2d_PKCS7_ISSUER_AND_SERIAL: function(a: PPKCS7_ISSUER_AND_SERIAL; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_ISSUER_AND_SERIAL_it: function: PASN1_ITEM; cdecl = nil;

	PKCS7_ISSUER_AND_SERIAL_digest: function(_data: PPKCS7_ISSUER_AND_SERIAL;const _type: PEVP_MD;_md: PAnsiChar; var _len: TC_UINT): TC_INT; cdecl = nil;
	PKCS7_dup: function(_p7: PPKCS7): PPKCS7; cdecl = nil;
	d2i_PKCS7_bio: function(_bp: PBIO;_p7: PPPKCS7): PPKCS7; cdecl = nil;
	i2d_PKCS7_bio: function(_bp: PBIO; _p7: PPKCS7): TC_INT; cdecl = nil;
	i2d_PKCS7_bio_stream: function(_out: PBIO; _p7: PPKCS7; _in: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	PEM_write_bio_PKCS7_stream: function(_out: PBIO; _p7: PPKCS7; _in: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;

	PKCS7_SIGNER_INFO_new: function: PPKCS7_SIGNER_INFO; cdecl = nil;
	PKCS7_SIGNER_INFO_free: procedure(a: PPKCS7_SIGNER_INFO); cdecl = nil;
	d2i_PKCS7_SIGNER_INFO: function(a: PPPKCS7_SIGNER_INFO; _in: PPAnsiChar; len: TC_LONG): PPKCS7_SIGNER_INFO; cdecl = nil;
	i2d_PKCS7_SIGNER_INFO: function(a: PPKCS7_SIGNER_INFO; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_SIGNER_INFO_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_RECIP_INFO_new: function: PPKCS7_RECIP_INFO; cdecl = nil;
	PKCS7_RECIP_INFO_free: procedure(a: PPKCS7_RECIP_INFO); cdecl = nil;
	d2i_PKCS7_RECIP_INFO: function(a: PPPKCS7_RECIP_INFO; _in: PPAnsiChar; len: TC_LONG): PPKCS7_RECIP_INFO; cdecl = nil;
	i2d_PKCS7_RECIP_INFO: function(a: PPKCS7_RECIP_INFO; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_RECIP_INFO_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_SIGNED_new: function: PPKCS7_SIGNED; cdecl = nil;
	PKCS7_SIGNED_free: procedure(a: PPKCS7_SIGNED); cdecl = nil;
	d2i_PKCS7_SIGNED: function(a: PPPKCS7_SIGNED; _in: PPAnsiChar; len: TC_LONG): PPKCS7_SIGNED; cdecl = nil;
	i2d_PKCS7_SIGNED: function(a: PPKCS7_SIGNED; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_SIGNED_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_ENC_CONTENT_new: function: PPKCS7_ENC_CONTENT; cdecl = nil;
	PKCS7_ENC_CONTENT_free: procedure(a: PPKCS7_ENC_CONTENT); cdecl = nil;
	d2i_PKCS7_ENC_CONTENT: function(a: PPPKCS7_ENC_CONTENT; _in: PPAnsiChar; len: TC_LONG): PPKCS7_ENC_CONTENT; cdecl = nil;
	i2d_PKCS7_ENC_CONTENT: function(a: PPKCS7_ENC_CONTENT; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_ENC_CONTENT_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_ENVELOPE_new: function: PPKCS7_ENVELOPE; cdecl = nil;
	PKCS7_ENVELOPE_free: procedure(a: PPKCS7_ENVELOPE); cdecl = nil;
	d2i_PKCS7_ENVELOPE: function(a: PPPKCS7_ENVELOPE; _in: PPAnsiChar; len: TC_LONG): PPKCS7_ENVELOPE; cdecl = nil;
	i2d_PKCS7_ENVELOPE: function(a: PPKCS7_ENVELOPE; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_ENVELOPE_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_SIGN_ENVELOPE_new: function: PPKCS7_SIGN_ENVELOPE; cdecl = nil;
	PKCS7_SIGN_ENVELOPE_free: procedure(a: PPKCS7_SIGN_ENVELOPE); cdecl = nil;
  d2i_PKCS7_SIGN_ENVELOPE: function(a: PPPKCS7_SIGN_ENVELOPE; _in: PPAnsiChar; len: TC_LONG): PPKCS7_SIGN_ENVELOPE; cdecl = nil;
	i2d_PKCS7_SIGN_ENVELOPE: function(a: PPKCS7_SIGN_ENVELOPE; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_SIGN_ENVELOPE_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_DIGEST_new: function: PPKCS7_DIGEST; cdecl = nil;
	PKCS7_DIGEST_free: procedure(a: PPKCS7_DIGEST); cdecl = nil;
	d2i_PKCS7_DIGEST: function(a: PPPKCS7_DIGEST; _in: PPAnsiChar; len: TC_LONG): PPKCS7_DIGEST; cdecl = nil;
	i2d_PKCS7_DIGEST: function(a: PPKCS7_DIGEST; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_DIGEST_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_ENCRYPT_new: function: PPKCS7_ENCRYPT; cdecl = nil;
	PKCS7_ENCRYPT_free: procedure(a: PPKCS7_ENCRYPT); cdecl = nil;
	d2i_PKCS7_ENCRYPT: function(a: PPPKCS7_ENCRYPT; _in: PPAnsiChar; len: TC_LONG): PPKCS7_ENCRYPT; cdecl = nil;
	i2d_PKCS7_ENCRYPT: function(a: PPKCS7_ENCRYPT; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_ENCRYPT_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_new: function: PPKCS7; cdecl = nil;
	PKCS7_free: procedure(a: PPKCS7); cdecl = nil;
	d2i_PKCS7: function(a: PPPKCS7; _in: PPAnsiChar; len: TC_LONG): PPKCS7; cdecl = nil;
	i2d_PKCS7: function(a: PPKCS7; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS7_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_ATTR_SIGN_it: function: PASN1_ITEM; cdecl = nil;
	PKCS7_ATTR_VERIFY_it: function: PASN1_ITEM; cdecl = nil;

	PKCS7_ctrl: function(_p7: PPKCS7; _cmd: TC_INT; _larg: TC_LONG; _parg: PAnsiChar): TC_LONG; cdecl = nil;

	PKCS7_set_type: function(_p7: PPKCS7; _type: TC_INT): TC_INT; cdecl = nil;
	PKCS7_set0_type_other: function(_p7: PPKCS7; _type: TC_INT; _other: PASN1_TYPE): TC_INT; cdecl = nil;
	PKCS7_set_content: function(_p7: PPKCS7; _p7_data: PPKCS7): TC_INT; cdecl = nil;
	PKCS7_SIGNER_INFO_set: function(_p7i: PPKCS7_SIGNER_INFO; _x509: PX509; _pkey: PEVP_PKEY;const _dgst: PEVP_MD): TC_INT; cdecl = nil;
	PKCS7_SIGNER_INFO_sign: function(_si: PPKCS7_SIGNER_INFO): TC_INT; cdecl = nil;
	PKCS7_add_signer: function(_p7: PPKCS7; _p7i: PPKCS7_SIGNER_INFO): TC_INT; cdecl = nil;
	PKCS7_add_certificate: function(_p7: PPKCS7; _x509: PX509): TC_INT; cdecl = nil;
	PKCS7_add_crl: function(_p7: Pointer; _x509: PX509_CRL): TC_INT; cdecl = nil;
	PKCS7_content_new: function(_p7: PPKCS7; _nid: TC_INT): TC_INT; cdecl = nil;
	PKCS7_dataVerify: function(_cert_store: PX509_STORE; _ctx: PX509_STORE_CTX;_bio: PBIO; _p7: PPKCS7; _si: PPKCS7_SIGNER_INFO): TC_INT; cdecl = nil;
	PKCS7_signatureVerify: function(_bio: PBIO; _p7: PPKCS7; _si: PPKCS7_SIGNER_INFO; _x509: PX509): TC_INT; cdecl = nil;

	PKCS7_dataInit: function(_p7: PPKCS7; _bio: PBIO): PBIO; cdecl = nil;
	PKCS7_dataFinal: function(_p7: PPKCS7; _bio: PBIO): TC_INT; cdecl = nil;
	PKCS7_dataDecode: function(_p7: PPKCS7; _pkey: PEVP_PKEY; _in_bio: PBIO; _pcert: PX509): PBIO; cdecl = nil;

	PKCS7_add_signature: function(_p7: PPKCS7; _x509: PX509; _pkey: PEVP_PKEY; const _dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl = nil;
	PKCS7_cert_from_signer_info: function(_p7: PPKCS7; _si: PPKCS7_SIGNER_INFO): PX509; cdecl = nil;
	PKCS7_set_digest: function(_p7: PPKCS7; const _md: PEVP_MD): TC_INT; cdecl = nil;
	PKCS7_get_signer_info: function(_p7: PPKCS7): PSTACK_OF_PKCS7_SIGNER_INFO; cdecl = nil;

	PKCS7_add_recipient: function(_p7: PPKCS7; _x509: PX509): PPKCS7_RECIP_INFO; cdecl = nil;
	PKCS7_SIGNER_INFO_get0_algs: procedure(_si: PPKCS7_SIGNER_INFO; _pk: PPEVP_PKEY; _pdig: PPX509_ALGOR; _psig: PPX509_ALGOR); cdecl = nil;
	PKCS7_RECIP_INFO_get0_alg: procedure(_ri: PPKCS7_RECIP_INFO; _penc: PPX509_ALGOR); cdecl = nil;
	PKCS7_add_recipient_info: function(_p7: PPKCS7; _ri: PPKCS7_RECIP_INFO): TC_INT; cdecl = nil;
	PKCS7_RECIP_INFO_set: function(_p7i: PPKCS7_RECIP_INFO; _x509: PX509): TC_INT; cdecl = nil;
	PKCS7_set_cipher: function(_p7: PPKCS7; const _cipher: PEVP_CIPHER): TC_INT; cdecl = nil;
	//PKCS7_stream: function(unsigned char ***boundary; _p7: PPKCS7): TC_INT; cdecl = nil;

	PKCS7_get_issuer_and_serial: function(_p7: PPKCS7; _idx: TC_INT): Pointer; cdecl = nil;
	PKCS7_digest_from_attributes: function( _sk: PSTACK_OF_X509_ATTRIBUTE): Pointer; cdecl = nil;
	PKCS7_add_signed_attribute: function(_p7si: PPKCS7_SIGNER_INFO;_nid: TC_INT;_type: TC_INT;_data: Pointer): TC_INT; cdecl = nil;
	PKCS7_add_attribute : function(_p7si: PPKCS7_SIGNER_INFO; _nid: TC_INT; _atrtype: TC_INT;_value: Pointer): TC_INT; cdecl = nil;
	PKCS7_get_attribute: function(_si: PPKCS7_SIGNER_INFO; _nid: TC_INT): PASN1_TYPE; cdecl = nil;
	PKCS7_get_signed_attribute: function(_si: PPKCS7_SIGNER_INFO; _nid: TC_INT): PASN1_TYPE; cdecl = nil;
	PKCS7_set_signed_attributes: function(_p7si: PPKCS7_SIGNER_INFO; _sk: PSTACK_OF_X509_ATTRIBUTE): TC_INT; cdecl = nil;
	PKCS7_set_attributes: function(_p7si: PPKCS7_SIGNER_INFO; _sk: PSTACK_OF_X509_ATTRIBUTE): TC_INT; cdecl = nil;

	PKCS7_sign: function(_signcert: PX509; _pkey: PEVP_PKEY;  _certs: PSTACK_OF_X509;_data: PBIO; _flags: TC_INT): PPKCS7; cdecl = nil;

	PKCS7_sign_add_signer: function(_p7: PPKCS7;_signcert: PX509; _pkey: PEVP_PKEY; const _md: PEVP_MD;_flags: TC_INT): PPKCS7_SIGNER_INFO; cdecl = nil;

	PKCS7_final: function(_p7: PPKCS7; _data: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	PKCS7_verify: function(_p7: PPKCS7;  _certs: PSTACK_OF_X509; _store: PX509_STORE;_indata: PBIO; _out: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	PKCS7_get0_signers: function(_p7: PPKCS7;  _certs: PSTACK_OF_X509; _flags: TC_INT): PSTACK_OF_X509; cdecl = nil;
	PKCS7_encrypt: function( _certs: PSTACK_OF_X509; _in: PBIO; const _cipher: PEVP_CIPHER;_flags: TC_INT): PPKCS7; cdecl = nil;
	PKCS7_decrypt: function(_p7: PPKCS7; _pkey: PEVP_PKEY; _cert: PX509; _data: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;

	PKCS7_add_attrib_smimecap: function(_si: PPKCS7_SIGNER_INFO; _cap: PSTACK_OF_X509_ALGOR): TC_INT; cdecl = nil;
	PKCS7_get_smimecap: function(si: PPKCS7_SIGNER_INFO): PSTACK_OF_X509_ALGOR; cdecl = nil;
	PKCS7_simple_smimecap: function( _sk: PSTACK_OF_X509_ALGOR; _nid: TC_INT; _arg: TC_INT): TC_INT; cdecl = nil;

	PKCS7_add_attrib_content_type: function(_si: PPKCS7_SIGNER_INFO; _coid: PASN1_OBJECT): TC_INT; cdecl = nil;
	PKCS7_add0_attrib_signing_time: function(_si: PPKCS7_SIGNER_INFO; _t: PASN1_TIME): TC_INT; cdecl = nil;
	PKCS7_add1_attrib_digest: function(_si: PPKCS7_SIGNER_INFO;const _md: PAnsiChar; _mdlen: TC_INT): TC_INT; cdecl = nil;

	SMIME_write_PKCS7: function(_bio: PBIO; _p7: PPKCS7; _data: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	SMIME_read_PKCS7: function(_bio: PBIO; _bcont: PPBIO): PPKCS7; cdecl = nil;

	BIO_new_PKCS7: function(_out: PBIO; _p7: PPKCS7): PBIO; cdecl = nil;

	ERR_load_PKCS7_strings: procedure; cdecl = nil;

procedure SSL_InitPKCS7;

implementation
uses ssl_lib;

procedure SSL_InitPKCS7;
begin
	if @PKCS7_new = nil then
		begin
			@PKCS7_ISSUER_AND_SERIAL_new:= LoadFunctionCLib('PKCS7_ISSUER_AND_SERIAL_new');
			@PKCS7_ISSUER_AND_SERIAL_free:= LoadFunctionCLib('PKCS7_ISSUER_AND_SERIAL_free');
			@d2i_PKCS7_ISSUER_AND_SERIAL:= LoadFunctionCLib('d2i_PKCS7_ISSUER_AND_SERIAL');
			@i2d_PKCS7_ISSUER_AND_SERIAL:= LoadFunctionCLib('i2d_PKCS7_ISSUER_AND_SERIAL');
			@PKCS7_ISSUER_AND_SERIAL_it:= LoadFunctionCLib('PKCS7_ISSUER_AND_SERIAL_it');
			@PKCS7_ISSUER_AND_SERIAL_digest:= LoadFunctionCLib('PKCS7_ISSUER_AND_SERIAL_digest');
			@PKCS7_dup:= LoadFunctionCLib('PKCS7_dup');
			@d2i_PKCS7_bio:= LoadFunctionCLib('d2i_PKCS7_bio');
			@i2d_PKCS7_bio:= LoadFunctionCLib('i2d_PKCS7_bio');
			@i2d_PKCS7_bio_stream:= LoadFunctionCLib('i2d_PKCS7_bio_stream');
			@PEM_write_bio_PKCS7_stream:= LoadFunctionCLib('PEM_write_bio_PKCS7_stream');
			@PKCS7_SIGNER_INFO_new:= LoadFunctionCLib('PKCS7_SIGNER_INFO_new');
			@PKCS7_SIGNER_INFO_free:= LoadFunctionCLib('PKCS7_SIGNER_INFO_free');
			@d2i_PKCS7_SIGNER_INFO:= LoadFunctionCLib('d2i_PKCS7_SIGNER_INFO');
			@i2d_PKCS7_SIGNER_INFO:= LoadFunctionCLib('i2d_PKCS7_SIGNER_INFO');
			@PKCS7_SIGNER_INFO_it:= LoadFunctionCLib('PKCS7_SIGNER_INFO_it');
			@PKCS7_RECIP_INFO_new:= LoadFunctionCLib('PKCS7_RECIP_INFO_new');
			@PKCS7_RECIP_INFO_free:= LoadFunctionCLib('PKCS7_RECIP_INFO_free');
			@d2i_PKCS7_RECIP_INFO:= LoadFunctionCLib('d2i_PKCS7_RECIP_INFO');
			@i2d_PKCS7_RECIP_INFO:= LoadFunctionCLib('i2d_PKCS7_RECIP_INFO');
			@PKCS7_RECIP_INFO_it:= LoadFunctionCLib('PKCS7_RECIP_INFO_it');
			@PKCS7_SIGNED_new:= LoadFunctionCLib('PKCS7_SIGNED_new');
			@PKCS7_SIGNED_free:= LoadFunctionCLib('PKCS7_SIGNED_free');
			@d2i_PKCS7_SIGNED:= LoadFunctionCLib('d2i_PKCS7_SIGNED');
			@i2d_PKCS7_SIGNED:= LoadFunctionCLib('i2d_PKCS7_SIGNED');
			@PKCS7_SIGNED_it:= LoadFunctionCLib('PKCS7_SIGNED_it');
			@PKCS7_ENC_CONTENT_new:= LoadFunctionCLib('PKCS7_ENC_CONTENT_new');
			@PKCS7_ENC_CONTENT_free:= LoadFunctionCLib('PKCS7_ENC_CONTENT_free');
			@d2i_PKCS7_ENC_CONTENT:= LoadFunctionCLib('d2i_PKCS7_ENC_CONTENT');
			@i2d_PKCS7_ENC_CONTENT:= LoadFunctionCLib('i2d_PKCS7_ENC_CONTENT');
			@PKCS7_ENC_CONTENT_it:= LoadFunctionCLib('PKCS7_ENC_CONTENT_it');
			@PKCS7_ENVELOPE_new:= LoadFunctionCLib('PKCS7_ENVELOPE_new');
			@PKCS7_ENVELOPE_free:= LoadFunctionCLib('PKCS7_ENVELOPE_free');
			@d2i_PKCS7_ENVELOPE:= LoadFunctionCLib('d2i_PKCS7_ENVELOPE');
			@i2d_PKCS7_ENVELOPE:= LoadFunctionCLib('i2d_PKCS7_ENVELOPE');
			@PKCS7_ENVELOPE_it:= LoadFunctionCLib('PKCS7_ENVELOPE_it');
			@PKCS7_SIGN_ENVELOPE_new:= LoadFunctionCLib('PKCS7_SIGN_ENVELOPE_new');
			@PKCS7_SIGN_ENVELOPE_free:= LoadFunctionCLib('PKCS7_SIGN_ENVELOPE_free');
			@d2i_PKCS7_SIGN_ENVELOPE:= LoadFunctionCLib('d2i_PKCS7_SIGN_ENVELOPE');
			@i2d_PKCS7_SIGN_ENVELOPE:= LoadFunctionCLib('i2d_PKCS7_SIGN_ENVELOPE');
			@PKCS7_SIGN_ENVELOPE_it:= LoadFunctionCLib('PKCS7_SIGN_ENVELOPE_it');
			@PKCS7_DIGEST_new:= LoadFunctionCLib('PKCS7_DIGEST_new');
			@PKCS7_DIGEST_free:= LoadFunctionCLib('PKCS7_DIGEST_free');
			@d2i_PKCS7_DIGEST:= LoadFunctionCLib('d2i_PKCS7_DIGEST');
			@i2d_PKCS7_DIGEST:= LoadFunctionCLib('i2d_PKCS7_DIGEST');
			@PKCS7_DIGEST_it:= LoadFunctionCLib('PKCS7_DIGEST_it');
			@PKCS7_ENCRYPT_new:= LoadFunctionCLib('PKCS7_ENCRYPT_new');
			@PKCS7_ENCRYPT_free:= LoadFunctionCLib('PKCS7_ENCRYPT_free');
			@d2i_PKCS7_ENCRYPT:= LoadFunctionCLib('d2i_PKCS7_ENCRYPT');
			@i2d_PKCS7_ENCRYPT:= LoadFunctionCLib('i2d_PKCS7_ENCRYPT');
			@PKCS7_ENCRYPT_it:= LoadFunctionCLib('PKCS7_ENCRYPT_it');
			@PKCS7_new:= LoadFunctionCLib('PKCS7_new');
			@PKCS7_free:= LoadFunctionCLib('PKCS7_free');
			@d2i_PKCS7:= LoadFunctionCLib('d2i_PKCS7');
			@i2d_PKCS7:= LoadFunctionCLib('i2d_PKCS7');
			@PKCS7_it:= LoadFunctionCLib('PKCS7_it');

			@PKCS7_ATTR_SIGN_it:= LoadFunctionCLib('PKCS7_ATTR_SIGN_it');
			@PKCS7_ATTR_VERIFY_it:= LoadFunctionCLib('PKCS7_ATTR_VERIFY_it');
			@PKCS7_ctrl:= LoadFunctionCLib('PKCS7_ctrl');
			@PKCS7_set_type:= LoadFunctionCLib('PKCS7_set_type');
			@PKCS7_set0_type_other:= LoadFunctionCLib('PKCS7_set0_type_other');
			@PKCS7_set_content:= LoadFunctionCLib('PKCS7_set_content');
			@PKCS7_SIGNER_INFO_set:= LoadFunctionCLib('PKCS7_SIGNER_INFO_set');
			@PKCS7_SIGNER_INFO_sign:= LoadFunctionCLib('PKCS7_SIGNER_INFO_sign');
			@PKCS7_add_signer:= LoadFunctionCLib('PKCS7_add_signer');
			@PKCS7_add_certificate:= LoadFunctionCLib('PKCS7_add_certificate');
			@PKCS7_add_crl:= LoadFunctionCLib('PKCS7_add_crl');
			@PKCS7_content_new:= LoadFunctionCLib('PKCS7_content_new');
			@PKCS7_dataVerify:= LoadFunctionCLib('PKCS7_dataVerify');
			@PKCS7_signatureVerify:= LoadFunctionCLib('PKCS7_signatureVerify');
			@PKCS7_dataInit:= LoadFunctionCLib('PKCS7_dataInit');
			@PKCS7_dataFinal:= LoadFunctionCLib('PKCS7_dataFinal');
			@PKCS7_dataDecode:= LoadFunctionCLib('PKCS7_dataDecode');
			@PKCS7_add_signature:= LoadFunctionCLib('PKCS7_add_signature');
			@PKCS7_cert_from_signer_info:= LoadFunctionCLib('PKCS7_cert_from_signer_info');
			@PKCS7_set_digest:= LoadFunctionCLib('PKCS7_set_digest');
			@PKCS7_get_signer_info:= LoadFunctionCLib('PKCS7_get_signer_info');
			@PKCS7_add_recipient:= LoadFunctionCLib('PKCS7_add_recipient');
			@PKCS7_SIGNER_INFO_get0_algs:= LoadFunctionCLib('PKCS7_SIGNER_INFO_get0_algs');
			@PKCS7_RECIP_INFO_get0_alg:= LoadFunctionCLib('PKCS7_RECIP_INFO_get0_alg');
			@PKCS7_add_recipient_info:= LoadFunctionCLib('PKCS7_add_recipient_info');
			@PKCS7_RECIP_INFO_set:= LoadFunctionCLib('PKCS7_RECIP_INFO_set');
			@PKCS7_set_cipher:= LoadFunctionCLib('PKCS7_set_cipher');
			@PKCS7_get_issuer_and_serial:= LoadFunctionCLib('PKCS7_get_issuer_and_serial');
			@PKCS7_digest_from_attributes:= LoadFunctionCLib('PKCS7_digest_from_attributes');
			@PKCS7_add_signed_attribute:= LoadFunctionCLib('PKCS7_add_signed_attribute');
			@PKCS7_add_attribute := LoadFunctionCLib('PKCS7_add_attribute');
			@PKCS7_get_attribute:= LoadFunctionCLib('PKCS7_get_attribute');
			@PKCS7_get_signed_attribute:= LoadFunctionCLib('PKCS7_get_signed_attribute');
			@PKCS7_set_signed_attributes:= LoadFunctionCLib('PKCS7_set_signed_attributes');
			@PKCS7_set_attributes:= LoadFunctionCLib('PKCS7_set_attributes');
			@PKCS7_sign:= LoadFunctionCLib('PKCS7_sign');
			@PKCS7_sign_add_signer:= LoadFunctionCLib('PKCS7_sign_add_signer');
			@PKCS7_final:= LoadFunctionCLib('PKCS7_final');
			@PKCS7_verify:= LoadFunctionCLib('PKCS7_verify');
			@PKCS7_get0_signers:= LoadFunctionCLib('PKCS7_get0_signers');
			@PKCS7_encrypt:= LoadFunctionCLib('PKCS7_encrypt');
			@PKCS7_decrypt:= LoadFunctionCLib('PKCS7_decrypt');
			@PKCS7_add_attrib_smimecap:= LoadFunctionCLib('PKCS7_add_attrib_smimecap');
			@PKCS7_get_smimecap:= LoadFunctionCLib('PKCS7_get_smimecap');
			@PKCS7_simple_smimecap:= LoadFunctionCLib('PKCS7_simple_smimecap');
			@PKCS7_add_attrib_content_type:= LoadFunctionCLib('PKCS7_add_attrib_content_type');
			@PKCS7_add0_attrib_signing_time:= LoadFunctionCLib('PKCS7_add0_attrib_signing_time');
			@PKCS7_add1_attrib_digest:= LoadFunctionCLib('PKCS7_add1_attrib_digest');
			@SMIME_write_PKCS7:= LoadFunctionCLib('SMIME_write_PKCS7');
			@SMIME_read_PKCS7:= LoadFunctionCLib('SMIME_read_PKCS7');
			@BIO_new_PKCS7:= LoadFunctionCLib('BIO_new_PKCS7');
			@ERR_load_PKCS7_strings:= LoadFunctionCLib('ERR_load_PKCS7_strings');

		end;
end;
end.