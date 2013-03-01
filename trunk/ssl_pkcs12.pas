unit ssl_pkcs12;
interface
uses ssl_types;
var
	
	PKCS12_x5092certbag: function(x509: PX509): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_x509crl2certbag: function(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_certbag2x509: function(bag: PPKCS12_SAFEBAG): PX509; cdecl = nil;
	PKCS12_certbag2x509crl: function(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl = nil;

	PKCS12_item_pack_safebag: function(obj: Pointer; const it: PASN1_ITEM; nid1: TC_INT;nid2: TC_INT): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_MAKE_KEYBAG: function(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS8_decrypt: function(p8: PX509_SIG; const pass: PAnsiChar; passlen: TC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
	PKCS12_decrypt_skey: function(bag: PPKCS12_SAFEBAG; const pass: PAnsiChar; passlen: TC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
	PKCS8_encrypt: function(pbe_nid: TC_INT; const cipher: PEVP_CIPHER;const pass: PAnsiChar; passlen: TC_INT;salt: PAnsiChar; saltlen: TC_INT; iter: TC_INT;p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl = nil;
	PKCS12_MAKE_SHKEYBAG: function(pbe_nid: TC_INT; const pass: PAnsiChar;passlen: TC_INT; salt: PAnsiChar;saltlen: TC_INT; iter: TC_INT;p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_pack_p7data: function(sk: PSTACK_OF_PKCS12_SAFEBAG): PPKCS7; cdecl = nil;
	PKCS12_unpack_p7data: function(p7: PPKCS7): PSTACK_OF_PKCS12_SAFEBAG; cdecl = nil;
	PKCS12_pack_p7encdata: function(pbe_nid: TC_INT; const pass: PAnsiChar; passlen: TC_INT;salt: PAnsiChar; saltlen: TC_INT; iter: TC_INT;bags: PSTACK_OF_PKCS12_SAFEBAG): PPKCS7; cdecl = nil;
	PKCS12_unpack_p7encdata: function(p7: PPKCS7; const pass: PAnsiChar; passlen: TC_INT): PSTACK_OF_PKCS12_SAFEBAG; cdecl = nil;

	PKCS12_pack_authsafes: function(p12: PPKCS12; safes: PSTACK_OF_PKCS7): TC_INT; cdecl = nil;
	PKCS12_unpack_authsafes: function(p12: PPKCS12): PSTACK_OF_PKCS7; cdecl = nil;

	PKCS12_add_localkeyid: function(bag: PPKCS12_SAFEBAG; _name: PAnsiChar; namelen: TC_INT): TC_INT; cdecl = nil;
	PKCS12_add_friendlyname_asc: function(bag: PPKCS12_SAFEBAG; const _name: PAnsiChar; namelen: TC_INT): TC_INT; cdecl = nil;
	PKCS12_add_CSPName_asc: function(bag: PPKCS12_SAFEBAG; const _name: PAnsiChar; namelen: TC_INT): TC_INT; cdecl = nil;
	PKCS12_add_friendlyname_uni: function(bag: PPKCS12_SAFEBAG; const _name: PAnsiChar; namelen: TC_INT): TC_INT; cdecl = nil;
	PKCS8_add_keyusage: function(p8: PPKCS8_PRIV_KEY_INFO; usage: TC_INT): TC_INT; cdecl = nil;
	PKCS12_get_attr_gen: function(attrs: PSTACK_OF_X509_ATTRIBUTE; attr_nid: TC_INT): PASN1_TYPE; cdecl = nil;
	PKCS12_get_friendlyname: function(bag: PPKCS12_SAFEBAG): PAnsiChar; cdecl = nil;
	PKCS12_pbe_crypt: function(_algor: PX509_ALGOR; const pass: PAnsiChar;_passlen: TC_INT; _in: PAnsiChar; _inlen: TC_INT; _data: PPAnsiChar; var _datalen: TC_INT; _en_de: TC_INT): PAnsiChar; cdecl = nil;
	PKCS12_item_decrypt_d2i: function(_algor: PX509_ALGOR; const _it: PASN1_ITEM;const pass: PAnsiChar; _passlen: TC_INT; _oct: PASN1_OCTET_STRING; _zbuf: TC_INT): Pointer; cdecl = nil;
	PKCS12_item_i2d_encrypt: function(_algor: PX509_ALGOR; const _it: PASN1_ITEM;const pass: PAnsiChar; _passlen: TC_INT;_obj: Pointer; _zbuf: TC_INT): PASN1_OCTET_STRING; cdecl = nil;
	PKCS12_init: function(_mode: TC_INT): PPKCS12; cdecl = nil;
	PKCS12_key_gen_asc: function(const pass: PAnsiChar; passlen: TC_INT; salt: PAnsiChar;saltlen: TC_INT; id: TC_INT; _iter: TC_INT; _n: TC_INT; _out: PAnsiChar; const _md_type: PEVP_MD): TC_INT; cdecl = nil;
	PKCS12_key_gen_uni: function(pass: PAnsiChar; _passlen: TC_INT; salt: PAnsiChar; _saltlen: TC_INT; _id: TC_INT; _iter: TC_INT; _n: TC_INT; _out: PAnsiChar; const _md_type: PEVP_MD): TC_INT; cdecl = nil;
	PKCS12_PBE_keyivgen: function(_ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; _passlen: TC_INT;_param: PASN1_TYPE; const cipher: PEVP_CIPHER; const _md_type: PEVP_MD;_en_de: TC_INT): TC_INT; cdecl = nil;
	PKCS12_gen_mac: function(_p12: PPKCS12; const pass: PAnsiChar; _passlen: TC_INT;_mac: PAnsiChar; var _maclen: TC_UINT): TC_INT; cdecl = nil;
	PKCS12_verify_mac: function(_p12: PPKCS12; const pass: PAnsiChar; _passlen: TC_INT): TC_INT; cdecl = nil;
	PKCS12_set_mac: function(_p12: PPKCS12; const pass: PAnsiChar; _passlen: TC_INT;salt: PAnsiChar; _saltlen: TC_INT; _iter: TC_INT;const _md_type: PEVP_MD): TC_INT; cdecl = nil;
	PKCS12_setup_mac: function(_p12: PPKCS12; _iter: TC_INT; salt: PAnsiChar;_saltlen: TC_INT; const _md_type: PEVP_MD): TC_INT; cdecl = nil;
	OPENSSL_asc2uni: function(const _asc: PAnsiChar; _asclen: TC_INT; _uni: PPAnsiChar; var _unilen: TC_INT): PAnsiChar; cdecl = nil;
	OPENSSL_uni2asc: function(_uni: PAnsiChar; _unilen: TC_INT): PAnsiChar; cdecl = nil;

	PKCS12_new: function: PPKCS12; cdecl = nil;
	PKCS12_free: procedure(a: PPKCS12); cdecl = nil;
	d2i_PKCS12: function(a: PPPKCS12; _in: PPAnsiChar; len: TC_LONG): PPKCS12; cdecl = nil;
	i2d_PKCS12: function(a: PPKCS12; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS12_it: function: PASN1_ITEM; cdecl = nil;
	PKCS12_MAC_DATA_new: function: PPKCS12_MAC_DATA; cdecl = nil;
	PKCS12_MAC_DATA_free: procedure(a: PPKCS12_MAC_DATA); cdecl = nil;
	d2i_PKCS12_MAC_DATA: function(a: PPPKCS12_MAC_DATA; _in: PPAnsiChar; len: TC_LONG): PPKCS12_MAC_DATA; cdecl = nil;
	i2d_PKCS12_MAC_DATA: function(a: PPKCS12_MAC_DATA; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS12_MAC_DATA_it: function: PASN1_ITEM; cdecl = nil;
	PKCS12_SAFEBAG_new: function: PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_SAFEBAG_free: procedure(a: PPKCS12_SAFEBAG); cdecl = nil;
	d2i_PKCS12_SAFEBAG: function(a: PPPKCS12_SAFEBAG; _in: PPAnsiChar; len: TC_LONG): PPKCS12_SAFEBAG; cdecl = nil;
	i2d_PKCS12_SAFEBAG: function(a: PPKCS12_SAFEBAG; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS12_SAFEBAG_it: function: PASN1_ITEM; cdecl = nil;
	PKCS12_BAGS_new: function: PPKCS12_BAGS; cdecl = nil;
	PKCS12_BAGS_free: procedure(a: PPKCS12_BAGS); cdecl = nil;
	d2i_PKCS12_BAGS: function(a: PPPKCS12_BAGS; _in: PPAnsiChar; len: TC_LONG): PPKCS12_BAGS; cdecl = nil;
	i2d_PKCS12_BAGS: function(a: PPKCS12_BAGS; _out: PPAnsiChar): TC_INT; cdecl = nil;
	PKCS12_BAGS_it: function: PASN1_ITEM; cdecl = nil;

	PKCS12_PBE_add: procedure; cdecl = nil;
	PKCS12_parse: function(_p12: PPKCS12; const pass: PAnsiChar; _pkey: PPEVP_PKEY; _cert: PPX509;ca: PPSTACK_OF_X509): TC_INT; cdecl = nil;
	PKCS12_create: function(pass: PAnsiChar; _name: PAnsiChar; _pkey: PEVP_PKEY; _cert: PX509;ca: PSTACK_OF_X509; _nid_key: TC_INT; _nid_cert: TC_INT; _iter: TC_INT;_mac_iter: TC_INT; _keytype: TC_INT): PPKCS12; cdecl = nil;

	PKCS12_add_cert: function(_pbags: PPSTACK_OF_PKCS12_SAFEBAG; _cert: PX509): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_add_key: function(_pbags: PPSTACK_OF_PKCS12_SAFEBAG; _key: PEVP_PKEY;_key_usage: TC_INT; _iter: TC_INT;_key_nid: TC_INT; pass: PAnsiChar): PPKCS12_SAFEBAG; cdecl = nil;
	PKCS12_add_safe: function(_psafes: PPSTACK_OF_PKCS7; _bags: PSTACK_OF_PKCS12_SAFEBAG;_safe_nid: TC_INT; _iter: TC_INT; pass: PAnsiChar): TC_INT; cdecl = nil;
	PKCS12_add_safes: function(_safes: PSTACK_OF_PKCS7; _p7_nid: TC_INT): PPKCS12; cdecl = nil;

	i2d_PKCS12_bio: function(_bp: PBIO; _p12: PPKCS12): TC_INT; cdecl = nil;
	d2i_PKCS12_bio: function(_bp: PBIO; _p12: PPPKCS12): PPKCS12; cdecl = nil;
	PKCS12_newpass: function(_p12: PPKCS12; _oldpass: PAnsiChar; _newpass: PAnsiChar): TC_INT; cdecl = nil;

	ERR_load_PKCS12_strings: procedure; cdecl = nil;

procedure SSL_InitPKCS12;

implementation
uses ssl_lib;

procedure SSL_InitPKCS12;
begin
	if @PKCS12_new = nil then
		begin
			@PKCS12_x5092certbag:= LoadFunctionCLib('PKCS12_x5092certbag');
			@PKCS12_x509crl2certbag:= LoadFunctionCLib('PKCS12_x509crl2certbag');
			@PKCS12_certbag2x509:= LoadFunctionCLib('PKCS12_certbag2x509');
			@PKCS12_certbag2x509crl:= LoadFunctionCLib('PKCS12_certbag2x509crl');
			@PKCS12_item_pack_safebag:= LoadFunctionCLib('PKCS12_item_pack_safebag');
			@PKCS12_MAKE_KEYBAG:= LoadFunctionCLib('PKCS12_MAKE_KEYBAG');
			@PKCS8_decrypt:= LoadFunctionCLib('PKCS8_decrypt');
			@PKCS12_decrypt_skey:= LoadFunctionCLib('PKCS12_decrypt_skey');
			@PKCS8_encrypt:= LoadFunctionCLib('PKCS8_encrypt');
			@PKCS12_MAKE_SHKEYBAG:= LoadFunctionCLib('PKCS12_MAKE_SHKEYBAG');
			@PKCS12_pack_p7data:= LoadFunctionCLib('PKCS12_pack_p7data');
			@PKCS12_unpack_p7data:= LoadFunctionCLib('PKCS12_unpack_p7data');
			@PKCS12_pack_p7encdata:= LoadFunctionCLib('PKCS12_pack_p7encdata');
			@PKCS12_unpack_p7encdata:= LoadFunctionCLib('PKCS12_unpack_p7encdata');
			@PKCS12_pack_authsafes:= LoadFunctionCLib('PKCS12_pack_authsafes');
			@PKCS12_unpack_authsafes:= LoadFunctionCLib('PKCS12_unpack_authsafes');
			@PKCS12_add_localkeyid:= LoadFunctionCLib('PKCS12_add_localkeyid');
			@PKCS12_add_friendlyname_asc:= LoadFunctionCLib('PKCS12_add_friendlyname_asc');
			@PKCS12_add_CSPName_asc:= LoadFunctionCLib('PKCS12_add_CSPName_asc');
			@PKCS12_add_friendlyname_uni:= LoadFunctionCLib('PKCS12_add_friendlyname_uni');
			@PKCS8_add_keyusage:= LoadFunctionCLib('PKCS8_add_keyusage');
			@PKCS12_get_attr_gen:= LoadFunctionCLib('PKCS12_get_attr_gen');
			@PKCS12_get_friendlyname:= LoadFunctionCLib('PKCS12_get_friendlyname');
			@PKCS12_pbe_crypt:= LoadFunctionCLib('PKCS12_pbe_crypt');
			@PKCS12_item_decrypt_d2i:= LoadFunctionCLib('PKCS12_item_decrypt_d2i');
			@PKCS12_item_i2d_encrypt:= LoadFunctionCLib('PKCS12_item_i2d_encrypt');
			@PKCS12_init:= LoadFunctionCLib('PKCS12_init');
			@PKCS12_key_gen_asc:= LoadFunctionCLib('PKCS12_key_gen_asc');
			@PKCS12_key_gen_uni:= LoadFunctionCLib('PKCS12_key_gen_uni');
			@PKCS12_PBE_keyivgen:= LoadFunctionCLib('PKCS12_PBE_keyivgen');
			@PKCS12_gen_mac:= LoadFunctionCLib('PKCS12_gen_mac');
			@PKCS12_verify_mac:= LoadFunctionCLib('PKCS12_verify_mac');
			@PKCS12_set_mac:= LoadFunctionCLib('PKCS12_set_mac');
			@PKCS12_setup_mac:= LoadFunctionCLib('PKCS12_setup_mac');
			@OPENSSL_asc2uni:= LoadFunctionCLib('OPENSSL_asc2uni');
			@OPENSSL_uni2asc:= LoadFunctionCLib('OPENSSL_uni2asc');
			@PKCS12_new:= LoadFunctionCLib('PKCS12_new');
			@PKCS12_free:= LoadFunctionCLib('PKCS12_free');
			@d2i_PKCS12:= LoadFunctionCLib('d2i_PKCS12');
			@i2d_PKCS12:= LoadFunctionCLib('i2d_PKCS12');
			@PKCS12_it:= LoadFunctionCLib('PKCS12_it');
			@PKCS12_MAC_DATA_new:= LoadFunctionCLib('PKCS12_MAC_DATA_new');
			@PKCS12_MAC_DATA_free:= LoadFunctionCLib('PKCS12_MAC_DATA_free');
			@d2i_PKCS12_MAC_DATA:= LoadFunctionCLib('d2i_PKCS12_MAC_DATA');
			@i2d_PKCS12_MAC_DATA:= LoadFunctionCLib('i2d_PKCS12_MAC_DATA');
			@PKCS12_MAC_DATA_it:= LoadFunctionCLib('PKCS12_MAC_DATA_it');
			@PKCS12_SAFEBAG_new:= LoadFunctionCLib('PKCS12_SAFEBAG_new');
			@PKCS12_SAFEBAG_free:= LoadFunctionCLib('PKCS12_SAFEBAG_free');
			@d2i_PKCS12_SAFEBAG:= LoadFunctionCLib('d2i_PKCS12_SAFEBAG');
			@i2d_PKCS12_SAFEBAG:= LoadFunctionCLib('i2d_PKCS12_SAFEBAG');
			@PKCS12_SAFEBAG_it:= LoadFunctionCLib('PKCS12_SAFEBAG_it');
			@PKCS12_BAGS_new:= LoadFunctionCLib('PKCS12_BAGS_new');
			@PKCS12_BAGS_free:= LoadFunctionCLib('PKCS12_BAGS_free');
			@d2i_PKCS12_BAGS:= LoadFunctionCLib('d2i_PKCS12_BAGS');
			@i2d_PKCS12_BAGS:= LoadFunctionCLib('i2d_PKCS12_BAGS');
			@PKCS12_BAGS_it:= LoadFunctionCLib('PKCS12_BAGS_it');
			@PKCS12_PBE_add:= LoadFunctionCLib('PKCS12_PBE_add');
			@PKCS12_parse:= LoadFunctionCLib('PKCS12_parse');
			@PKCS12_create:= LoadFunctionCLib('PKCS12_create');
			@PKCS12_add_cert:= LoadFunctionCLib('PKCS12_add_cert');
			@PKCS12_add_key:= LoadFunctionCLib('PKCS12_add_key');
			@PKCS12_add_safe:= LoadFunctionCLib('PKCS12_add_safe');
			@PKCS12_add_safes:= LoadFunctionCLib('PKCS12_add_safes');
			@i2d_PKCS12_bio:= LoadFunctionCLib('i2d_PKCS12_bio');
			@d2i_PKCS12_bio:= LoadFunctionCLib('d2i_PKCS12_bio');
			@PKCS12_newpass:= LoadFunctionCLib('PKCS12_newpass');
			@ERR_load_PKCS12_strings:= LoadFunctionCLib('ERR_load_PKCS12_strings');

		end;
end;

end.
