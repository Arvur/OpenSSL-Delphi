unit ssl_cms;
interface
uses ssl_types;

var
	CMS_get0_type: function(_cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;

	CMS_dataInit: function(_cms: PCMS_ContentInfo; _icont: PBIO): PBIO; cdecl = nil;
	CMS_dataFinal: function(_cms: PCMS_ContentInfo; _bio: PBIO): TC_INT; cdecl = nil;

	CMS_get0_content: function(_cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl = nil;
	CMS_is_detached: function(_cms: PCMS_ContentInfo): TC_INT; cdecl = nil;
	CMS_set_detached: function(_cms: PCMS_ContentInfo; _detached: TC_INT): TC_INT; cdecl = nil;

  CMS_ContentInfo_new: function: PCMS_ContentInfo; cdecl = nil;
  CMS_ContentInfo_free: procedure(a: PCMS_ContentInfo); cdecl = nil;
  d2i_CMS_ContentInfo: function(a: PPCMS_ContentInfo; _in: PPAnsiChar; len: TC_LONG): PCMS_ContentInfo; cdecl = nil;
  i2d_CMS_ContentInfo: function(a: PCMS_ContentInfo; _out: PPAnsiChar): TC_INT; cdecl = nil;
  CMS_ContentInfo_it: function: PASN1_ITEM; cdecl = nil;
  CMS_ReceiptRequest_new: function: PCMS_ReceiptRequest; cdecl = nil;
  CMS_ReceiptRequest_free: procedure(a: PCMS_ReceiptRequest); cdecl = nil;
  d2i_CMS_ReceiptRequest: function(a: PPCMS_ReceiptRequest; _in: PPAnsiChar; len: TC_LONG): PCMS_ReceiptRequest; cdecl = nil;
  i2d_CMS_ReceiptRequest: function(a: PCMS_ReceiptRequest; _out: PPAnsiChar): TC_INT; cdecl = nil;
  CMS_ReceiptRequest_it: function: PASN1_ITEM; cdecl = nil;


	//CMS_stream: function(unsigned char ***boundary; _cms: PCMS_ContentInfo): TC_INT; cdecl = nil;
	d2i_CMS_bio: function(_bp: PBIO; _cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = nil;
	i2d_CMS_bio: function(_bp: PBIO; _cms: PCMS_ContentInfo): TC_INT; cdecl = nil;

	BIO_new_CMS: function(_out: PBIO; _cms: PCMS_ContentInfo): PBIO; cdecl = nil;
	i2d_CMS_bio_stream: function(_out: PBIO; _cms: PCMS_ContentInfo; _in: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	PEM_write_bio_CMS_stream: function(_out: PBIO; _cms: PCMS_ContentInfo; _in: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;
	SMIME_read_CMS: function(_bio: PBIO; _bcont: PPBIO): PCMS_ContentInfo; cdecl = nil;
	SMIME_write_CMS: function(_bio: PBIO; _cms: PCMS_ContentInfo; _data: PBIO; _flags: TC_INT): TC_INT; cdecl = nil;

	CMS_final: function(_cms: PCMS_ContentInfo; _data: PBIO; _dcont: PBIO; _flags: TC_UINT): TC_INT; cdecl = nil;

	CMS_sign: function(_signcert: PX509; _pkey: PEVP_PKEY;  _certs: PSTACK_OF_X509; _data: PBIO; _flags: TC_UINT): PCMS_ContentInfo; cdecl = nil;

	CMS_sign_receipt: function(_si: PCMS_SignerInfo; _signcert: PX509; _pkey: PEVP_PKEY; _certs: PSTACK_OF_X509; _flags: TC_UINT): PCMS_ContentInfo; cdecl = nil;

	CMS_data: function(_cms: PCMS_ContentInfo; _out: PBIO; _flags: TC_UINT): TC_INT; cdecl = nil;
	CMS_data_create: function(_in: PBIO; _flags: TC_UINT): PCMS_ContentInfo; cdecl = nil;

	CMS_digest_verify: function(_cms: PCMS_ContentInfo; _dcont: PBIO; _out: PBIO;flags: TC_INT): TC_INT; cdecl = nil;
	CMS_digest_create: function(_in: PBIO; const _md: PEVP_MD; flags: TC_INT): PCMS_ContentInfo; cdecl = nil;

	CMS_EncryptedData_decrypt: function(_cms: PCMS_ContentInfo;const _key: PAnsiChar; keylen: TC_SIZE_T;_dcont: PBIO; _out: PBIO; flags: TC_INT): TC_INT; cdecl = nil;

	CMS_EncryptedData_encrypt: function(_in: PBIO; const _cipher: PEVP_CIPHER;const _key: PAnsiChar; keylen: TC_SIZE_T; flags: TC_INT): PCMS_ContentInfo; cdecl = nil;

	CMS_EncryptedData_set1_key: function(_cms: PCMS_ContentInfo; const _ciph: PEVP_CIPHER;const _key: PAnsiChar; keylen: TC_SIZE_T): TC_INT; cdecl = nil;

	CMS_verify: function(_cms: PCMS_ContentInfo;  _certs: PSTACK_OF_X509;_store: PX509_STORE; _dcont: PBIO; _out: PBIO; flags: TC_INT): TC_INT; cdecl = nil;

	CMS_verify_receipt: function(_rcms: PCMS_ContentInfo; _ocms: PCMS_ContentInfo; _certs: PSTACK_OF_X509;_store: PX509_STORE; flags: TC_INT): TC_INT; cdecl = nil;

	CMS_get0_signers: function(_cms: PCMS_ContentInfo): PSTACK_OF_X509; cdecl = nil;

	CMS_encrypt: function( _certs: PSTACK_OF_X509; _in: PBIO;const _cipher: PEVP_CIPHER; flags: TC_INT): PCMS_ContentInfo; cdecl = nil;

	CMS_decrypt: function(_cms: PCMS_ContentInfo; _pkey: PEVP_PKEY; _cert: PX509;_dcont: PBIO; _out: PBIO;flags: TC_INT): TC_INT; cdecl = nil;
	
	CMS_decrypt_set1_pkey: function(_cms: PCMS_ContentInfo; _pk: PEVP_PKEY; _cert: PX509): TC_INT; cdecl = nil;
	CMS_decrypt_set1_key: function(_cms: PCMS_ContentInfo; _key: PAnsiChar; keylen: TC_SIZE_T; _id: PAnsiChar; idlen: TC_SIZE_T): TC_INT; cdecl = nil;
	CMS_decrypt_set1_password: function(_cms: PCMS_ContentInfo; _pass: PAnsiChar; passlen: TC_OSSL_SSIZE_T): TC_INT; cdecl = nil;

	CMS_get0_RecipientInfos: function(_cms: PCMS_ContentInfo): PSTACK_OF_CMS_RecipientInfo; cdecl = nil;
	CMS_RecipientInfo_type: function(_ri: PCMS_RecipientInfo): TC_INT; cdecl = nil;
	CMS_EnvelopedData_create: function(const _cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = nil;
	CMS_add1_recipient_cert: function(_cms: PCMS_ContentInfo;_recip: PX509; flags: TC_INT): PCMS_RecipientInfo; cdecl = nil;
	CMS_RecipientInfo_set0_pkey: function(_ri: PCMS_RecipientInfo; _pkey: PEVP_PKEY): TC_INT; cdecl = nil;
	CMS_RecipientInfo_ktri_cert_cmp: function(_ri: PCMS_RecipientInfo; _cert: PX509): TC_INT; cdecl = nil;
	CMS_RecipientInfo_ktri_get0_algs: function(_ri: PCMS_RecipientInfo; _pk: PPEVP_PKEY; _recip: PPX509;_palg: PPX509_ALGOR): TC_INT; cdecl = nil;
	CMS_RecipientInfo_ktri_get0_signer_id: function(_ri: PCMS_RecipientInfo; _keyid: PPASN1_OCTET_STRING; _issuer: PPX509_NAME; _sno: PPASN1_INTEGER): TC_INT; cdecl = nil;

	CMS_add0_recipient_key: function(_cms: PCMS_ContentInfo; _nid: TC_INT; _key: PAnsiChar; keylen: TC_SIZE_T; _id: PAnsiChar; idlen: TC_SIZE_T;_date: PASN1_GENERALIZEDTIME;_otherTypeId: PASN1_OBJECT;_otherType: PASN1_TYPE): PCMS_RecipientInfo; cdecl = nil;

	CMS_RecipientInfo_kekri_get0_id: function(_ri: PCMS_RecipientInfo;_palg: PPX509_ALGOR; _pid: PPASN1_OCTET_STRING; _pdate: PPASN1_GENERALIZEDTIME; _potherid: PPASN1_OBJECT; _pothertype: PPASN1_TYPE): TC_INT; cdecl = nil;

	CMS_RecipientInfo_set0_key: function(_ri: PCMS_RecipientInfo; _key: PAnsiChar; keylen: TC_SIZE_T): TC_INT; cdecl = nil;

	CMS_RecipientInfo_kekri_id_cmp: function(_ri: PCMS_RecipientInfo; const _id: PAnsiChar; idlen: TC_SIZE_T): TC_INT; cdecl = nil;

	CMS_RecipientInfo_set0_password: function(_ri: PCMS_RecipientInfo; _pass: PAnsiChar; passlen: TC_OSSL_SSIZE_T): TC_INT; cdecl = nil;

	CMS_add0_recipient_password: function(_cms: PCMS_ContentInfo;_iter: TC_INT; _wrap_nid: TC_INT; pbe_nid: TC_INT; _pass: PAnsiChar; passlen: TC_OSSL_SSIZE_T;const _kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl = nil;

	CMS_RecipientInfo_decrypt: function(_cms: PCMS_ContentInfo; _ri: PCMS_RecipientInfo): TC_INT; cdecl = nil;
	
	CMS_uncompress: function(_cms: PCMS_ContentInfo; _dcont: PBIO; _out: PBIO;flags: TC_INT): TC_INT; cdecl = nil;
	CMS_compress: function(_in: PBIO; _comp_nid: TC_INT; flags: TC_INT): PCMS_ContentInfo; cdecl = nil;

	CMS_set1_eContentType: function(_cms: PCMS_ContentInfo; const _oid: PASN1_OBJECT): TC_INT; cdecl = nil;
	CMS_get0_eContentType: function(_cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;

	CMS_add0_CertificateChoices: function(_cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl = nil;
	CMS_add0_cert: function(_cms: PCMS_ContentInfo; _cert: PX509): TC_INT; cdecl = nil;
	CMS_add1_cert: function(_cms: PCMS_ContentInfo; _cert: PX509): TC_INT; cdecl = nil;
	CMS_get1_certs: function(_cms: PCMS_ContentInfo): PSTACK_OF_X509; cdecl = nil;

	CMS_add0_RevocationInfoChoice: function(_cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl = nil;
	CMS_add0_crl: function(_cms: PCMS_ContentInfo; _crl: PX509_CRL): TC_INT; cdecl = nil;
	CMS_add1_crl: function(_cms: PCMS_ContentInfo; _crl: PX509_CRL): TC_INT; cdecl = nil;
	CMS_get1_crls: function(_cms: PCMS_ContentInfo): PSTACK_OF_X509_CRL; cdecl = nil;

	CMS_SignedData_init: function(_cms: PCMS_ContentInfo): TC_INT; cdecl = nil;
	CMS_add1_signer: function(_cms: PCMS_ContentInfo;_signer: PX509; _pk: PEVP_PKEY; const _md: PEVP_MD;flags: TC_INT): PCMS_SignerInfo; cdecl = nil;
	CMS_get0_SignerInfos: function(_cms: PCMS_ContentInfo): PSTACK_OF_CMS_SignerInfo; cdecl = nil;

	CMS_SignerInfo_set1_signer_cert: procedure(_si: PCMS_SignerInfo; _signer: PX509); cdecl = nil;
	CMS_SignerInfo_get0_signer_id: function(_si: PCMS_SignerInfo; _keyid: PPASN1_OCTET_STRING; _issuer: PPX509_NAME; _sno: PPASN1_INTEGER ): TC_INT; cdecl = nil;
	CMS_SignerInfo_cert_cmp: function(_si: PCMS_SignerInfo; _cert: PX509): TC_INT; cdecl = nil;
	CMS_set1_signers_certs: function(_cms: PCMS_ContentInfo;  _certs: PSTACK_OF_X509; flags: TC_INT): TC_INT; cdecl = nil;
	CMS_SignerInfo_get0_algs: procedure(_si: PCMS_SignerInfo; _pk: PPEVP_PKEY ; _signer: PPX509; _pdig: PPX509_ALGOR; _psig: PPX509_ALGOR ); cdecl = nil;
	CMS_SignerInfo_sign: function(_si: PCMS_SignerInfo): TC_INT; cdecl = nil;
	CMS_SignerInfo_verify: function(_si: PCMS_SignerInfo): TC_INT; cdecl = nil;
	CMS_SignerInfo_verify_content: function(_si: PCMS_SignerInfo; _chain: PBIO): TC_INT; cdecl = nil;

	CMS_add_smimecap: function(_si: PCMS_SignerInfo;  _algs: PSTACK_OF_X509_ALGOR): TC_INT; cdecl = nil;
	CMS_add_simple_smimecap: function( _algs: PPSTACK_OF_X509_ALGOR;_algnid: TC_INT; _keysize: TC_INT): TC_INT; cdecl = nil;
	CMS_add_standard_smimecap: function( _smcap: PPSTACK_OF_X509_ALGOR): TC_INT; cdecl = nil;

	CMS_signed_get_attr_count: function(const _si: PCMS_SignerInfo): TC_INT; cdecl = nil;
	CMS_signed_get_attr_by_NID: function(const _si: PCMS_SignerInfo; nid: TC_INT;lastpos: TC_INT): TC_INT; cdecl = nil;
	CMS_signed_get_attr_by_OBJ: function(const _si: PCMS_SignerInfo; _obj: PASN1_OBJECT;lastpos: TC_INT): TC_INT; cdecl = nil;
	CMS_signed_get_attr: function(const _si: PCMS_SignerInfo; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	CMS_signed_delete_attr: function(_si: PCMS_SignerInfo; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	CMS_signed_add1_attr: function(_si: PCMS_SignerInfo; _attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	CMS_signed_add1_attr_by_OBJ: function(_si: PCMS_SignerInfo;const _obj: PASN1_OBJECT; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_signed_add1_attr_by_NID: function(_si: PCMS_SignerInfo;_nid: TC_INT; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_signed_add1_attr_by_txt: function(_si: PCMS_SignerInfo;const _attrname: PAnsiChar; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_signed_get0_data_by_OBJ: function(_si: PCMS_SignerInfo; _oid: PASN1_OBJECT; _lastpos: TC_INT; _type: TC_INT): Pointer; cdecl = nil;

	CMS_unsigned_get_attr_count: function(const _si: PCMS_SignerInfo): TC_INT; cdecl = nil;
	CMS_unsigned_get_attr_by_NID: function(const _si: PCMS_SignerInfo; _nid: TC_INT; lastpos: TC_INT): TC_INT; cdecl = nil;
	CMS_unsigned_get_attr_by_OBJ: function(const _si: PCMS_SignerInfo; _obj: PASN1_OBJECT; lastpos: TC_INT): TC_INT; cdecl = nil;
	CMS_unsigned_get_attr: function(const _si: PCMS_SignerInfo; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	CMS_unsigned_delete_attr: function(_si: PCMS_SignerInfo; _loc: TC_INT): PX509_ATTRIBUTE; cdecl = nil;
	CMS_unsigned_add1_attr: function(_si: PCMS_SignerInfo; _attr: PX509_ATTRIBUTE): TC_INT; cdecl = nil;
	CMS_unsigned_add1_attr_by_OBJ: function(_si: PCMS_SignerInfo;const _obj: PASN1_OBJECT; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_unsigned_add1_attr_by_NID: function(_si: PCMS_SignerInfo;_nid: TC_INT; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_unsigned_add1_attr_by_txt: function(_si: PCMS_SignerInfo;const _attrname: PAnsiChar; _type: TC_INT;const bytes: Pointer; len: TC_INT): TC_INT; cdecl = nil;
	CMS_unsigned_get0_data_by_OBJ: function(_si: PCMS_SignerInfo; _oid: PASN1_OBJECT;_lastpos: TC_INT; _type: TC_INT): Pointer; cdecl = nil;

	CMS_get1_ReceiptRequest: function(_si: PCMS_SignerInfo; _prr: PPCMS_ReceiptRequest ): TC_INT; cdecl = nil;
	CMS_ReceiptRequest_create0: function(_id: PAnsiChar; _idlen: TC_INT;_allorfirst: TC_INT; _receiptList: PSTACK_OF_GENERAL_NAMES; _receiptsTo: PSTACK_OF_GENERAL_NAMES): PCMS_ReceiptRequest; cdecl = nil;
	CMS_add1_ReceiptRequest: function(_si: PCMS_SignerInfo; _rr: PCMS_ReceiptRequest): TC_INT; cdecl = nil;
	CMS_ReceiptRequest_get0_values: procedure(_rr: PPCMS_ReceiptRequest;_pcid: PPASN1_STRING ;var _pallorfirst: TC_INT;  _plist: PPSTACK_OF_GENERAL_NAMES;  _prto: PPSTACK_OF_GENERAL_NAMES); cdecl = nil;

	ERR_load_CMS_strings: procedure; cdecl = nil;
	
procedure SSL_InitCMS;
		
implementation
uses ssl_lib;


procedure SSL_InitCMS;
begin
 if @CMS_sign = nil then
	 begin
		 @CMS_get0_type:= LoadFunctionCLib('CMS_get0_type');
		 @CMS_dataInit:= LoadFunctionCLib('CMS_dataInit');
		 @CMS_dataFinal:= LoadFunctionCLib('CMS_dataFinal');
		 @CMS_get0_content:= LoadFunctionCLib('CMS_get0_content');
		 @CMS_is_detached:= LoadFunctionCLib('CMS_is_detached');
		 @CMS_set_detached:= LoadFunctionCLib('CMS_set_detached');
		 @d2i_CMS_bio:= LoadFunctionCLib('d2i_CMS_bio');
		 @i2d_CMS_bio:= LoadFunctionCLib('i2d_CMS_bio');
		 @BIO_new_CMS:= LoadFunctionCLib('BIO_new_CMS');
		 @i2d_CMS_bio_stream:= LoadFunctionCLib('i2d_CMS_bio_stream');
		 @PEM_write_bio_CMS_stream:= LoadFunctionCLib('PEM_write_bio_CMS_stream');
		 @SMIME_read_CMS:= LoadFunctionCLib('SMIME_read_CMS');
		 @SMIME_write_CMS:= LoadFunctionCLib('SMIME_write_CMS');
		 @CMS_final:= LoadFunctionCLib('CMS_final');
		 @CMS_sign:= LoadFunctionCLib('CMS_sign');
		 @CMS_sign_receipt:= LoadFunctionCLib('CMS_sign_receipt');
		 @CMS_data:= LoadFunctionCLib('CMS_data');
		 @CMS_data_create:= LoadFunctionCLib('CMS_data_create');
		 @CMS_digest_verify:= LoadFunctionCLib('CMS_digest_verify');
		 @CMS_digest_create:= LoadFunctionCLib('CMS_digest_create');
		 @CMS_EncryptedData_decrypt:= LoadFunctionCLib('CMS_EncryptedData_decrypt');
		 @CMS_EncryptedData_encrypt:= LoadFunctionCLib('CMS_EncryptedData_encrypt');
		 @CMS_EncryptedData_set1_key:= LoadFunctionCLib('CMS_EncryptedData_set1_key');
		 @CMS_verify:= LoadFunctionCLib('CMS_verify');
		 @CMS_verify_receipt:= LoadFunctionCLib('CMS_verify_receipt');
		 @CMS_get0_signers:= LoadFunctionCLib('CMS_get0_signers');
		 @CMS_encrypt:= LoadFunctionCLib('CMS_encrypt');
		 @CMS_decrypt:= LoadFunctionCLib('CMS_decrypt');
		 @CMS_decrypt_set1_pkey:= LoadFunctionCLib('CMS_decrypt_set1_pkey');
		 @CMS_decrypt_set1_key:= LoadFunctionCLib('CMS_decrypt_set1_key');
		 @CMS_decrypt_set1_password:= LoadFunctionCLib('CMS_decrypt_set1_password');
		 @CMS_get0_RecipientInfos:= LoadFunctionCLib('CMS_get0_RecipientInfos');
		 @CMS_RecipientInfo_type:= LoadFunctionCLib('CMS_RecipientInfo_type');
		 @CMS_EnvelopedData_create:= LoadFunctionCLib('CMS_EnvelopedData_create');
		 @CMS_add1_recipient_cert:= LoadFunctionCLib('CMS_add1_recipient_cert');
		 @CMS_RecipientInfo_set0_pkey:= LoadFunctionCLib('CMS_RecipientInfo_set0_pkey');
		 @CMS_RecipientInfo_ktri_cert_cmp:= LoadFunctionCLib('CMS_RecipientInfo_ktri_cert_cmp');
		 @CMS_RecipientInfo_ktri_get0_algs:= LoadFunctionCLib('CMS_RecipientInfo_ktri_get0_algs');
		 @CMS_RecipientInfo_ktri_get0_signer_id:= LoadFunctionCLib('CMS_RecipientInfo_ktri_get0_signer_id');
		 @CMS_add0_recipient_key:= LoadFunctionCLib('CMS_add0_recipient_key');
		 @CMS_RecipientInfo_kekri_get0_id:= LoadFunctionCLib('CMS_RecipientInfo_kekri_get0_id');
		 @CMS_RecipientInfo_set0_key:= LoadFunctionCLib('CMS_RecipientInfo_set0_key');
		 @CMS_RecipientInfo_kekri_id_cmp:= LoadFunctionCLib('CMS_RecipientInfo_kekri_id_cmp');
		 @CMS_RecipientInfo_set0_password:= LoadFunctionCLib('CMS_RecipientInfo_set0_password');
		 @CMS_add0_recipient_password:= LoadFunctionCLib('CMS_add0_recipient_password');
		 @CMS_RecipientInfo_decrypt:= LoadFunctionCLib('CMS_RecipientInfo_decrypt');
		 @CMS_uncompress:= LoadFunctionCLib('CMS_uncompress');
		 @CMS_compress:= LoadFunctionCLib('CMS_compress');
		 @CMS_set1_eContentType:= LoadFunctionCLib('CMS_set1_eContentType');
		 @CMS_get0_eContentType:= LoadFunctionCLib('CMS_get0_eContentType');
		 @CMS_add0_CertificateChoices:= LoadFunctionCLib('CMS_add0_CertificateChoices');
		 @CMS_add0_cert:= LoadFunctionCLib('CMS_add0_cert');
		 @CMS_add1_cert:= LoadFunctionCLib('CMS_add1_cert');
		 @CMS_get1_certs:= LoadFunctionCLib('CMS_get1_certs');
		 @CMS_add0_RevocationInfoChoice:= LoadFunctionCLib('CMS_add0_RevocationInfoChoice');
		 @CMS_add0_crl:= LoadFunctionCLib('CMS_add0_crl');
		 @CMS_add1_crl:= LoadFunctionCLib('CMS_add1_crl');
		 @CMS_get1_crls:= LoadFunctionCLib('CMS_get1_crls');
		 @CMS_SignedData_init:= LoadFunctionCLib('CMS_SignedData_init');
		 @CMS_add1_signer:= LoadFunctionCLib('CMS_add1_signer');
		 @CMS_get0_SignerInfos:= LoadFunctionCLib('CMS_get0_SignerInfos');
		 @CMS_SignerInfo_set1_signer_cert:= LoadFunctionCLib('CMS_SignerInfo_set1_signer_cert');
		 @CMS_SignerInfo_get0_signer_id:= LoadFunctionCLib('CMS_SignerInfo_get0_signer_id');
		 @CMS_SignerInfo_cert_cmp:= LoadFunctionCLib('CMS_SignerInfo_cert_cmp');
		 @CMS_set1_signers_certs:= LoadFunctionCLib('CMS_set1_signers_certs');
		 @CMS_SignerInfo_get0_algs:= LoadFunctionCLib('CMS_SignerInfo_get0_algs');
		 @CMS_SignerInfo_sign:= LoadFunctionCLib('CMS_SignerInfo_sign');
		 @CMS_SignerInfo_verify:= LoadFunctionCLib('CMS_SignerInfo_verify');
		 @CMS_SignerInfo_verify_content:= LoadFunctionCLib('CMS_SignerInfo_verify_content');
		 @CMS_add_smimecap:= LoadFunctionCLib('CMS_add_smimecap');
		 @CMS_add_simple_smimecap:= LoadFunctionCLib('CMS_add_simple_smimecap');
		 @CMS_add_standard_smimecap:= LoadFunctionCLib('CMS_add_standard_smimecap');
		 @CMS_signed_get_attr_count:= LoadFunctionCLib('CMS_signed_get_attr_count');
		 @CMS_signed_get_attr_by_NID:= LoadFunctionCLib('CMS_signed_get_attr_by_NID');
		 @CMS_signed_get_attr_by_OBJ:= LoadFunctionCLib('CMS_signed_get_attr_by_OBJ');
		 @CMS_signed_get_attr:= LoadFunctionCLib('CMS_signed_get_attr');
		 @CMS_signed_delete_attr:= LoadFunctionCLib('CMS_signed_delete_attr');
		 @CMS_signed_add1_attr:= LoadFunctionCLib('CMS_signed_add1_attr');
		 @CMS_signed_add1_attr_by_OBJ:= LoadFunctionCLib('CMS_signed_add1_attr_by_OBJ');
		 @CMS_signed_add1_attr_by_NID:= LoadFunctionCLib('CMS_signed_add1_attr_by_NID');
		 @CMS_signed_add1_attr_by_txt:= LoadFunctionCLib('CMS_signed_add1_attr_by_txt');
		 @CMS_signed_get0_data_by_OBJ:= LoadFunctionCLib('CMS_signed_get0_data_by_OBJ');
		 @CMS_unsigned_get_attr_count:= LoadFunctionCLib('CMS_unsigned_get_attr_count');
		 @CMS_unsigned_get_attr_by_NID:= LoadFunctionCLib('CMS_unsigned_get_attr_by_NID');
		 @CMS_unsigned_get_attr_by_OBJ:= LoadFunctionCLib('CMS_unsigned_get_attr_by_OBJ');
		 @CMS_unsigned_get_attr:= LoadFunctionCLib('CMS_unsigned_get_attr');
		 @CMS_unsigned_delete_attr:= LoadFunctionCLib('CMS_unsigned_delete_attr');
		 @CMS_unsigned_add1_attr:= LoadFunctionCLib('CMS_unsigned_add1_attr');
		 @CMS_unsigned_add1_attr_by_OBJ:= LoadFunctionCLib('CMS_unsigned_add1_attr_by_OBJ');
		 @CMS_unsigned_add1_attr_by_NID:= LoadFunctionCLib('CMS_unsigned_add1_attr_by_NID');
		 @CMS_unsigned_add1_attr_by_txt:= LoadFunctionCLib('CMS_unsigned_add1_attr_by_txt');
		 @CMS_unsigned_get0_data_by_OBJ:= LoadFunctionCLib('CMS_unsigned_get0_data_by_OBJ');
		 @CMS_get1_ReceiptRequest:= LoadFunctionCLib('CMS_get1_ReceiptRequest');
		 @CMS_ReceiptRequest_create0:= LoadFunctionCLib('CMS_ReceiptRequest_create0');
		 @CMS_add1_ReceiptRequest:= LoadFunctionCLib('CMS_add1_ReceiptRequest');
		 @CMS_ReceiptRequest_get0_values:= LoadFunctionCLib('CMS_ReceiptRequest_get0_values');
		 @ERR_load_CMS_strings:= LoadFunctionCLib('ERR_load_CMS_strings');
		 @CMS_ContentInfo_new:= LoadFunctionCLib('CMS_ContentInfo_new');
		 @CMS_ContentInfo_free:= LoadFunctionCLib('CMS_ContentInfo_free');
		 @d2i_CMS_ContentInfo:= LoadFunctionCLib('d2i_CMS_ContentInfo');
		 @i2d_CMS_ContentInfo:= LoadFunctionCLib('i2d_CMS_ContentInfo');
		 @CMS_ContentInfo_it:= LoadFunctionCLib('CMS_ContentInfo_it');
		 @CMS_ReceiptRequest_new:= LoadFunctionCLib('CMS_ReceiptRequest_new');
		 @CMS_ReceiptRequest_free:= LoadFunctionCLib('CMS_ReceiptRequest_free');
		 @d2i_CMS_ReceiptRequest:= LoadFunctionCLib('d2i_CMS_ReceiptRequest');
		 @i2d_CMS_ReceiptRequest:= LoadFunctionCLib('i2d_CMS_ReceiptRequest');
		 @CMS_ReceiptRequest_it:= LoadFunctionCLib('CMS_ReceiptRequest_it');
	 end;

end;

end.
