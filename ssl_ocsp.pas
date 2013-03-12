unit ssl_ocsp;

interface
uses ssl_types;

var
    OCSP_CERTID_dup: function(_id: POCSP_CERTID): POCSP_CERTID; cdecl = nil;

    OCSP_sendreq_bio: function(_b: PBIO; _path: PAnsiChar; _req: POCSP_REQUEST): POCSP_RESPONSE; cdecl = nil;
    OCSP_sendreq_new: function(_io: PBIO; _path: PAnsiChar; _req: POCSP_REQUEST; _maxline: TC_INT): POCSP_REQ_CTX; cdecl = nil;								
    OCSP_sendreq_nbio: function(_presp: PPOCSP_RESPONSE; _rctx: PPOCSP_REQ_CTX): TC_INT; cdecl = nil;
    OCSP_REQ_CTX_free: procedure(_rctx: POCSP_REQ_CTX); cdecl = nil;
    OCSP_REQ_CTX_set1_req: function(_rctx: POCSP_REQ_CTX; _req: POCSP_REQUEST): TC_INT; cdecl = nil;
    OCSP_REQ_CTX_add1_header: function(_rctx: POCSP_REQ_CTX;const _name: PAnsiChar; const _value: PAnsiChar): TC_INT; cdecl = nil;

    OCSP_cert_to_id: function(const _dgst: PEVP_MD; _subject: PX509; _issuer: PX509): POCSP_CERTID; cdecl = nil;

    OCSP_cert_id_new: function(const _dgst: PEVP_MD; _issuerName: PX509_NAME; _issuerKey: PASN1_BIT_STRING; _serialNumber: PASN1_INTEGER): POCSP_CERTID; cdecl = nil;

    OCSP_request_add0_id: function(_req: POCSP_REQUEST; _cid: POCSP_CERTID): POCSP_ONEREQ; cdecl = nil;

    OCSP_request_add1_nonce: function(_req: POCSP_REQUEST; _val: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
    OCSP_basic_add1_nonce: function(_resp: POCSP_BASICRESP; _val: PAnsiChar; _len: TC_INT): TC_INT; cdecl = nil;
    OCSP_check_nonce: function(_req: POCSP_REQUEST; _bs: POCSP_BASICRESP): TC_INT; cdecl = nil;
    OCSP_copy_nonce: function(_resp: POCSP_BASICRESP; _req: POCSP_REQUEST): TC_INT; cdecl = nil;

    OCSP_request_set1_name: function(_req: POCSP_REQUEST; _nm: PX509_NAME): TC_INT; cdecl = nil;
    OCSP_request_add1_cert: function(_req: POCSP_REQUEST; _cert: PX509): TC_INT; cdecl = nil;

    OCSP_request_sign: function(_req: POCSP_REQUEST;_signer: PX509; _key: PEVP_PKEY; const _dgst: PEVP_MD; _certs: PSTACK_OF_X509; _flags: TC_ULONG): TC_INT; cdecl = nil;

    OCSP_response_status: function(_resp: POCSP_RESPONSE): TC_INT; cdecl = nil;
    OCSP_response_get1_basic: function(_resp: POCSP_RESPONSE): POCSP_BASICRESP; cdecl = nil;

    OCSP_resp_count: function(_bs: POCSP_BASICRESP): TC_INT; cdecl = nil;
    OCSP_resp_get0: function(_bs: POCSP_BASICRESP; _idx: TC_INT): POCSP_SINGLERESP; cdecl = nil;
    OCSP_resp_find: function(_bs: POCSP_BASICRESP; _id: POCSP_CERTID; _last: TC_INT): TC_INT; cdecl = nil;
    OCSP_single_get0_status: function(_single: POCSP_SINGLERESP; var _reason: TC_INT;_revtime: PPASN1_GENERALIZEDTIME ; _thisupd: PPASN1_GENERALIZEDTIME; _nextupd: PPASN1_GENERALIZEDTIME ): TC_INT; cdecl = nil;
    OCSP_resp_find_status: function(_bs: POCSP_BASICRESP; _id: POCSP_CERTID; var _status: TC_INT; var _reason: TC_INT; _revtime: PPASN1_GENERALIZEDTIME; _thisupd: PPASN1_GENERALIZEDTIME; _nextupd: PPASN1_GENERALIZEDTIME ): TC_INT; cdecl = nil;
    OCSP_check_validity: function(_thisupd: PASN1_GENERALIZEDTIME; _nextupd: PASN1_GENERALIZEDTIME;_sec: TC_LONG; _maxsec: TC_LONG): TC_INT; cdecl = nil;

    OCSP_request_verify: function(_req: POCSP_REQUEST; _certs: PSTACK_OF_X509; _store: PX509_STORE; _flags: TC_LONG): TC_INT; cdecl = nil;

    OCSP_parse_url: function(_url: PAnsiChar; _phost: PPAnsiChar; _pport: PPAnsiChar; _ppath: PPAnsiChar; var _pssl: TC_INT): TC_INT; cdecl = nil;

    OCSP_id_issuer_cmp: function(_a: POCSP_CERTID; _b: POCSP_CERTID): TC_INT; cdecl = nil;
    OCSP_id_cmp: function(_a: POCSP_CERTID; _b: POCSP_CERTID): TC_INT; cdecl = nil;

    OCSP_request_onereq_count: function(_req: POCSP_REQUEST): TC_INT; cdecl = nil;
    OCSP_request_onereq_get0: function(_req: POCSP_REQUEST; _i: TC_INT): POCSP_ONEREQ; cdecl = nil;
    OCSP_onereq_get0_id: function(_one: POCSP_ONEREQ): POCSP_CERTID; cdecl = nil;
    OCSP_id_get0_info: function(_piNameHash: PPASN1_OCTET_STRING; _pmd: PPASN1_OBJECT; _pikeyHash: PPASN1_OCTET_STRING; _pserial: PPASN1_INTEGER; _cid: POCSP_CERTID): TC_INT; cdecl = nil;
    OCSP_request_is_signed: function(req: POCSP_REQUEST): TC_INT; cdecl = nil;
    OCSP_response_create: function(_status: TC_INT; _bs: POCSP_BASICRESP): POCSP_RESPONSE; cdecl = nil;
    OCSP_basic_add1_status: function(_rsp: POCSP_BASICRESP; _cid: POCSP_CERTID; _status: TC_INT; _reason: TC_INT; _revtime: PASN1_TIME; _thisupd: PASN1_TIME; _nextupd: PASN1_TIME): POCSP_SINGLERESP; cdecl = nil;
    OCSP_basic_add1_cert: function(_resp: POCSP_BASICRESP; _cert: PX509): TC_INT; cdecl = nil;
    OCSP_basic_sign: function(_brsp: POCSP_BASICRESP; _signer: PX509; _key: PEVP_PKEY; const _dgst: PEVP_MD; _certs: PSTACK_OF_X509; _flags: TC_ULONG): TC_INT; cdecl = nil;

    OCSP_crlID_new: function(_url: PAnsiChar; var _n: TC_LONG; _tim: PAnsiChar): PX509_EXTENSION; cdecl = nil;

    OCSP_accept_responses_new: function(_oids: PPAnsiChar): PX509_EXTENSION; cdecl = nil;

    OCSP_archive_cutoff_new: function(_tim : PAnsiChar): PX509_EXTENSION; cdecl = nil;

    OCSP_url_svcloc_new: function(_issuer: PX509_NAME; _urls: PPAnsiChar): PX509_EXTENSION; cdecl = nil;

    OCSP_REQUEST_get_ext_count: function(_x: POCSP_REQUEST): TC_INT; cdecl = nil;
    OCSP_REQUEST_get_ext_by_NID: function(_x: POCSP_REQUEST; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_REQUEST_get_ext_by_OBJ: function(_x: POCSP_REQUEST; _obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_REQUEST_get_ext_by_critical: function(_x: POCSP_REQUEST; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_REQUEST_get_ext: function(_x: POCSP_REQUEST; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_REQUEST_delete_ext: function(_x: POCSP_REQUEST; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_REQUEST_get1_ext_d2i: function(_x: POCSP_REQUEST; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
    OCSP_REQUEST_add1_ext_i2d: function(_x: POCSP_REQUEST; _nid: TC_INT; _value: Pointer; _crit: TC_INT; _flags: TC_ULONG): TC_INT; cdecl = nil;
    OCSP_REQUEST_add_ext: function(_x: POCSP_REQUEST; _ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;

    OCSP_ONEREQ_get_ext_count: function(_x: POCSP_ONEREQ): TC_INT; cdecl = nil;
    OCSP_ONEREQ_get_ext_by_NID: function(_x: POCSP_ONEREQ; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_ONEREQ_get_ext_by_OBJ: function(_x: POCSP_ONEREQ; _obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_ONEREQ_get_ext_by_critical: function(_x: POCSP_ONEREQ; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_ONEREQ_get_ext: function(_x: POCSP_ONEREQ; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_ONEREQ_delete_ext: function(_x: POCSP_ONEREQ; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_ONEREQ_get1_ext_d2i: function(_x: POCSP_ONEREQ; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
    OCSP_ONEREQ_add1_ext_i2d: function(_x: POCSP_ONEREQ; _nid: TC_INT; _value: Pointer; _crit: TC_INT; _flags: TC_LONG): TC_INT; cdecl = nil;
    OCSP_ONEREQ_add_ext: function(_x: POCSP_ONEREQ; _ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;

    OCSP_BASICRESP_get_ext_count: function(_x: POCSP_BASICRESP): TC_INT; cdecl = nil;
    OCSP_BASICRESP_get_ext_by_NID: function(_x: POCSP_BASICRESP; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_BASICRESP_get_ext_by_OBJ: function(_x: POCSP_BASICRESP; _obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_BASICRESP_get_ext_by_critical: function(_x: POCSP_BASICRESP; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_BASICRESP_get_ext: function(_x: POCSP_BASICRESP; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_BASICRESP_delete_ext: function(_x: POCSP_BASICRESP; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_BASICRESP_get1_ext_d2i: function(_x: POCSP_BASICRESP; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
    OCSP_BASICRESP_add1_ext_i2d: function(_x: POCSP_BASICRESP; _nid: TC_INT; _value: Pointer; _crit: TC_INT; _flags: TC_LONG): TC_INT; cdecl = nil;
    OCSP_BASICRESP_add_ext: function(_x: POCSP_BASICRESP; _ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;

    OCSP_SINGLERESP_get_ext_count: function(_x: POCSP_SINGLERESP): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_get_ext_by_NID: function(_x: POCSP_SINGLERESP; _nid: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_get_ext_by_OBJ: function(_x: POCSP_SINGLERESP; _obj: PASN1_OBJECT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_get_ext_by_critical: function(_x: POCSP_SINGLERESP; _crit: TC_INT; _lastpos: TC_INT): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_get_ext: function(_x: POCSP_SINGLERESP; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_SINGLERESP_delete_ext: function(_x: POCSP_SINGLERESP; _loc: TC_INT): PX509_EXTENSION; cdecl = nil;
    OCSP_SINGLERESP_get1_ext_d2i: function(_x: POCSP_SINGLERESP; _nid: TC_INT; var _crit: TC_INT; var _idx: TC_INT): Pointer; cdecl = nil;
    OCSP_SINGLERESP_add1_ext_i2d: function(_x: POCSP_SINGLERESP; _nid: TC_INT; _value: Pointer; _crit: TC_INT; _flags: TC_LONG): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_add_ext: function(_x: POCSP_SINGLERESP; _ex: PX509_EXTENSION; _loc: TC_INT): TC_INT; cdecl = nil;

    OCSP_SINGLERESP_new: function: POCSP_SINGLERESP; cdecl = nil;
    OCSP_SINGLERESP_free: procedure(a: POCSP_SINGLERESP); cdecl = nil;
    d2i_OCSP_SINGLERESP: function(a: PPOCSP_SINGLERESP; _in: PPAnsiChar; len: TC_LONG): POCSP_SINGLERESP; cdecl = nil;
    i2d_OCSP_SINGLERESP: function(a: POCSP_SINGLERESP; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_SINGLERESP_it: function: PASN1_ITEM; cdecl = nil;

    OCSP_CERTSTATUS_new: function: POCSP_CERTSTATUS; cdecl = nil;
    OCSP_CERTSTATUS_free: procedure(a: POCSP_CERTSTATUS); cdecl = nil;
    d2i_OCSP_CERTSTATUS: function(a: PPOCSP_CERTSTATUS; _in: PPAnsiChar; len: TC_LONG): POCSP_CERTSTATUS; cdecl = nil;
    i2d_OCSP_CERTSTATUS: function(a: POCSP_CERTSTATUS; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_CERTSTATUS_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_REVOKEDINFO_new: function: POCSP_REVOKEDINFO; cdecl = nil;
    OCSP_REVOKEDINFO_free: procedure(a: POCSP_REVOKEDINFO); cdecl = nil;
    d2i_OCSP_REVOKEDINFO: function(a: PPOCSP_REVOKEDINFO; _in: PPAnsiChar; len: TC_LONG): POCSP_REVOKEDINFO; cdecl = nil;
    i2d_OCSP_REVOKEDINFO: function(a: POCSP_REVOKEDINFO; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_REVOKEDINFO_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_BASICRESP_new: function: POCSP_BASICRESP; cdecl = nil;
    OCSP_BASICRESP_free: procedure(a: POCSP_BASICRESP); cdecl = nil;
    d2i_OCSP_BASICRESP: function(a: PPOCSP_BASICRESP; _in: PPAnsiChar; len: TC_LONG): POCSP_BASICRESP; cdecl = nil;
    i2d_OCSP_BASICRESP: function(a: POCSP_BASICRESP; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_BASICRESP_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_RESPDATA_new: function: POCSP_RESPDATA; cdecl = nil;
    OCSP_RESPDATA_free: procedure(a: POCSP_RESPDATA); cdecl = nil;
    d2i_OCSP_RESPDATA: function(a: PPOCSP_RESPDATA; _in: PPAnsiChar; len: TC_LONG): POCSP_RESPDATA; cdecl = nil;
    i2d_OCSP_RESPDATA: function(a: POCSP_RESPDATA; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_RESPDATA_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_RESPID_new: function: POCSP_RESPID; cdecl = nil;
    OCSP_RESPID_free: procedure(a: POCSP_RESPID); cdecl = nil;
    d2i_OCSP_RESPID: function(a: PPOCSP_RESPID; _in: PPAnsiChar; len: TC_LONG): POCSP_RESPID; cdecl = nil;
    i2d_OCSP_RESPID: function(a: POCSP_RESPID; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_RESPID_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_RESPONSE_new: function: POCSP_RESPONSE; cdecl = nil;
    OCSP_RESPONSE_free: procedure(a: POCSP_RESPONSE); cdecl = nil;
    d2i_OCSP_RESPONSE: function(a: PPOCSP_RESPONSE; _in: PPAnsiChar; len: TC_LONG): POCSP_RESPONSE; cdecl = nil;
    i2d_OCSP_RESPONSE: function(a: POCSP_RESPONSE; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_RESPONSE_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_RESPBYTES_new: function: POCSP_RESPBYTES; cdecl = nil;
    OCSP_RESPBYTES_free: procedure(a: POCSP_RESPBYTES); cdecl = nil;
    d2i_OCSP_RESPBYTES: function(a: PPOCSP_RESPBYTES; _in: PPAnsiChar; len: TC_LONG): POCSP_RESPBYTES; cdecl = nil;
    i2d_OCSP_RESPBYTES: function(a: POCSP_RESPBYTES; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_RESPBYTES_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_ONEREQ_new: function: POCSP_ONEREQ; cdecl = nil;
    OCSP_ONEREQ_free: procedure(a: POCSP_ONEREQ); cdecl = nil;
    d2i_OCSP_ONEREQ: function(a: PPOCSP_ONEREQ; _in: PPAnsiChar; len: TC_LONG): POCSP_ONEREQ; cdecl = nil;
    i2d_OCSP_ONEREQ: function(a: POCSP_ONEREQ; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_ONEREQ_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_CERTID_new: function: POCSP_CERTID; cdecl = nil;
    OCSP_CERTID_free: procedure(a: POCSP_CERTID); cdecl = nil;
    d2i_OCSP_CERTID: function(a: PPOCSP_CERTID; _in: PPAnsiChar; len: TC_LONG): POCSP_CERTID; cdecl = nil;
    i2d_OCSP_CERTID: function(a: POCSP_CERTID; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_CERTID_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_REQUEST_new: function: POCSP_REQUEST; cdecl = nil;
    OCSP_REQUEST_free: procedure(a: POCSP_REQUEST); cdecl = nil;
    d2i_OCSP_REQUEST: function(a: PPOCSP_REQUEST; _in: PPAnsiChar; len: TC_LONG): POCSP_REQUEST; cdecl = nil;
    i2d_OCSP_REQUEST: function(a: POCSP_REQUEST; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_REQUEST_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_SIGNATURE_new: function: POCSP_SIGNATURE; cdecl = nil;
    OCSP_SIGNATURE_free: procedure(a: POCSP_SIGNATURE); cdecl = nil;
    d2i_OCSP_SIGNATURE: function(a: PPOCSP_SIGNATURE; _in: PPAnsiChar; len: TC_LONG): POCSP_SIGNATURE; cdecl = nil;
    i2d_OCSP_SIGNATURE: function(a: POCSP_SIGNATURE; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_SIGNATURE_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_REQINFO_new: function: POCSP_REQINFO; cdecl = nil;
    OCSP_REQINFO_free: procedure(a: POCSP_REQINFO); cdecl = nil;
    d2i_OCSP_REQINFO: function(a: PPOCSP_REQINFO; _in: PPAnsiChar; len: TC_LONG): POCSP_REQINFO; cdecl = nil;
    i2d_OCSP_REQINFO: function(a: POCSP_REQINFO; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_REQINFO_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_CRLID_new_a: function: PASN1_ITEM; cdecl = nil;
    OCSP_CRLID_free: procedure(a: POCSP_CRLID); cdecl = nil;
    d2i_OCSP_CRLID: function(a: PPOCSP_CRLID; _in: PPAnsiChar; len: TC_LONG): POCSP_CRLID; cdecl = nil;
    i2d_OCSP_CRLID: function(a: POCSP_CRLID; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_CRLID_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_SERVICELOC_new: function: POCSP_SERVICELOC; cdecl = nil;
    OCSP_SERVICELOC_free: procedure(a: POCSP_SERVICELOC); cdecl = nil;
    d2i_OCSP_SERVICELOC: function(a: PPOCSP_SERVICELOC; _in: PPAnsiChar; len: TC_LONG): POCSP_SERVICELOC; cdecl = nil;
    i2d_OCSP_SERVICELOC: function(a: POCSP_SERVICELOC; _out: PPAnsiChar): TC_INT; cdecl = nil;
    OCSP_SERVICELOC_it: function: PASN1_ITEM; cdecl = nil;
    OCSP_response_status_str: function(_s: TC_LONG): PAnsiChar; cdecl = nil;
    OCSP_cert_status_str: function(_s: TC_LONG): PAnsiChar; cdecl = nil;
    OCSP_crl_reason_str: function(_s: TC_LONG): PAnsiChar; cdecl = nil;

    OCSP_REQUEST_print: function(_bp: PBIO; _a: POCSP_REQUEST; _flags: TC_LONG): TC_INT; cdecl = nil;
    OCSP_RESPONSE_print: function(_bp: PBIO; _o: POCSP_RESPONSE; _flags: TC_LONG): TC_INT; cdecl = nil;

    OCSP_basic_verify: function(_bs: POCSP_BASICRESP; _certs: PSTACK_OF_X509; _st: PX509_STORE; _flags: TC_LONG): TC_INT; cdecl = nil;

    ERR_load_OCSP_strings: procedure; cdecl = nil;


procedure SSL_InitOCSP;

implementation
uses ssl_lib;

procedure SSL_InitOCSP;
begin
     if @OCSP_CERTID_dup = nil then
     begin
        @OCSP_CERTID_dup:= LoadFunctionCLib('OCSP_CERTID_dup');
        @OCSP_sendreq_bio:= LoadFunctionCLib('OCSP_sendreq_bio');
        @OCSP_sendreq_new:= LoadFunctionCLib('OCSP_sendreq_new');
        @OCSP_sendreq_nbio:= LoadFunctionCLib('OCSP_sendreq_nbio');
        @OCSP_REQ_CTX_free:= LoadFunctionCLib('OCSP_REQ_CTX_free');
        @OCSP_REQ_CTX_set1_req:= LoadFunctionCLib('OCSP_REQ_CTX_set1_req');
        @OCSP_REQ_CTX_add1_header:= LoadFunctionCLib('OCSP_REQ_CTX_add1_header');
        @OCSP_cert_to_id:= LoadFunctionCLib('OCSP_cert_to_id');
        @OCSP_cert_id_new:= LoadFunctionCLib('OCSP_cert_id_new');
        @OCSP_request_add0_id:= LoadFunctionCLib('OCSP_request_add0_id');
        @OCSP_request_add1_nonce:= LoadFunctionCLib('OCSP_request_add1_nonce');
        @OCSP_basic_add1_nonce:= LoadFunctionCLib('OCSP_basic_add1_nonce');
        @OCSP_check_nonce:= LoadFunctionCLib('OCSP_check_nonce');
        @OCSP_copy_nonce:= LoadFunctionCLib('OCSP_copy_nonce');
        @OCSP_request_set1_name:= LoadFunctionCLib('OCSP_request_set1_name');
        @OCSP_request_add1_cert:= LoadFunctionCLib('OCSP_request_add1_cert');
        @OCSP_request_sign:= LoadFunctionCLib('OCSP_request_sign');
        @OCSP_response_status:= LoadFunctionCLib('OCSP_response_status');
        @OCSP_response_get1_basic:= LoadFunctionCLib('OCSP_response_get1_basic');
        @OCSP_resp_count:= LoadFunctionCLib('OCSP_resp_count');
        @OCSP_resp_get0:= LoadFunctionCLib('OCSP_resp_get0');
        @OCSP_resp_find:= LoadFunctionCLib('OCSP_resp_find');
        @OCSP_single_get0_status:= LoadFunctionCLib('OCSP_single_get0_status');
        @OCSP_resp_find_status:= LoadFunctionCLib('OCSP_resp_find_status');
        @OCSP_check_validity:= LoadFunctionCLib('OCSP_check_validity');
        @OCSP_request_verify:= LoadFunctionCLib('OCSP_request_verify');
        @OCSP_parse_url:= LoadFunctionCLib('OCSP_parse_url');
        @OCSP_id_issuer_cmp:= LoadFunctionCLib('OCSP_id_issuer_cmp');
        @OCSP_id_cmp:= LoadFunctionCLib('OCSP_id_cmp');
        @OCSP_request_onereq_count:= LoadFunctionCLib('OCSP_request_onereq_count');
        @OCSP_request_onereq_get0:= LoadFunctionCLib('OCSP_request_onereq_get0');
        @OCSP_onereq_get0_id:= LoadFunctionCLib('OCSP_onereq_get0_id');
        @OCSP_id_get0_info:= LoadFunctionCLib('OCSP_id_get0_info');
        @OCSP_request_is_signed:= LoadFunctionCLib('OCSP_request_is_signed');
        @OCSP_response_create:= LoadFunctionCLib('OCSP_response_create');
        @OCSP_basic_add1_status:= LoadFunctionCLib('OCSP_basic_add1_status');
        @OCSP_basic_add1_cert:= LoadFunctionCLib('OCSP_basic_add1_cert');
        @OCSP_basic_sign:= LoadFunctionCLib('OCSP_basic_sign');
        @OCSP_crlID_new:= LoadFunctionCLib('OCSP_crlID_new');
        @OCSP_accept_responses_new:= LoadFunctionCLib('OCSP_accept_responses_new');
        @OCSP_archive_cutoff_new:= LoadFunctionCLib('OCSP_archive_cutoff_new');
        @OCSP_url_svcloc_new:= LoadFunctionCLib('OCSP_url_svcloc_new');
        @OCSP_REQUEST_get_ext_count:= LoadFunctionCLib('OCSP_REQUEST_get_ext_count');
        @OCSP_REQUEST_get_ext_by_NID:= LoadFunctionCLib('OCSP_REQUEST_get_ext_by_NID');
        @OCSP_REQUEST_get_ext_by_OBJ:= LoadFunctionCLib('OCSP_REQUEST_get_ext_by_OBJ');
        @OCSP_REQUEST_get_ext_by_critical:= LoadFunctionCLib('OCSP_REQUEST_get_ext_by_critical');
        @OCSP_REQUEST_get_ext:= LoadFunctionCLib('OCSP_REQUEST_get_ext');
        @OCSP_REQUEST_delete_ext:= LoadFunctionCLib('OCSP_REQUEST_delete_ext');
        @OCSP_REQUEST_get1_ext_d2i:= LoadFunctionCLib('OCSP_REQUEST_get1_ext_d2i');
        @OCSP_REQUEST_add1_ext_i2d:= LoadFunctionCLib('OCSP_REQUEST_add1_ext_i2d');
        @OCSP_REQUEST_add_ext:= LoadFunctionCLib('OCSP_REQUEST_add_ext');
        @OCSP_ONEREQ_get_ext_count:= LoadFunctionCLib('OCSP_ONEREQ_get_ext_count');
        @OCSP_ONEREQ_get_ext_by_NID:= LoadFunctionCLib('OCSP_ONEREQ_get_ext_by_NID');
        @OCSP_ONEREQ_get_ext_by_OBJ:= LoadFunctionCLib('OCSP_ONEREQ_get_ext_by_OBJ');
        @OCSP_ONEREQ_get_ext_by_critical:= LoadFunctionCLib('OCSP_ONEREQ_get_ext_by_critical');
        @OCSP_ONEREQ_get_ext:= LoadFunctionCLib('OCSP_ONEREQ_get_ext');
        @OCSP_ONEREQ_delete_ext:= LoadFunctionCLib('OCSP_ONEREQ_delete_ext');
        @OCSP_ONEREQ_get1_ext_d2i:= LoadFunctionCLib('OCSP_ONEREQ_get1_ext_d2i');
        @OCSP_ONEREQ_add1_ext_i2d:= LoadFunctionCLib('OCSP_ONEREQ_add1_ext_i2d');
        @OCSP_ONEREQ_add_ext:= LoadFunctionCLib('OCSP_ONEREQ_add_ext');
        @OCSP_BASICRESP_get_ext_count:= LoadFunctionCLib('OCSP_BASICRESP_get_ext_count');
        @OCSP_BASICRESP_get_ext_by_NID:= LoadFunctionCLib('OCSP_BASICRESP_get_ext_by_NID');
        @OCSP_BASICRESP_get_ext_by_OBJ:= LoadFunctionCLib('OCSP_BASICRESP_get_ext_by_OBJ');
        @OCSP_BASICRESP_get_ext_by_critical:= LoadFunctionCLib('OCSP_BASICRESP_get_ext_by_critical');
        @OCSP_BASICRESP_get_ext:= LoadFunctionCLib('OCSP_BASICRESP_get_ext');
        @OCSP_BASICRESP_delete_ext:= LoadFunctionCLib('OCSP_BASICRESP_delete_ext');
        @OCSP_BASICRESP_get1_ext_d2i:= LoadFunctionCLib('OCSP_BASICRESP_get1_ext_d2i');
        @OCSP_BASICRESP_add1_ext_i2d:= LoadFunctionCLib('OCSP_BASICRESP_add1_ext_i2d');
        @OCSP_BASICRESP_add_ext:= LoadFunctionCLib('OCSP_BASICRESP_add_ext');
        @OCSP_SINGLERESP_get_ext_count:= LoadFunctionCLib('OCSP_SINGLERESP_get_ext_count');
        @OCSP_SINGLERESP_get_ext_by_NID:= LoadFunctionCLib('OCSP_SINGLERESP_get_ext_by_NID');
        @OCSP_SINGLERESP_get_ext_by_OBJ:= LoadFunctionCLib('OCSP_SINGLERESP_get_ext_by_OBJ');
        @OCSP_SINGLERESP_get_ext_by_critical:= LoadFunctionCLib('OCSP_SINGLERESP_get_ext_by_critical');
        @OCSP_SINGLERESP_get_ext:= LoadFunctionCLib('OCSP_SINGLERESP_get_ext');
        @OCSP_SINGLERESP_delete_ext:= LoadFunctionCLib('OCSP_SINGLERESP_delete_ext');
        @OCSP_SINGLERESP_get1_ext_d2i:= LoadFunctionCLib('OCSP_SINGLERESP_get1_ext_d2i');
        @OCSP_SINGLERESP_add1_ext_i2d:= LoadFunctionCLib('OCSP_SINGLERESP_add1_ext_i2d');
        @OCSP_SINGLERESP_add_ext:= LoadFunctionCLib('OCSP_SINGLERESP_add_ext');
        @OCSP_SINGLERESP_new:= LoadFunctionCLib('OCSP_SINGLERESP_new');
        @OCSP_SINGLERESP_free:= LoadFunctionCLib('OCSP_SINGLERESP_free');
        @d2i_OCSP_SINGLERESP:= LoadFunctionCLib('d2i_OCSP_SINGLERESP');
        @i2d_OCSP_SINGLERESP:= LoadFunctionCLib('i2d_OCSP_SINGLERESP');
        @OCSP_SINGLERESP_it:= LoadFunctionCLib('OCSP_SINGLERESP_it');
        @OCSP_CERTSTATUS_new:= LoadFunctionCLib('OCSP_CERTSTATUS_new');
        @OCSP_CERTSTATUS_free:= LoadFunctionCLib('OCSP_CERTSTATUS_free');
        @d2i_OCSP_CERTSTATUS:= LoadFunctionCLib('d2i_OCSP_CERTSTATUS');
        @i2d_OCSP_CERTSTATUS:= LoadFunctionCLib('i2d_OCSP_CERTSTATUS');
        @OCSP_CERTSTATUS_it:= LoadFunctionCLib('OCSP_CERTSTATUS_it');
        @OCSP_REVOKEDINFO_new:= LoadFunctionCLib('OCSP_REVOKEDINFO_new');
        @OCSP_REVOKEDINFO_free:= LoadFunctionCLib('OCSP_REVOKEDINFO_free');
        @d2i_OCSP_REVOKEDINFO:= LoadFunctionCLib('d2i_OCSP_REVOKEDINFO');
        @i2d_OCSP_REVOKEDINFO:= LoadFunctionCLib('i2d_OCSP_REVOKEDINFO');
        @OCSP_REVOKEDINFO_it:= LoadFunctionCLib('OCSP_REVOKEDINFO_it');
        @OCSP_BASICRESP_new:= LoadFunctionCLib('OCSP_BASICRESP_new');
        @OCSP_BASICRESP_free:= LoadFunctionCLib('OCSP_BASICRESP_free');
        @d2i_OCSP_BASICRESP:= LoadFunctionCLib('d2i_OCSP_BASICRESP');
        @i2d_OCSP_BASICRESP:= LoadFunctionCLib('i2d_OCSP_BASICRESP');
        @OCSP_BASICRESP_it:= LoadFunctionCLib('OCSP_BASICRESP_it');
        @OCSP_RESPDATA_new:= LoadFunctionCLib('OCSP_RESPDATA_new');
        @OCSP_RESPDATA_free:= LoadFunctionCLib('OCSP_RESPDATA_free');
        @d2i_OCSP_RESPDATA:= LoadFunctionCLib('d2i_OCSP_RESPDATA');
        @i2d_OCSP_RESPDATA:= LoadFunctionCLib('i2d_OCSP_RESPDATA');
        @OCSP_RESPDATA_it:= LoadFunctionCLib('OCSP_RESPDATA_it');
        @OCSP_RESPID_new:= LoadFunctionCLib('OCSP_RESPID_new');
        @OCSP_RESPID_free:= LoadFunctionCLib('OCSP_RESPID_free');
        @d2i_OCSP_RESPID:= LoadFunctionCLib('d2i_OCSP_RESPID');
        @i2d_OCSP_RESPID:= LoadFunctionCLib('i2d_OCSP_RESPID');
        @OCSP_RESPID_it:= LoadFunctionCLib('OCSP_RESPID_it');
        @OCSP_RESPONSE_new:= LoadFunctionCLib('OCSP_RESPONSE_new');
        @OCSP_RESPONSE_free:= LoadFunctionCLib('OCSP_RESPONSE_free');
        @d2i_OCSP_RESPONSE:= LoadFunctionCLib('d2i_OCSP_RESPONSE');
        @i2d_OCSP_RESPONSE:= LoadFunctionCLib('i2d_OCSP_RESPONSE');
        @OCSP_RESPONSE_it:= LoadFunctionCLib('OCSP_RESPONSE_it');
        @OCSP_RESPBYTES_new:= LoadFunctionCLib('OCSP_RESPBYTES_new');
        @OCSP_RESPBYTES_free:= LoadFunctionCLib('OCSP_RESPBYTES_free');
        @d2i_OCSP_RESPBYTES:= LoadFunctionCLib('d2i_OCSP_RESPBYTES');
        @i2d_OCSP_RESPBYTES:= LoadFunctionCLib('i2d_OCSP_RESPBYTES');
        @OCSP_RESPBYTES_it:= LoadFunctionCLib('OCSP_RESPBYTES_it');
        @OCSP_ONEREQ_new:= LoadFunctionCLib('OCSP_ONEREQ_new');
        @OCSP_ONEREQ_free:= LoadFunctionCLib('OCSP_ONEREQ_free');
        @d2i_OCSP_ONEREQ:= LoadFunctionCLib('d2i_OCSP_ONEREQ');
        @i2d_OCSP_ONEREQ:= LoadFunctionCLib('i2d_OCSP_ONEREQ');
        @OCSP_ONEREQ_it:= LoadFunctionCLib('OCSP_ONEREQ_it');
        @OCSP_CERTID_new:= LoadFunctionCLib('OCSP_CERTID_new');
        @OCSP_CERTID_free:= LoadFunctionCLib('OCSP_CERTID_free');
        @d2i_OCSP_CERTID:= LoadFunctionCLib('d2i_OCSP_CERTID');
        @i2d_OCSP_CERTID:= LoadFunctionCLib('i2d_OCSP_CERTID');
        @OCSP_CERTID_it:= LoadFunctionCLib('OCSP_CERTID_it');
        @OCSP_REQUEST_new:= LoadFunctionCLib('OCSP_REQUEST_new');
        @OCSP_REQUEST_free:= LoadFunctionCLib('OCSP_REQUEST_free');
        @d2i_OCSP_REQUEST:= LoadFunctionCLib('d2i_OCSP_REQUEST');
        @i2d_OCSP_REQUEST:= LoadFunctionCLib('i2d_OCSP_REQUEST');
        @OCSP_REQUEST_it:= LoadFunctionCLib('OCSP_REQUEST_it');
        @OCSP_SIGNATURE_new:= LoadFunctionCLib('OCSP_SIGNATURE_new');
        @OCSP_SIGNATURE_free:= LoadFunctionCLib('OCSP_SIGNATURE_free');
        @d2i_OCSP_SIGNATURE:= LoadFunctionCLib('d2i_OCSP_SIGNATURE');
        @i2d_OCSP_SIGNATURE:= LoadFunctionCLib('i2d_OCSP_SIGNATURE');
        @OCSP_SIGNATURE_it:= LoadFunctionCLib('OCSP_SIGNATURE_it');
        @OCSP_REQINFO_new:= LoadFunctionCLib('OCSP_REQINFO_new');
        @OCSP_REQINFO_free:= LoadFunctionCLib('OCSP_REQINFO_free');
        @d2i_OCSP_REQINFO:= LoadFunctionCLib('d2i_OCSP_REQINFO');
        @i2d_OCSP_REQINFO:= LoadFunctionCLib('i2d_OCSP_REQINFO');
        @OCSP_REQINFO_it:= LoadFunctionCLib('OCSP_REQINFO_it');
        @OCSP_CRLID_new_a:= LoadFunctionCLib('OCSP_CRLID_new');
        @OCSP_CRLID_free:= LoadFunctionCLib('OCSP_CRLID_free');
        @d2i_OCSP_CRLID:= LoadFunctionCLib('d2i_OCSP_CRLID');
        @i2d_OCSP_CRLID:= LoadFunctionCLib('i2d_OCSP_CRLID');
        @OCSP_CRLID_it:= LoadFunctionCLib('OCSP_CRLID_it');
        @OCSP_SERVICELOC_new:= LoadFunctionCLib('OCSP_SERVICELOC_new');
        @OCSP_SERVICELOC_free:= LoadFunctionCLib('OCSP_SERVICELOC_free');
        @d2i_OCSP_SERVICELOC:= LoadFunctionCLib('d2i_OCSP_SERVICELOC');
        @i2d_OCSP_SERVICELOC:= LoadFunctionCLib('i2d_OCSP_SERVICELOC');
        @OCSP_SERVICELOC_it:= LoadFunctionCLib('OCSP_SERVICELOC_it');
        @OCSP_response_status_str:= LoadFunctionCLib('OCSP_response_status_str');
        @OCSP_cert_status_str:= LoadFunctionCLib('OCSP_cert_status_str');
        @OCSP_crl_reason_str:= LoadFunctionCLib('OCSP_crl_reason_str');
        @OCSP_REQUEST_print:= LoadFunctionCLib('OCSP_REQUEST_print');
        @OCSP_RESPONSE_print:= LoadFunctionCLib('OCSP_RESPONSE_print');
        @OCSP_basic_verify:= LoadFunctionCLib('OCSP_basic_verify');
        @ERR_load_OCSP_strings:= LoadFunctionCLib('ERR_load_OCSP_strings');

     end;

end;

end.
