unit ssl_objects;

interface
uses ssl_types;
var
    OBJ_NAME_init: function: TC_INT; cdecl = nil;
    OBJ_NAME_new_index: function(hash_func: OBJ_hash_func; cmp_func: OBJ_cmp_func; free_func: OBJ_free_func): TC_INT; cdecl = nil;
    OBJ_NAME_get: function(const  _name: PAnsiChar; _type: TC_INT): PAnsiChar; cdecl = nil;
    OBJ_NAME_add: function(const  _name: PAnsiChar;_type: TC_INT;const  _data: PAnsiChar): TC_INT; cdecl = nil;
    OBJ_NAME_remove: function(const  _name: PAnsiChar;_type: TC_INT): TC_INT; cdecl = nil;
    OBJ_NAME_cleanup: procedure(_type: TC_INT); cdecl = nil;
    OBJ_NAME_do_all: procedure(_type: TC_INT; fn: OBJ_NAME_CALLBACK; arg: Pointer); cdecl = nil;
    OBJ_NAME_do_all_sorted: procedure(_type: TC_INT; fn: OBJ_NAME_CALLBACK; arg: Pointer); cdecl = nil;

    OBJ_dup: function(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl = nil;
    OBJ_nid2obj: function(_n: TC_INT): PASN1_OBJECT; cdecl = nil;
    OBJ_nid2ln: function(_n: TC_INT): PAnsiChar; cdecl = nil;
    OBJ_nid2sn: function(n: TC_INT): PAnsiChar; cdecl = nil;
    OBJ_obj2nid: function(const o: PASN1_OBJECT): TC_INT; cdecl = nil;
    OBJ_txt2obj: function(const  _s: PAnsiChar; _no_name: TC_INT): PASN1_OBJECT; cdecl = nil;
    OBJ_obj2txt: function( _buf: PAnsiChar; _buf_len: TC_INT; const a: PASN1_OBJECT; _no_name: TC_INT): TC_INT; cdecl = nil;
    OBJ_txt2nid: function(const  _s: PAnsiChar): TC_INT; cdecl = nil;
    OBJ_ln2nid: function(const  _s: PAnsiChar): TC_INT; cdecl = nil;
    OBJ_sn2nid: function(const  _s: PAnsiChar): TC_INT; cdecl = nil;
    OBJ_cmp: function(const a: PASN1_OBJECT;const b: PASN1_OBJECT): TC_INT; cdecl = nil;
    OBJ_bsearch_: function(const key: Pointer; const base: Pointer;_num: TC_INT;_size: TC_INT; cmp: OBJ_CMP_CALLBACK): Pointer; cdecl = nil;
    OBJ_bsearch_ex_: function(const key: Pointer;const base: Pointer; _num: TC_INT; _size: TC_INT; cmp: OBJ_CMP_CALLBACK;   _flags: TC_INT): Pointer; cdecl = nil;
    
    OBJ_new_nid: function(_num: TC_INT): TC_INT; cdecl = nil;
    OBJ_add_object: function(const obj: PASN1_OBJECT): TC_INT; cdecl = nil;
    OBJ_create: function(const  _oid: PAnsiChar;const  _sn: PAnsiChar;const  _ln: PAnsiChar): TC_INT; cdecl = nil;
    OBJ_cleanup: procedure; cdecl = nil;
    OBJ_create_objects: function(_in: PBIO): TC_INT; cdecl = nil;

    OBJ_find_sigid_algs: function(_signid: TC_INT; var _pdig_nid: TC_INT; var _ppkey_nid: TC_INT): TC_INT; cdecl = nil;
    OBJ_find_sigid_by_algs: function(var _psignid: TC_INT; _dig_nid: TC_INT; _pkey_nid: TC_INT): TC_INT; cdecl = nil;
    OBJ_add_sigid: function(_signid: TC_INT; _dig_id: TC_INT; _pkey_id: TC_INT): TC_INT; cdecl = nil;
    OBJ_sigid_free: procedure; cdecl = nil;

//extern int obj_cleanup_defer;
    check_defer: procedure(_nid: TC_INT); cdecl = nil;

    ERR_load_OBJ_strings: procedure; cdecl = nil;
   
procedure SSL_InitOBJ;   
   
implementation
uses ssl_lib;

procedure SSL_InitOBJ;
begin
 if @OBJ_NAME_init = nil then
 begin
    @OBJ_NAME_init:= LoadFunctionCLib('OBJ_NAME_init');
    @OBJ_NAME_new_index:= LoadFunctionCLib('OBJ_NAME_new_index');
    @OBJ_NAME_get:= LoadFunctionCLib('OBJ_NAME_get');
    @OBJ_NAME_add:= LoadFunctionCLib('OBJ_NAME_add');
    @OBJ_NAME_remove:= LoadFunctionCLib('OBJ_NAME_remove');
    @OBJ_NAME_cleanup:= LoadFunctionCLib('OBJ_NAME_cleanup');
    @OBJ_NAME_do_all:= LoadFunctionCLib('OBJ_NAME_do_all');
    @OBJ_NAME_do_all_sorted:= LoadFunctionCLib('OBJ_NAME_do_all_sorted');
    @OBJ_dup:= LoadFunctionCLib('OBJ_dup');
    @OBJ_nid2obj:= LoadFunctionCLib('OBJ_nid2obj');
    @OBJ_nid2ln:= LoadFunctionCLib('OBJ_nid2ln');
    @OBJ_nid2sn:= LoadFunctionCLib('OBJ_nid2sn');
    @OBJ_obj2nid:= LoadFunctionCLib('OBJ_obj2nid');
    @OBJ_txt2obj:= LoadFunctionCLib('OBJ_txt2obj');
    @OBJ_obj2txt:= LoadFunctionCLib('OBJ_obj2txt');
    @OBJ_txt2nid:= LoadFunctionCLib('OBJ_txt2nid');
    @OBJ_ln2nid:= LoadFunctionCLib('OBJ_ln2nid');
    @OBJ_sn2nid:= LoadFunctionCLib('OBJ_sn2nid');
    @OBJ_cmp:= LoadFunctionCLib('OBJ_cmp');
    @OBJ_bsearch_:= LoadFunctionCLib('OBJ_bsearch_', false);
    @OBJ_bsearch_ex_:= LoadFunctionCLib('OBJ_bsearch_ex_', false);
    @OBJ_new_nid:= LoadFunctionCLib('OBJ_new_nid');
    @OBJ_add_object:= LoadFunctionCLib('OBJ_add_object');
    @OBJ_create:= LoadFunctionCLib('OBJ_create');
    @OBJ_cleanup:= LoadFunctionCLib('OBJ_cleanup');
    @OBJ_create_objects:= LoadFunctionCLib('OBJ_create_objects');
    @OBJ_find_sigid_algs:= LoadFunctionCLib('OBJ_find_sigid_algs', false);
    @OBJ_find_sigid_by_algs:= LoadFunctionCLib('OBJ_find_sigid_by_algs', false);
    @OBJ_add_sigid:= LoadFunctionCLib('OBJ_add_sigid', false);
    @OBJ_sigid_free:= LoadFunctionCLib('OBJ_sigid_free', false);
    @check_defer:= LoadFunctionCLib('check_defer', false);
    @ERR_load_OBJ_strings:= LoadFunctionCLib('ERR_load_OBJ_strings');
    
 end;
end;

end.
