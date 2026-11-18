#!/usr/bin/env python3
"""Monta um APK Android (WebView) do zero: DEX, manifest binário, resources.arsc, zip alinhado e assinatura v2."""
import struct, hashlib, zlib, zipfile, io, os, sys, datetime

PKG = 'com.jadilson.escalacao'
CLS = 'L' + PKG.replace('.', '/') + '/MainActivity;'
APP_LABEL = 'JA Escalação'
VERSION_CODE, VERSION_NAME = 3, '1.2'
MIN_SDK, TARGET_SDK = 24, 34
HERE = os.path.dirname(os.path.abspath(__file__))

u8 = lambda v: struct.pack('<B', v)
u16 = lambda v: struct.pack('<H', v)
u32 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)
u64 = lambda v: struct.pack('<Q', v)

def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)

def align(buf, n):
    while len(buf) % n: buf += b'\0'

# =====================================================================
# DEX
# =====================================================================
def shorty(t):
    return t if len(t) == 1 else 'L'

class DexBuilder:
    def __init__(self):
        self.strings, self.types, self.protos, self.fields, self.methods = set(), set(), set(), set(), set()
    def T(self, t):
        self.strings.add(t); self.types.add(t); return ('T', t)
    def S(self, s):
        self.strings.add(s); return ('S', s)
    def P(self, ret, params):
        self.T(ret); [self.T(p) for p in params]
        sh = shorty(ret) + ''.join(shorty(p) for p in params)
        self.strings.add(sh); key = (sh, ret, tuple(params)); self.protos.add(key); return key
    def M(self, cls, name, ret, params):
        self.T(cls); self.strings.add(name); p = self.P(ret, params)
        key = (cls, name, p); self.methods.add(key); return ('M', key)
    def F(self, cls, name, typ):
        self.T(cls); self.T(typ); self.strings.add(name)
        key = (cls, name, typ); self.fields.add(key); return ('F', key)

    def finalize(self):
        self.str_list = sorted(self.strings, key=lambda s: [ord(c) for c in s])
        self.si = {s: i for i, s in enumerate(self.str_list)}
        self.type_list = sorted(self.types, key=lambda t: self.si[t])
        self.ti = {t: i for i, t in enumerate(self.type_list)}
        self.proto_list = sorted(self.protos, key=lambda p: (self.ti[p[1]], [self.ti[x] for x in p[2]]))
        self.pi = {p: i for i, p in enumerate(self.proto_list)}
        self.field_list = sorted(self.fields, key=lambda f: (self.ti[f[0]], self.si[f[1]], self.ti[f[2]]))
        self.fi = {f: i for i, f in enumerate(self.field_list)}
        self.method_list = sorted(self.methods, key=lambda m: (self.ti[m[0]], self.si[m[1]], self.pi[m[2]]))
        self.mi = {m: i for i, m in enumerate(self.method_list)}

    def idx(self, ref):
        k, v = ref
        return {'T': self.ti, 'S': self.si, 'M': self.mi, 'F': self.fi}[k][v]

# --- codificação de instruções (unidades de 16 bits) ---
def invoke(op, regs, midx):
    a = len(regs); r = list(regs) + [0] * (5 - a)
    c, d, e, f, g = r
    return [(a << 12) | (g << 8) | op, midx, (f << 12) | (e << 8) | (d << 4) | c]
def inv_virtual(regs, m): return invoke(0x6e, regs, m)
def inv_super(regs, m):   return invoke(0x6f, regs, m)
def inv_direct(regs, m):  return invoke(0x70, regs, m)
def ret_void():           return [0x000e]
def const4(a, b):         return [((b & 0xf) << 12) | (a << 8) | 0x12]
def const32(a, v):        v &= 0xFFFFFFFF; return [(a << 8) | 0x14, v & 0xFFFF, v >> 16]
def new_inst(a, t):       return [(a << 8) | 0x22, t]
def const_str(a, s):      return [(a << 8) | 0x1a, s]
def move_res_obj(a):      return [(a << 8) | 0x0c]
def move_res(a):          return [(a << 8) | 0x0a]
def iput_obj(a, b, f):    return [(b << 12) | (a << 8) | 0x5b, f]
def iget_obj(a, b, f):    return [(b << 12) | (a << 8) | 0x54, f]
def if_eqz(a, off):       return [(a << 8) | 0x38, off & 0xFFFF]

def inv_static(regs, m):  return invoke(0x71, regs, m)
def inv_iface(regs, m):   return invoke(0x72, regs, m)
def ret(a):               return [(a << 8) | 0x0f]

def assemble(items):
    """items: lists of words, ('L', name) labels, or ('if-eqz', reg, label)."""
    pos, labels = 0, {}
    for it in items:
        if isinstance(it, tuple) and it[0] == 'L': labels[it[1]] = pos
        elif isinstance(it, tuple): pos += 2
        else: pos += len(it)
    out, pos = [], 0
    for it in items:
        if isinstance(it, tuple) and it[0] == 'L': continue
        if isinstance(it, tuple):
            _, reg, lab = it; w = if_eqz(reg, labels[lab] - pos)
        else: w = it
        out += w; pos += len(w)
    return out

def build_dex():
    d = DexBuilder()
    CC = 'L' + PKG.replace('.', '/') + '/ChromeClient;'
    ACT, BUNDLE, WV = 'Landroid/app/Activity;', 'Landroid/os/Bundle;', 'Landroid/webkit/WebView;'
    WS, WIN, CTX, VIEW = 'Landroid/webkit/WebSettings;', 'Landroid/view/Window;', 'Landroid/content/Context;', 'Landroid/view/View;'
    WVC, WCC, STR = 'Landroid/webkit/WebViewClient;', 'Landroid/webkit/WebChromeClient;', 'Ljava/lang/String;'
    VC, FCP, INTENT = 'Landroid/webkit/ValueCallback;', 'Landroid/webkit/WebChromeClient$FileChooserParams;', 'Landroid/content/Intent;'
    URIS, OBJ = '[Landroid/net/Uri;', 'Ljava/lang/Object;'
    d.T(CLS); d.T(ACT); d.T(CC); d.T(WCC)
    m_act_init = d.M(ACT, '<init>', 'V', [])
    m_act_oncreate = d.M(ACT, 'onCreate', 'V', [BUNDLE])
    m_act_back = d.M(ACT, 'onBackPressed', 'V', [])
    m_act_result = d.M(ACT, 'onActivityResult', 'V', ['I', 'I', INTENT])
    m_start = d.M(ACT, 'startActivityForResult', 'V', [INTENT, 'I'])
    m_getwin = d.M(ACT, 'getWindow', WIN, [])
    m_setcv = d.M(ACT, 'setContentView', 'V', [VIEW])
    m_sbc = d.M(WIN, 'setStatusBarColor', 'V', ['I'])
    m_nbc = d.M(WIN, 'setNavigationBarColor', 'V', ['I'])
    m_wv_init = d.M(WV, '<init>', 'V', [CTX])
    m_bg = d.M(WV, 'setBackgroundColor', 'V', ['I'])
    m_gs = d.M(WV, 'getSettings', WS, [])
    m_js = d.M(WS, 'setJavaScriptEnabled', 'V', ['Z'])
    m_dom = d.M(WS, 'setDomStorageEnabled', 'V', ['Z'])
    m_file = d.M(WS, 'setAllowFileAccess', 'V', ['Z'])
    m_univ = d.M(WS, 'setAllowUniversalAccessFromFileURLs', 'V', ['Z'])
    m_wcc_init = d.M(WCC, '<init>', 'V', [])
    m_setwcc = d.M(WV, 'setWebChromeClient', 'V', [WCC])
    m_wvc_init = d.M(WVC, '<init>', 'V', [])
    m_setwvc = d.M(WV, 'setWebViewClient', 'V', [WVC])
    m_load = d.M(WV, 'loadUrl', 'V', [STR])
    m_cangoback = d.M(WV, 'canGoBack', 'Z', [])
    m_goback = d.M(WV, 'goBack', 'V', [])
    m_onrecv = d.M(VC, 'onReceiveValue', 'V', [OBJ])
    m_parse = d.M(FCP, 'parseResult', URIS, ['I', INTENT])
    m_cintent = d.M(FCP, 'createIntent', INTENT, [])
    s_url = d.S('file:///android_asset/index.html')
    f_wv = d.F(CLS, 'wv', WV)
    f_cb = d.F(CLS, 'cb', VC)
    f_act = d.F(CC, 'act', CLS)
    my_init = d.M(CLS, '<init>', 'V', [])
    my_oncreate = d.M(CLS, 'onCreate', 'V', [BUNDLE])
    my_back = d.M(CLS, 'onBackPressed', 'V', [])
    my_result = d.M(CLS, 'onActivityResult', 'V', ['I', 'I', INTENT])
    cc_init = d.M(CC, '<init>', 'V', [CLS])
    cc_show = d.M(CC, 'onShowFileChooser', 'Z', [WV, VC, FCP])
    t_wv, t_cc, t_wvc = d.T(WV), d.T(CC), d.T(WVC)
    d.finalize()
    I = d.idx

    # ---- MainActivity ----
    code_init = (1, 1, 1, inv_direct([0], I(m_act_init)) + ret_void())
    c = []   # regs 5: v0..v2, p0=v3, p1=v4
    c += inv_super([3, 4], I(m_act_oncreate))
    c += inv_virtual([3], I(m_getwin)); c += move_res_obj(0)
    c += const32(1, 0xFF0E2A1B); c += inv_virtual([0, 1], I(m_sbc))
    c += const32(1, 0xFF0A1D13); c += inv_virtual([0, 1], I(m_nbc))
    c += new_inst(0, I(t_wv)); c += inv_direct([0, 3], I(m_wv_init))
    c += iput_obj(0, 3, I(f_wv))
    c += const32(1, 0xFF07140D); c += inv_virtual([0, 1], I(m_bg))
    c += inv_virtual([0], I(m_gs)); c += move_res_obj(1)
    c += const4(2, 1)
    for m in (m_js, m_dom, m_file, m_univ): c += inv_virtual([1, 2], I(m))
    c += new_inst(1, I(t_cc)); c += inv_direct([1, 3], I(cc_init)); c += inv_virtual([0, 1], I(m_setwcc))
    c += new_inst(1, I(t_wvc)); c += inv_direct([1], I(m_wvc_init)); c += inv_virtual([0, 1], I(m_setwvc))
    c += const_str(1, I(s_url)); c += inv_virtual([0, 1], I(m_load))
    c += inv_virtual([3, 0], I(m_setcv))
    c += ret_void()
    code_oncreate = (5, 2, 2, c)
    code_back = (3, 1, 1, assemble([   # v0,v1, p0=v2
        iget_obj(0, 2, I(f_wv)), ('if-eqz', 0, 'sup'),
        inv_virtual([0], I(m_cangoback)), move_res(1), ('if-eqz', 1, 'sup'),
        inv_virtual([0], I(m_goback)), ret_void(),
        ('L', 'sup'), inv_super([2], I(m_act_back)), ret_void()]))
    code_result = (6, 4, 4, assemble([  # v0,v1, p0=v2, p1=v3 req, p2=v4 res, p3=v5 data
        inv_super([2, 3, 4, 5], I(m_act_result)),
        iget_obj(0, 2, I(f_cb)), ('if-eqz', 0, 'end'),
        inv_static([4, 5], I(m_parse)), move_res_obj(1),
        inv_iface([0, 1], I(m_onrecv)),
        const4(1, 0), iput_obj(1, 2, I(f_cb)),
        ('L', 'end'), ret_void()]))
    # ---- ChromeClient ----
    code_cc_init = (2, 2, 1, inv_direct([0], I(m_wcc_init)) + iput_obj(1, 0, I(f_act)) + ret_void())
    code_cc_show = (6, 4, 3, assemble([  # v0,v1, p0=v2, p1=v3 wv, p2=v4 cb, p3=v5 params
        iget_obj(0, 2, I(f_act)), iget_obj(1, 0, I(f_cb)), ('if-eqz', 1, 'novo'),
        const4(3, 0), inv_iface([1, 3], I(m_onrecv)),
        ('L', 'novo'), iput_obj(4, 0, I(f_cb)),
        inv_virtual([5], I(m_cintent)), move_res_obj(1),
        const4(3, 1), inv_virtual([0, 1, 3], I(m_start)),
        const4(1, 1), ret(1)]))

    classes = [
        dict(cls=CLS, sup=ACT, fields=[(I(f_cb), 0x1), (I(f_wv), 0x2)],
             direct=[(I(my_init), 0x10001, code_init)],
             virtual=[(I(my_oncreate), 0x4, code_oncreate), (I(my_back), 0x1, code_back), (I(my_result), 0x4, code_result)]),
        dict(cls=CC, sup=WCC, fields=[(I(f_act), 0x12)],   # private final
             direct=[(I(cc_init), 0x10001, code_cc_init)],
             virtual=[(I(cc_show), 0x1, code_cc_show)]),
    ]
    for k in classes:
        k['fields'].sort(); k['direct'].sort(); k['virtual'].sort()

    n_s, n_t, n_p, n_f, n_m = len(d.str_list), len(d.type_list), len(d.proto_list), len(d.field_list), len(d.method_list)
    n_c = len(classes)
    off = 0x70
    string_ids_off = off; off += 4 * n_s
    type_ids_off = off; off += 4 * n_t
    proto_ids_off = off; off += 12 * n_p
    field_ids_off = off; off += 8 * n_f
    method_ids_off = off; off += 8 * n_m
    class_defs_off = off; off += 32 * n_c
    data_off = off
    data = bytearray()
    def here(): return data_off + len(data)
    code_offs = {}
    code_items_off = here()
    for k in classes:
        for midx, _, (regs, ins, outs, insns) in k['direct'] + k['virtual']:
            align(data, 4)
            code_offs[midx] = here()
            data += u16(regs) + u16(ins) + u16(outs) + u16(0) + u32(0) + u32(len(insns))
            for w in insns: data += u16(w)
    n_code = len(code_offs)
    align(data, 4)
    tl_off = {}
    type_lists_off = here()
    for p in d.proto_list:
        params = p[2]
        if params and params not in tl_off:
            align(data, 4)
            tl_off[params] = here()
            data += u32(len(params)) + b''.join(u16(d.ti[x]) for x in params)
            align(data, 4)
    n_tl = len(tl_off)
    str_data_off = here(); s_off = []
    for s in d.str_list:
        s_off.append(here())
        enc = s.encode('utf-8')
        assert all(ch < 0x80 for ch in enc) and '\0' not in s
        data += uleb(len(s)) + enc + b'\0'
    class_data_offs = []
    class_data_off = here()
    for k in classes:
        class_data_offs.append(here())
        data += uleb(0) + uleb(len(k['fields'])) + uleb(len(k['direct'])) + uleb(len(k['virtual']))
        prev = 0
        for fidx, acc in k['fields']:
            data += uleb(fidx - prev) + uleb(acc); prev = fidx
        for group in (k['direct'], k['virtual']):
            prev = 0
            for midx, acc, _ in group:
                data += uleb(midx - prev) + uleb(acc) + uleb(code_offs[midx]); prev = midx
    align(data, 4)
    map_off = here()
    items = [(0x0000, 1, 0), (0x0001, n_s, string_ids_off), (0x0002, n_t, type_ids_off), (0x0003, n_p, proto_ids_off),
             (0x0004, n_f, field_ids_off), (0x0005, n_m, method_ids_off), (0x0006, n_c, class_defs_off),
             (0x2001, n_code, code_items_off)]
    if n_tl: items.append((0x1001, n_tl, type_lists_off))
    items += [(0x2002, n_s, str_data_off), (0x2000, n_c, class_data_off), (0x1000, 1, map_off)]
    items.sort(key=lambda x: x[2])
    data += u32(len(items)) + b''.join(u16(t) + u16(0) + u32(n) + u32(o) for t, n, o in items)
    ids = bytearray()
    for o in s_off: ids += u32(o)
    for t in d.type_list: ids += u32(d.si[t])
    for p in d.proto_list: ids += u32(d.si[p[0]]) + u32(d.ti[p[1]]) + u32(tl_off.get(p[2], 0) if p[2] else 0)
    for f in d.field_list: ids += u16(d.ti[f[0]]) + u16(d.ti[f[2]]) + u32(d.si[f[1]])
    for m in d.method_list: ids += u16(d.ti[m[0]]) + u16(d.pi[m[2]]) + u32(d.si[m[1]])
    for k, cdo in zip(classes, class_data_offs):
        ids += u32(d.ti[k['cls']]) + u32(0x1) + u32(d.ti[k['sup']]) + u32(0) + u32(0xFFFFFFFF) + u32(0) + u32(cdo) + u32(0)
    assert 0x70 + len(ids) == data_off
    file_size = data_off + len(data)
    hdr = bytearray(b'dex\n035\0') + b'\0' * 24
    hdr += u32(file_size) + u32(0x70) + u32(0x12345678) + u32(0) + u32(0) + u32(map_off)
    hdr += u32(n_s) + u32(string_ids_off) + u32(n_t) + u32(type_ids_off) + u32(n_p) + u32(proto_ids_off)
    hdr += u32(n_f) + u32(field_ids_off) + u32(n_m) + u32(method_ids_off) + u32(n_c) + u32(class_defs_off)
    hdr += u32(len(data)) + u32(data_off)
    assert len(hdr) == 0x70
    dex = bytearray(hdr + ids + data)
    dex[12:32] = hashlib.sha1(dex[32:]).digest()
    dex[8:12] = u32(zlib.adler32(bytes(dex[12:])))
    return bytes(dex)


# =====================================================================
# String pool (UTF-16) usado no XML binário e no resources.arsc
# =====================================================================
def string_pool(strings):
    offs, body = [], bytearray()
    for s in strings:
        offs.append(len(body))
        units = s.encode('utf-16-le')
        n = len(units) // 2
        assert n < 0x8000
        body += u16(n) + units + u16(0)
    align(body, 4)
    hsize = 28
    strings_start = hsize + 4 * len(strings)
    size = strings_start + len(body)
    return u16(0x0001) + u16(hsize) + u32(size) + u32(len(strings)) + u32(0) + u32(0) + u32(strings_start) + u32(0) \
        + b''.join(u32(o) for o in offs) + bytes(body)

# =====================================================================
# AndroidManifest.xml binário
# =====================================================================
ATTR_ID = {'theme': 0x01010000, 'label': 0x01010001, 'icon': 0x01010002, 'name': 0x01010003, 'exported': 0x01010010,
           'screenOrientation': 0x0101001e, 'configChanges': 0x0101001f, 'minSdkVersion': 0x0101020c,
           'versionCode': 0x0101021b, 'versionName': 0x0101021c, 'windowSoftInputMode': 0x0101022b,
           'targetSdkVersion': 0x01010270, 'allowBackup': 0x01010280, 'hardwareAccelerated': 0x010102d3}
ANDROID_NS = 'http://schemas.android.com/apk/res/android'
T_REF, T_STR, T_DEC, T_HEX, T_BOOL = 0x01, 0x03, 0x10, 0x11, 0x12

def build_manifest(icon_id):
    # (tag, [(attrName, android_ns?, type, value)], children)
    A = lambda n, t, v: (n, True, t, v)
    tree = ('manifest', [A('versionCode', T_DEC, VERSION_CODE), A('versionName', T_STR, VERSION_NAME), ('package', False, T_STR, PKG)], [
        ('uses-sdk', [A('minSdkVersion', T_DEC, MIN_SDK), A('targetSdkVersion', T_DEC, TARGET_SDK)], []),
        ('uses-permission', [A('name', T_STR, 'android.permission.INTERNET')], []),
        ('application', [A('theme', T_REF, 0x0103022e), A('label', T_STR, APP_LABEL), A('icon', T_REF, icon_id),
                         A('allowBackup', T_BOOL, True), A('hardwareAccelerated', T_BOOL, True)], [
            ('activity', [A('name', T_STR, PKG + '.MainActivity'), A('exported', T_BOOL, True),
                          A('screenOrientation', T_DEC, 1),                    # portrait
                          A('configChanges', T_HEX, 0x04a0 | 0x0100 | 0x0800),  # orientation|screenSize|keyboardHidden|screenLayout|smallestScreenSize
                          A('windowSoftInputMode', T_HEX, 0x10)], [            # adjustResize
                ('intent-filter', [], [
                    ('action', [A('name', T_STR, 'android.intent.action.MAIN')], []),
                    ('category', [A('name', T_STR, 'android.intent.category.LAUNCHER')], []),
                ]),
            ]),
        ]),
    ])
    # coletar strings: primeiro os nomes de atributos com id (mapa de recursos), em ordem de id
    used_attrs = set()
    def walk(n):
        for a in n[1]:
            if a[1]: used_attrs.add(a[0])
        for ch in n[2]: walk(ch)
    walk(tree)
    attr_names = sorted(used_attrs, key=lambda x: ATTR_ID[x])
    strings = list(attr_names)
    def add(s):
        if s not in strings: strings.append(s)
        return strings.index(s)
    add('android'); add(ANDROID_NS)
    def walk2(n):
        add(n[0])
        for a in n[1]:
            add(a[0])
            if a[2] == T_STR: add(a[3])
        for ch in n[2]: walk2(ch)
    walk2(tree)
    si = {s: i for i, s in enumerate(strings)}
    NS = si[ANDROID_NS]
    body = bytearray()
    line = [1]
    def node(n):
        tag, attrs, kids = n
        def key(a): return ATTR_ID[a[0]] if a[1] else 0xFFFFFFFF
        attrs = sorted(attrs, key=key)
        ab = bytearray()
        for name, isns, typ, val in attrs:
            raw = si[val] if typ == T_STR else 0xFFFFFFFF
            data = si[val] if typ == T_STR else (0xFFFFFFFF if (typ == T_BOOL and val) else (0 if typ == T_BOOL else val))
            ab += u32(NS if isns else 0xFFFFFFFF) + u32(si[name]) + u32(raw) + u16(8) + u8(0) + u8(typ) + u32(data)
        ext = u32(0xFFFFFFFF) + u32(si[tag]) + u16(20) + u16(20) + u16(len(attrs)) + u16(0) + u16(0) + u16(0)
        chunk = ext + ab
        body.extend(u16(0x0102) + u16(16) + u32(16 + len(chunk)) + u32(line[0]) + u32(0xFFFFFFFF) + chunk); line[0] += 1
        for k in kids: node(k)
        body.extend(u16(0x0103) + u16(16) + u32(24) + u32(line[0]) + u32(0xFFFFFFFF) + u32(0xFFFFFFFF) + u32(si[tag])); line[0] += 1
    ns_start = u16(0x0100) + u16(16) + u32(24) + u32(1) + u32(0xFFFFFFFF) + u32(si['android']) + u32(NS)
    node(tree)
    ns_end = u16(0x0101) + u16(16) + u32(24) + u32(line[0]) + u32(0xFFFFFFFF) + u32(si['android']) + u32(NS)
    pool = string_pool(strings)
    resmap = u16(0x0180) + u16(8) + u32(8 + 4 * len(attr_names)) + b''.join(u32(ATTR_ID[a]) for a in attr_names)
    content = pool + resmap + ns_start + bytes(body) + ns_end
    return u16(0x0003) + u16(8) + u32(8 + len(content)) + content

# =====================================================================
# resources.arsc (apenas o ícone mipmap/ic_launcher em xxxhdpi)
# =====================================================================
ICON_PATH = 'res/mipmap-xxxhdpi-v4/ic_launcher.png'
def build_arsc():
    gpool = string_pool([ICON_PATH])
    tpool = string_pool(['mipmap'])
    kpool = string_pool(['ic_launcher'])
    spec = u16(0x0202) + u16(16) + u32(16 + 4) + u8(1) + u8(0) + u16(0) + u32(1) + u32(0x0100)
    config = bytearray(64); config[0:4] = u32(64); config[14:16] = u16(640); config[24:26] = u16(4)
    entry = u16(8) + u16(0) + u32(0) + u16(8) + u8(0) + u8(T_STR) + u32(0)
    th = 20 + 64
    typ = u16(0x0201) + u16(th) + u32(th + 4 + len(entry)) + u8(1) + u8(0) + u16(0) + u32(1) + u32(th + 4) + bytes(config) + u32(0) + entry
    name = PKG.encode('utf-16-le'); name += b'\0' * (256 - len(name))
    ph = 288
    pkg_body = tpool + kpool + spec + typ
    pkg = u16(0x0200) + u16(ph) + u32(ph + len(pkg_body)) + u32(0x7f) + name + u32(ph) + u32(1) + u32(ph + len(tpool)) + u32(1) + u32(0) + pkg_body
    content = gpool + pkg
    return u16(0x0002) + u16(12) + u32(12 + len(content)) + u32(1) + content, 0x7f010000

# =====================================================================
# Ícone
# =====================================================================
def build_icon():
    from PIL import Image, ImageDraw
    S = 768
    bg = Image.new('RGB', (S, S)); g = ImageDraw.Draw(bg)
    for k in range(8):
        t = k / 8
        c = (int(30 + 8 * t), int(150 - 55 * t), int(72 - 22 * t))
        if k % 2: c = tuple(max(0, v - 14) for v in c)
        g.rectangle([0, k * S // 8, S, (k + 1) * S // 8], fill=c)
    dr = ImageDraw.Draw(bg)
    w = 14; L = (235, 250, 240); m = 110
    dr.rounded_rectangle([m, m - 30, S - m, S - m + 30], radius=12, outline=L, width=w)
    dr.line([m, S // 2, S - m, S // 2], fill=L, width=w)
    dr.ellipse([S // 2 - 85, S // 2 - 85, S // 2 + 85, S // 2 + 85], outline=L, width=w)
    dr.rectangle([S // 2 - 150, m - 30, S // 2 + 150, m + 80], outline=L, width=w)
    dr.rectangle([S // 2 - 150, S - m - 80, S // 2 + 150, S - m + 30], outline=L, width=w)
    def player(x, y, col, r=44):
        dr.ellipse([x - r - 8, y - r - 8, x + r + 8, y + r + 8], fill=(255, 255, 255))
        dr.ellipse([x - r, y - r, x + r, y + r], fill=col)
    red, yel = (225, 29, 72), (245, 179, 1)
    player(S // 2, S - m - 25, yel)
    player(S // 2 - 165, S // 2 + 150, red); player(S // 2 + 165, S // 2 + 150, red)
    player(S // 2, S // 2, red)
    player(S // 2 - 190, S // 2 - 165, red); player(S // 2 + 190, S // 2 - 165, red); player(S // 2, S // 2 - 215, red)
    mask = Image.new('L', (S, S), 0); ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=170, fill=255)
    im = bg.convert('RGBA'); im.putalpha(mask)
    im = im.resize((192, 192), Image.LANCZOS)
    b = io.BytesIO(); im.save(b, 'PNG', optimize=True); return b.getvalue()

# =====================================================================
# ZIP alinhado + assinatura v2
# =====================================================================
def build_zip(entries):
    """entries: list of (name, bytes, stored?)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data, stored in entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 11, 16, 12, 0, 0))
            zi.create_system = 0; zi.external_attr = 0
            if stored:
                zi.compress_type = zipfile.ZIP_STORED
                pos = buf.tell(); hdr = 30 + len(name.encode())
                need = (-(pos + hdr)) % 4
                if need:
                    need += 4  # cabeçalho extra mínimo de 4 bytes
                    zi.extra = u16(0xD935) + u16(need - 4) + b'\0' * (need - 4)
                else:
                    zi.extra = b''
            else:
                zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data, compresslevel=9 if not stored else None)
    return buf.getvalue()

def check_alignment(apk):
    zf = zipfile.ZipFile(io.BytesIO(apk))
    for zi in zf.infolist():
        if zi.compress_type == zipfile.ZIP_STORED:
            off = zi.header_offset
            n, e = struct.unpack('<HH', apk[off + 26:off + 30])
            data_off = off + 30 + n + e
            assert data_off % 4 == 0, (zi.filename, data_off)

def lp(b): return u32(len(b)) + b

def sign_v2(apk, key, cert_der):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    eocd = apk.rfind(b'PK\x05\x06')
    cd_off = struct.unpack('<I', apk[eocd + 16:eocd + 20])[0]
    sections = [apk[:cd_off], apk[cd_off:eocd], apk[eocd:]]
    chunks = []
    for sec in sections:
        for i in range(0, len(sec), 1 << 20):
            ch = sec[i:i + (1 << 20)]
            chunks.append(hashlib.sha256(b'\xa5' + u32(len(ch)) + ch).digest())
    digest = hashlib.sha256(b'\x5a' + u32(len(chunks)) + b''.join(chunks)).digest()
    ALG = 0x0103  # RSASSA-PKCS1-v1_5 + SHA2-256
    signed_data = lp(lp(u32(ALG) + lp(digest))) + lp(lp(cert_der)) + lp(b'')
    sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + lp(lp(u32(ALG) + lp(sig))) + lp(pub)
    value = lp(lp(signer))
    pair = u64(4 + len(value)) + u32(0x7109871a) + value
    size = len(pair) + 8 + 16
    block = u64(size) + pair + u64(size) + b'APK Sig Block 42'
    new_eocd = bytearray(apk[eocd:]); new_eocd[16:20] = u32(cd_off + len(block))
    return apk[:cd_off] + block + apk[cd_off:eocd] + bytes(new_eocd)

def load_key():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    kp, cp = os.path.join(HERE, 'keys', 'key.pem'), os.path.join(HERE, 'keys', 'cert.der')
    if os.path.exists(kp):
        key = serialization.load_pem_private_key(open(kp, 'rb').read(), None)
        return key, open(cp, 'rb').read()
    os.makedirs(os.path.dirname(kp), exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Jadilson Alves'), x509.NameAttribute(NameOID.COUNTRY_NAME, 'BR')])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * 30)).sign(key, hashes.SHA256()))
    open(kp, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    der = cert.public_bytes(serialization.Encoding.DER); open(cp, 'wb').write(der)
    return key, der

def main(out):
    dex = build_dex()
    arsc, icon_id = build_arsc()
    manifest = build_manifest(icon_id)
    html = open(os.path.join(HERE, 'assets', 'index.html'), 'rb').read()
    entries = [('AndroidManifest.xml', manifest, False), ('classes.dex', dex, False), ('resources.arsc', arsc, True),
               (ICON_PATH, build_icon(), True), ('assets/index.html', html, False)]
    apk = build_zip(entries)
    check_alignment(apk)
    key, cert = load_key()
    apk = sign_v2(apk, key, cert)
    open(out, 'wb').write(apk)
    for n, d, _ in entries: open(os.path.join(HERE, 'out_' + n.replace('/', '_')), 'wb').write(d)
    print('ok', out, len(apk), 'bytes')

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'JA-Escalacao.apk'))
