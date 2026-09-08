#!/usr/bin/env python3
"""
Generate kstl's header-free intrinsics headers from the MSVC toolset headers.

MSVC recognises an intrinsic by NAME once it is declared with the right signature; the SDK
headers are nothing but those declarations (plus a few macros and inline helpers). So we parse
them and re-emit exactly the same declarations, one file per instruction-set family, each with a
kstl::<family> namespace of using-declarations so a caller can write kstl::sse2::_mm_add_epi8 or
`using namespace kstl::sse2;` without ever including <intrin.h> or <emmintrin.h>.

Each family header is a drop-in for its toolset header: the same types, declarations, macros and
inline helpers (as an x64 C++ build sees them), under the real include guard, which the file also
defines. So the two can meet in one translation unit in either order -- whichever comes second is
skipped -- and the namespaces still work because the names exist either way.

Also generated: bench/intrin_all/, a test that CALLS every declared intrinsic, one translation
unit per chunk of 24. Compiling and linking it proves each name is one MSVC accepts as an
intrinsic (an unrecognised name would be an unresolved external); running it executes every
family the CPU supports with each call under SEH, tallying privileged and unsupported
instructions and naming any other fault.

Usage: python tools/gen_intrin.py [toolset include dir]
"""
import os, re, sys

TOOLSET = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.44.35207\include"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(ROOT, "src", "kstl", "intrin")
BENCH_DIR = os.path.join(ROOT, "bench", "intrin_all")
UMBRELLA = os.path.join(ROOT, "src", "kstl", "intrin.hpp")

# (namespace, header, parent family or None, description, cpu gate expression for the test)
FAMILIES = [
    # intrin.h's own declarations use __m64/__m128/__m128i/__m128d (its SSE2-era leftovers), so the
    # x64 family sits on sse2; it does not pull in the AVX families the real header includes.
    ("x64",    "intrin.h",    "sse2",   "scalar x64 intrinsics: bit scan/count, wide multiply, rotate, byte swap, interlocked, rep string ops, cpuid, rdtsc, fences, TEB/PEB access", "true"),
    ("sse",    "xmmintrin.h", None,     "SSE (float vectors)",           "cpu_has(1, 0, 3, 25)"),
    ("sse2",   "emmintrin.h", "sse",    "SSE2 (integer and double vectors)", "cpu_has(1, 0, 3, 26)"),
    ("sse3",   "pmmintrin.h", "sse2",   "SSE3",                          "cpu_has(1, 0, 2, 0)"),
    ("ssse3",  "tmmintrin.h", "sse3",   "SSSE3",                         "cpu_has(1, 0, 2, 9)"),
    ("sse4_1", "smmintrin.h", "ssse3",  "SSE4.1",                        "cpu_has(1, 0, 2, 19)"),
    ("sse4_2", "nmmintrin.h", "sse4_1", "SSE4.2",                        "cpu_has(1, 0, 2, 20)"),
    # ammintrin.h also declares AMD's XOP/FMA4 256-bit forms, so it needs immintrin.h's types; the real
    # <intrin.h> includes it right after <immintrin.h> for the same reason.
    ("sse4a",  "ammintrin.h", "avx",    "SSE4A, XOP and FMA4 (AMD only)", "cpu_has(0x80000001, 0, 2, 6)"),
    ("aes",    "wmmintrin.h", "sse4_2", "AES-NI and PCLMULQDQ",          "cpu_has(1, 0, 2, 25) && cpu_has(1, 0, 2, 1)"),
    ("avx",    "immintrin.h", "aes",    "AVX, AVX2, FMA, F16C, BMI1/2 and everything else immintrin.h declares", "os_avx() && cpu_has(1, 0, 2, 28) && cpu_has(7, 0, 1, 5) && cpu_has(1, 0, 2, 12) && cpu_has(1, 0, 2, 29) && cpu_has(7, 0, 1, 3) && cpu_has(7, 0, 1, 8)"),
    ("avx512", "zmmintrin.h", "avx",    "AVX-512 (F, DQ, BW, VL and the later subsets zmmintrin.h declares)", "os_avx512() && cpu_has(7, 0, 1, 16) && cpu_has(7, 0, 1, 17) && cpu_has(7, 0, 1, 30) && cpu_has(7, 0, 1, 31)"),
]

# intrin.h wraps each declaration in a per-architecture macro; these are the x64 ones.
X64_WRAPPERS = ("__MACHINE", "__MACHINEX64", "__MACHINEX86_X64", "__MACHINEX86_X64_ARM64", "__MACHINEARM64_X64",
                "__MACHINEARM_ARM64_X64")   # "ARM and 64-bit Arch": the 64-bit interlocked family lives here

VECTOR_TYPES = ["__m64", "__m128", "__m128i", "__m128d", "__m256", "__m256i", "__m256d",
                "__m512", "__m512i", "__m512d", "__m128bh", "__m256bh", "__m512bh",
                "__m128h", "__m256h", "__m512h", "__mmask8", "__mmask16", "__mmask32", "__mmask64"]

# Intrinsics the test must compile but never execute: they terminate the process, hang, corrupt
# thread state, or change FP behaviour for everything after them. Privileged ones that merely
# fault are left to SEH, which reports them.
NEVER_RUN = re.compile(r"^(__fastfail|__int2c|__debugbreak|_mm_setcsr|__writeeflags|__write(gs|fs)\w*|__add(gs|fs)\w*|__inc(gs|fs)\w*|"
                       r"__svm_\w+|__vmx_\w+|__nvreg\w+|__halt|_mm_monitor\w*|_mm_mwait\w*|__umwait|__umonitor|__tpause|__lwp\w+|__[sl]lwpcb|"
                       r"_enclu|_encls|_enclv|_pconfig|_xabort|_xbegin|_xend|_xtest|_rsm|_disable|_enable|__invd|__wbinvd|__invlpg|__lidt|__lgdt|"
                       r"__out\w*|__in\w*|_xsaves\w*|_xrstors\w*|_xsetbv|__writemsr|__writecr\w*|__writedr\w*|__readcr\w*|__readdr\w*|__readmsr|"
                       r"_invpcid|__ud2|_serialize|__hlt|_mm_stream_load_si128|__movdir64b|_enqcmd\w*|_ptwrite\w*|__rdpmc|__readpmc|_mm_clwb|_mm_clflushopt|"
                       # supervisor-only (WRUSS, HRESET): they raise #GP, which Windows reports as an access
                       # violation rather than STATUS_PRIVILEGED_INSTRUCTION, so SEH cannot classify them
                       r"_wrussd|_wrussq|_hreset)$")
# Divisor operands: a zero divisor traps (#DE) in _udiv128/_div128/_udiv64/_div64 and inside the SVML
# routines behind _mm*_div_ep*/_rem_ep*/_divrem_ep*. Faulting INSIDE an SVML routine is worse than
# the trap itself: those routines carry no unwind data, so the SEH unwind restored garbage into the
# caller's callee-saved registers (a family tally printed -252). Divisors are therefore 1 / all-ones.
SCALAR_DIV_RE = re.compile(r"div(64|128)$")
VECTOR_DIV_RE = re.compile(r"_(div|rem|divrem)_ep[iu]\d+$")


def read(name):
    with open(os.path.join(TOOLSET, name), encoding="latin-1") as f:
        return f.read()


def prep(text):
    text = re.sub(r"\\\r?\n", " ", text)                       # line continuations
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)          # block comments
    text = re.sub(r"//[^\n]*", "", text)                        # line comments
    return arch_filter(text)


# The preprocessor conditions the generator evaluates, as an x64 C++ build of a normal (non-Windows-
# internal) program sees them. A condition naming anything else is kept with ALL its branches and
# its directive lines left in the text, which is how extract_inlines recognises a helper it must not
# take. Evaluating these is what keeps x86-only MMX declarations (everything under _M_IX86) out.
KNOWN_MACROS = {"_M_X64": True, "__cplusplus": True,
                "_M_IX86": False, "_M_ARM64": False, "_M_ARM64EC": False, "_M_HYBRID_X86_ARM64": False,
                "_M_CEE_PURE": False, "__midl": False, "__ICL": False, "_CRT_WINDOWS": False,
                "UNDOCKED_WINDOWS_UCRT": False, "USE_SOFT_INTRINSICS": False, "_CHPE_ONLY_": False,
                "_DISABLE_SOFTINTRIN_": False, "__clang__": False, "__EDG__": False, "__CUDACC__": False}


def eval_cond(expr):
    """True/False for a condition built only from KNOWN_MACROS, None if it mentions anything else."""
    e = re.sub(r"defined\s*\(?\s*(\w+)\s*\)?",
               lambda m: "?" if m.group(1) not in KNOWN_MACROS else ("1" if KNOWN_MACROS[m.group(1)] else "0"), expr)
    e = e.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    if not re.fullmatch(r"(?:\s|[01()]|\band\b|\bor\b|\bnot\b)+", e):
        return None
    return bool(eval(e))


def arch_filter(text):
    """Drop the branches of #if/#ifdef/#ifndef/#elif/#else that KNOWN_MACROS decide against."""
    out, stack = [], []          # frame: known (we decided it), emit (this branch is live), taken (a branch was)
    for line in text.split("\n"):
        m = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)", line)
        if not m:
            if all(f["emit"] for f in stack):
                out.append(line)
            continue
        kind, rest = m.group(1), m.group(2).strip()
        if kind in ("if", "ifdef", "ifndef"):
            outer = all(f["emit"] for f in stack)
            cond = rest if kind == "if" else f"defined({rest})" if kind == "ifdef" else f"!defined({rest})"
            v = eval_cond(cond) if outer else False
            if v is None:
                stack.append(dict(known=False, emit=outer, taken=False))
                out.append(line)
            else:
                stack.append(dict(known=True, emit=outer and v, taken=v))
            continue
        f = stack[-1]
        outer = all(g["emit"] for g in stack[:-1])
        if not f["known"]:
            if kind == "endif":
                stack.pop()
            out.append(line)
        elif kind == "endif":
            stack.pop()
        elif kind == "else":
            f["emit"] = outer and not f["taken"]
        else:                                                   # elif
            v = eval_cond(rest) if (outer and not f["taken"]) else False
            f["emit"] = outer and not f["taken"] and bool(v)
            f["taken"] = f["taken"] or bool(v)
    return "\n".join(out)


def include_guard(text):
    m = re.search(r"#\s*ifndef\s+(\w+)\s*\n\s*#\s*define\s+\1\b", text)
    return m.group(1) if m else None


def split_top(s, sep=","):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def no_declspec(decl):
    """A leading __declspec(...) has its own (possibly nested) parentheses; drop it before parsing."""
    while True:
        m = re.search(r"__declspec\s*\(", decl)
        if not m:
            return decl
        i, depth = m.end(), 1
        while i < len(decl) and depth:
            if decl[i] == "(":
                depth += 1
            elif decl[i] == ")":
                depth -= 1
            i += 1
        decl = (decl[:m.start()] + decl[i:]).strip()


# SAL annotations expand to nothing in the real headers (sal.h); we have no sal.h, so drop them.
SAL = re.compile(r"\b_NODISCARD\b|\b_[A-Z][A-Za-z0-9_]*_\b(?:\s*\([^()]*\))?")   # _In_, _Check_return_, _Out_writes_(n) ...


def strip_sal(decl):
    return " ".join(SAL.sub(" ", decl).split())


MODIFIER_WORDS = {"const", "volatile", "__unaligned", "__restrict", "__cdecl", "__stdcall", "__fastcall",
                  "__vectorcall", "__inline", "static", "extern", "unsigned", "signed", "constexpr", "noexcept"}

# Privileged AMD SEV-SNP helpers whose header declarations do not even match the compiler's own
# signature table (cl warns "incorrect number of arguments for intrinsic function"). Unusable in
# user mode anyway.
SKIP_NAMES = {"__rmpupdate", "__psmash", "__rmpadjust", "__pvalidate", "__rmpquery", "__rmpread", "__svm_invlpgb",
              # CRT library functions, not intrinsics: xmmintrin.h declares them only for the Intel compiler
              # (#ifdef __ICL), so re-exporting them would fail whenever the real header comes first.
              "_mm_malloc", "_mm_free"}


def uses_unknown_type(decl, known):
    """True if the return type or any parameter names a type we neither have builtin nor emit."""
    decl = no_declspec(decl)
    name = fn_name(decl)
    if name is None:
        return True
    head = decl[:decl.index(name)]
    words = re.findall(r"[A-Za-z_]\w*", head)
    for p in params_of(decl):
        words += re.findall(r"[A-Za-z_]\w*", param_type(p))
    return any(w not in known and w not in MODIFIER_WORDS for w in words)


def fn_name(decl):
    """Name of the function being declared: the identifier just before the first '('."""
    m = re.search(r"(\w+)\s*\(", no_declspec(decl))
    return m.group(1) if m else None


def params_of(decl):
    decl = no_declspec(decl)
    lp = decl.index("(")
    depth, i = 0, lp
    while i < len(decl):
        if decl[i] == "(":
            depth += 1
        elif decl[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    inner = decl[lp + 1:i].strip()
    if inner in ("", "void"):
        return []
    return split_top(inner)


TYPE_WORDS = {"int", "char", "short", "long", "float", "double", "void", "unsigned", "signed", "const", "volatile",
              "__int64", "__int32", "__int16", "__int8", "size_t", "__cdecl", "bool", "wchar_t", "__wchar_t"} | set(VECTOR_TYPES)


def param_type(p):
    """Strip the parameter name (if any) from a parameter declaration, keeping array-ness."""
    p = p.strip()
    arr = ""
    m = re.search(r"\[\s*(\d*)\s*\]\s*$", p)
    if m:
        arr = "[" + m.group(1) + "]"
        p = p[:m.start()].strip()
    toks = re.findall(r"\w+|\*|&", p)
    if len(toks) >= 2 and re.match(r"^\w+$", toks[-1]) and toks[-1] not in TYPE_WORDS:
        p = p[:p.rfind(toks[-1])].strip()
    return p + arr


def extract_externs(text):
    out, pos = [], 0
    while True:
        m = re.search(r"\bextern\b", text[pos:])
        if not m:
            break
        start = pos + m.end()
        if text[start:start + 8].lstrip().startswith('"C"'):
            pos = start
            continue
        end = text.find(";", start)
        if end < 0:
            break
        decl = " ".join(text[start:end].split())
        pos = end + 1
        if "(" not in decl:
            continue
        out.append(decl)
    return out


def extract_extern_data(text):
    """extern DATA declarations (immintrin.h's __isa_inverted, __avx10_version): the inline ISA helpers use them."""
    return [" ".join(m.group(0).split()) for m in re.finditer(r"^[ \t]*extern\s+[\w ]+?\s+\w+\s*;", text, flags=re.M)]


BARE_DECL = re.compile(r"^[ \t]*((?:const\s+)?(?:unsigned\s+|signed\s+)?"
                       r"(?:__m\d+[a-z]*|__mmask\d+|__int64|__int32|__int16|__int8|int|long|short|char|float|double|void|size_t)"
                       r"[\s\*]*?(?:__cdecl\s+)?(_\w+))\s*\(([^;{}]*)\)\s*;", re.M)


def extract_bare(text):
    """Declarations written without the extern keyword, which is how ammintrin.h declares SSE4A."""
    out = []
    for m in BARE_DECL.finditer(text):
        decl = " ".join((m.group(1) + "(" + m.group(3) + ")").split())
        out.append(decl)
    return out


def extract_wrapped(text):
    """intrin.h: declarations wrapped as __MACHINEX64(decl) etc. Returns the x64 ones."""
    out = []
    for m in re.finditer(r"\b(__MACHINE[A-Z0-9_]*)\s*\(", text):
        if m.group(1) not in X64_WRAPPERS:
            continue
        i, depth = m.end(), 1
        while i < len(text) and depth:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        decl = " ".join(text[m.end():i - 1].split())
        if "(" not in decl:
            continue
        out.append(decl)
    return out


def extract_defines(text, guard):
    out = []
    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+(\w+)(.*)$", text, flags=re.M):
        name, body = m.group(1), m.group(2)
        if name == guard or name.startswith("_INCLUDED_") or name.endswith("_H_INCLUDED") or name.endswith("_H_"):
            continue
        out.append(("#define " + name + body).rstrip())
    return out


def extract_inlines(text):
    """inline function definitions (brace matched): immintrin.h's __check_isa_support & co."""
    out = []
    for m in re.finditer(r"(?:static\s+)?\b(?:__inline|inline)\b[^;{]*\{", text):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[m.start():i]
        if re.search(r"^[ \t]*#", body, flags=re.M):
            continue        # straddles a preprocessor conditional we could not decide
        out.append(body.strip())
    return out


def extract_types(text):
    """typedef union/struct ... NAME; blocks: the vector types, ammintrin.h's plain SEV-SNP structs
    (a later real <intrin.h> declares functions over them, so a stand-in must define them), plus the
    one-line typedefs."""
    blocks = []
    for m in re.finditer(r"typedef\s+(union|struct)\b[^{;]*\{", text):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        end = text.find(";", i)
        block = text[m.start():end + 1]
        name = re.search(r"\}\s*(\w+)\s*;", block).group(1)
        blocks.append((name, re.sub(r"[ \t]+", " ", block).strip()))
    for m in re.finditer(r"^[ \t]*typedef\s+([\w ]+?)\s+(__mmask\d+|__m\d+bh|__m\d+h|__bfloat16|__tile)\s*;", text, flags=re.M):
        blocks.append((m.group(2), f"typedef {m.group(1).strip()} {m.group(2)};"))
    for m in re.finditer(r"typedef\s+enum\s*\{", text):            # e.g. _MM_MANTISSA_NORM_ENUM (getmant)
        close = text.find("}", m.end())
        end = text.find(";", close)
        block = text[m.start():end + 1]
        name = re.search(r"\}\s*(\w+)\s*;", block).group(1)
        # keep the newlines: some enum bodies carry #if/#endif lines, which must stay on their own
        block = "\n".join(l.rstrip() for l in re.sub(r"[ \t]+", " ", block).splitlines() if l.strip())
        blocks.append((name, block))
    return blocks


# ------------------------------------------------------------------ argument synthesis for the test

# Declared but not called by the test: their argument must be something no synthesiser can
# produce (a string literal naming a code segment).
NO_CALL = {"__code_seg",                              # wants a string literal naming a segment
           "_m_prefetchit0", "_m_prefetchit1",         # PREFETCHIT: the operand must be a code address
           "_rdpid_u32",                               # MSVC 14.44 internal compiler error generating RDPID
           # Declared by the toolset header but NOT provided by the compiler -- the link test found it
           # as an unresolved external: _m_prefetchrs (PREFETCHRST2) is declared ahead of an
           # implementation in 14.44.
           "_m_prefetchrs"}
# Declared, not called: MSVC 14.44 hits an internal compiler error generating these (FP16
# compare with an explicit rounding/SAE operand). A toolset bug, recorded so it is not re-found.
NO_CALL_RE = re.compile(r"_cmp_round_\w+_mask$")

ENUM_TYPES = set()   # enum type names the headers define; filled in by main() before the test is written


def is_integral(t):
    return not ("*" in t or "&" in t or "[" in t or "float" in t or "double" in t
                or any(t.endswith(v) or t == v or t == "const " + v for v in VECTOR_TYPES))


def synth_args(decl):
    """One argument expression per parameter, chosen so the call compiles and is safe to run."""
    fname = fn_name(decl)
    if fname == "__builtin_assume_aligned":
        return "(const void *)buf, 16"                  # (pointer, alignment, offsets...): a hint, needs a real power of two
    ps = params_of(decl)
    types = [" ".join(param_type(p).split()) for p in ps]
    last_int = max((i for i, t in enumerate(types) if is_integral(t)), default=-1)
    last_vec = max((i for i, t in enumerate(types) if not is_integral(t) and "*" not in t and "&" not in t
                    and "float" not in t and "double" not in t), default=-1)
    args = []
    tile_no = 0                                         # AMX: tile operands must be distinct immediates
    for i, (p, t) in enumerate(zip(ps, types)):
        if t.replace("const ", "") in ENUM_TYPES:
            args.append(f"({t.replace('const ', '')})0")   # C++ will not convert int to an enum implicitly
            continue
        if fname.startswith("_tile_") and is_integral(t):
            args.append(str(tile_no))
            tile_no += 1
            continue
        if ("gather" in fname or "scatter" in fname) and is_integral(t):
            args.append("1")                            # scale (1/2/4/8) and prefetch hint (T0 = 1) are both valid at 1
            continue
        if "[" in t:
            args.append("qbuf" if ("size_t" in t or "__int64" in t) else "info4")
        elif "*" in t or "&" in t:
            args.append(f"({t})buf")
        elif not is_integral(t):
            v = next(v for v in VECTOR_TYPES if t.endswith(v) or t == v or t == "const " + v) if "float" not in t and "double" not in t else None
            if v is not None:
                # A CONSTANT mask trips an internal compiler error in MSVC 14.44 while it folds the
                # k-register logic intrinsics (_kor_mask*, _kxor_mask*, ...); a volatile source does not.
                # Divisors get the all-ones vector (see VECTOR_DIV_RE). So does the mask of a masked AVX2
                # gather: with src, index and mask all the same zero value the compiler may put them in
                # one register, and VPGATHER raises #UD unless the three registers are distinct.
                ones = (i == last_vec and VECTOR_DIV_RE.search(fname)) or ("gather" in fname and "mask_i" in fname and i == 3)
                args.append(f"({v})g_mask" if v.startswith("__mmask") else ("o_" if ones else "z_") + v.lstrip("_"))
            else:
                args.append("0.0f" if "float" in t else "0.0")
        elif i == last_int and ("gather" in fname or "scatter" in fname):
            args.append("1")                            # scale: must be 1, 2, 4 or 8
        elif i == last_int and SCALAR_DIV_RE.search(fname):
            args.append("1")                            # divisor; dividend stays 0 so 128/64 cannot overflow
        elif i == last_int and ("_round" in fname or "_sae" in fname or "round" in p.lower() or "sae" in p.lower()):
            args.append("8")                            # _MM_FROUND_NO_EXC: 0 is not a valid rounding immediate
        else:
            args.append("0")
    return ", ".join(args)


def ret_type(decl):
    decl = no_declspec(decl)
    name = fn_name(decl)
    head = decl[:decl.index(name + "(") if (name + "(") in decl else decl.index(name)].strip()
    head = head.replace("__cdecl", "").strip()
    return head


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    fam_info = {}
    # Pass 1: every type any header defines, so pass 2 can tell a real type from a parameter name.
    texts = {}
    for ns, header, parent, desc, gate in FAMILIES:
        raw = read(header)
        text = prep(raw)
        if ns == "x64":
            # intrin.h keeps the intrinsics the STL itself needs (_umul128, _BitScanForward64, the
            # interlocked family, ...) in intrin0.inl.h, which it includes; the x64 family is both.
            # That file spells the calling convention with a macro that is empty on x64.
            raw = read("intrin0.inl.h") + "\n" + raw
            text = prep(raw).replace("__MACHINECALL_CDECL_OR_DEFAULT", "")
        texts[ns] = (raw, text, include_guard(raw))
    # mmintrin.h on x64 is nothing but the __m64 type (its MMX intrinsics are x86-only), and
    # xmmintrin.h includes it; sse.hpp carries that type under mmintrin's own guard.
    mm_raw = read("mmintrin.h")
    mm_guard, mm_types = include_guard(mm_raw), extract_types(prep(mm_raw))
    fam_types = {ns: (extract_types(texts[ns][1]) if ns != "x64" else []) for ns, *_ in FAMILIES}
    all_types = mm_types + [t for ns, *_ in FAMILIES for t in fam_types[ns]]
    known = set(TYPE_WORDS) | {name for name, _ in all_types}
    ENUM_TYPES.update(name for name, block in all_types if block.startswith("typedef enum"))

    # Pass 2: the declarations. SAL annotations are stripped, _Bool becomes bool, and anything
    # naming a type we neither have builtin nor emit (jmp_buf, AMD SEV structs) is skipped.
    for ns, header, parent, desc, gate in FAMILIES:
        raw, text, guard = texts[ns]
        # immintrin.h includes zmmintrin.h in the MIDDLE and declares its BF16/FP16 intrinsics after
        # it with zmmintrin's typedefs, so avx.hpp is emitted in two segments around avx512.hpp.
        m = re.search(r"^[ \t]*#[ \t]*include[ \t]*<zmmintrin\.h>[^\n]*$", text, flags=re.M) if ns == "avx" else None
        segs = [text[:m.start()], text[m.end():]] if m else [text]
        seen, skipped, segments = set(), [], []
        for seg in segs:
            decls = extract_wrapped(seg) if ns == "x64" else extract_externs(seg) + extract_bare(seg)
            uniq = []
            for d in decls:
                d = strip_sal(re.sub(r"\b_Bool\b", "bool", d))
                n = fn_name(d)
                if not n or n in seen:
                    continue
                seen.add(n)
                if n in SKIP_NAMES or uses_unknown_type(d, known):
                    skipped.append(n)
                    continue
                uniq.append(d)
            segments.append(dict(decls=uniq,
                                 types=extract_types(seg) if ns != "x64" else [],
                                 data=extract_extern_data(seg) if ns != "x64" else [],
                                 inlines=extract_inlines(seg) if ns != "x64" else [],
                                 defines=extract_defines(seg, guard) if ns != "x64" else []))
        decls = [d for s in segments for d in s["decls"]]
        defines = [d for s in segments for d in s["defines"]]
        inlines = [b for s in segments for b in s["inlines"]]
        macro_names = {re.match(r"#define\s+(\w+)", d).group(1) for d in defines}
        fam_info[ns] = dict(header=header, parent=parent, desc=desc, gate=gate, guard=guard, segments=segments,
                            decls=decls, defines=defines, inlines=inlines, macros=macro_names, skipped=skipped)

    # ---- types.hpp: only what every family needs and no toolset header owns ----
    with open(os.path.join(OUT_DIR, "types.hpp"), "w", encoding="utf-8") as f:
        f.write("// Generated by tools/gen_intrin.py -- do not edit.\n"
                "// size_t is not a builtin. The toolset declares it as exactly this, and an identical typedef may\n"
                "// be repeated, so this is safe whether or not a CRT header came first. The vector, mask and enum\n"
                "// types live in the family header that stands in for the toolset header defining them.\n"
                "#pragma once\n\n"
                "typedef unsigned __int64 size_t;\n")

    # ---- one header per family: a drop-in for the toolset header ----
    # Everything the real header has on x64 -- its types, declarations, macros, inline helpers -- under
    # its include guard, and the guard DEFINED at the end. Either order then works in one translation
    # unit: real header first, ours is skipped and the using-declarations bind to its names; ours first,
    # the real one is skipped and finds nothing missing. (The types are what forces this: a union cannot
    # be defined twice, so whichever header comes second must skip.)
    ASSERTS = {"__m128i": 16, "__m256i": 32, "__m512i": 64}
    seen_types, total = set(), 0
    for ns, header, parent, desc, gate in FAMILIES:
        fi = fam_info[ns]
        path = os.path.join(OUT_DIR, ns + ".hpp")
        with open(path, "w", encoding="utf-8") as f:
            # A classic guard rather than #pragma once, placed AFTER the parent include: avx.hpp and
            # avx512.hpp include each other (as immintrin.h and zmmintrin.h do), and whichever is
            # included first must let the other re-enter it once to finish the job.
            own = f"KSTL_INTRIN_{ns.upper()}_HPP"
            f.write(f"// Generated by tools/gen_intrin.py from <{header}> (MSVC toolset) -- do not edit.\n"
                    f"// {desc}.\n"
                    f"// {len(fi['decls'])} intrinsics. Declared at global scope with C linkage exactly as the real header\n"
                    f"// does, under its include guard (which this file also defines, so the two can be mixed in\n"
                    f"// either order); kstl::{ns} then re-exports every name, so kstl::{ns}::name(...) or\n"
                    f"// `using namespace kstl::{ns};` works with no SDK header included.\n")
            f.write('#include "types.hpp"\n')
            if parent:
                f.write(f'#include "{parent}.hpp"\n')
            f.write(f"\n#ifndef {own}\n#define {own}\n\n")
            if ns == "x64":
                # intrin.h has no guard we can honour usefully: it also includes the SDK's own CRT headers,
                # so a later real <intrin.h> must still run. Its declarations simply repeat ours.
                f.write('extern "C" {\n')
                for d in fi["decls"]:
                    f.write(d + ";\n")
                f.write("}\n\n")
            else:
                if ns == "sse":
                    f.write(f"#ifndef {mm_guard}\n")
                    for name, block in mm_types:
                        f.write(block + "\n")
                    f.write(f"#define {mm_guard}\n#endif  // {mm_guard}\n\n")
                f.write(f"#ifndef {fi['guard']}\n")
                owned = []
                for k, seg in enumerate(fi["segments"]):
                    if k:
                        f.write('#include "avx512.hpp"   // immintrin.h includes zmmintrin.h here, ahead of its BF16/FP16 declarations\n')
                    for name, block in seg["types"]:
                        if name in seen_types:
                            continue
                        seen_types.add(name)
                        owned.append(name)
                        f.write(block + "\n")
                    f.write('extern "C" {\n')
                    for d in seg["data"]:
                        f.write(d + "\n")
                    for d in seg["decls"]:
                        f.write(d + ";\n")
                    f.write("}\n")
                    for d in seg["defines"]:
                        f.write(d + "\n")
                    if seg["inlines"]:                  # after the macros: the ISA helpers use __IA_SUPPORT_*
                        f.write('extern "C" {\n')
                        for b in seg["inlines"]:
                            f.write(b + "\n")
                        f.write("}\n")
                f.write(f"#define {fi['guard']}\n#endif  // {fi['guard']}\n")
                for name in owned:
                    if name in ASSERTS:
                        f.write(f'static_assert(sizeof({name}) == {ASSERTS[name]} && alignof({name}) == {ASSERTS[name]}, "{name} layout");\n')
                f.write("\n")
            f.write(f"namespace kstl {{ namespace {ns} {{\n")
            for d in fi["decls"]:
                n = fn_name(d)
                if n in fi["macros"]:
                    continue                            # a function-like macro shadows it; the macro works unqualified
                f.write(f"using ::{n};\n")
            f.write("} }\n")
            if ns == "avx":
                f.write('\n#include "avx512.hpp"   // so avx.hpp brings kstl::avx512 even when the real immintrin.h came first\n')
            f.write(f"\n#endif  // {own}\n")
        total += len(fi["decls"])
        sk = fi["skipped"]
        print(f"{ns:8s} {header:14s} {len(fi['decls']):5d} intrinsics  {len(fi['defines']):4d} defines  {len(fi['inlines']):3d} inline helpers"
              f"  skipped {len(sk):2d}{(' (' + ', '.join(sk[:6]) + (', ...' if len(sk) > 6 else '') + ')') if sk else ''}")
    print(f"total    {total} intrinsics")

    # ---- umbrella ----
    with open(UMBRELLA, "w", encoding="utf-8") as f:
        f.write("// kstl/intrin.hpp -- every x64 intrinsic the MSVC toolset knows, declared ourselves so nothing\n"
                "// needs <intrin.h>, <emmintrin.h>, <immintrin.h> or friends. One file per instruction-set family\n"
                "// under intrin/, each with a kstl::<family> namespace; this umbrella includes them all. Include\n"
                "// only the family you need in hot headers (hash_map.hpp takes x64 and sse2) -- this file is for\n"
                "// convenience and for the test that exercises everything.\n"
                "//\n"
                "// Generated by tools/gen_intrin.py; regenerate after a toolset update. Every declaration is the\n"
                "// toolset's own, byte for byte, which is what makes MSVC treat the name as an intrinsic.\n"
                "#pragma once\n")
        for ns, *_ in FAMILIES:
            f.write(f'#include "intrin/{ns}.hpp"\n')

    # ---- the test that calls everything: one translation unit per chunk ----
    # A single unit of ~8k calls trips an internal compiler error in MSVC 14.44 that no individual
    # chunk reproduces (each of the 343 compiles clean on its own), so every chunk is its own file
    # and cl /MP compiles them in parallel; main.cpp gates each family on CPUID and runs it.
    import shutil
    shutil.rmtree(BENCH_DIR, ignore_errors=True)
    os.makedirs(BENCH_DIR)
    with open(os.path.join(BENCH_DIR, "common.hpp"), "w", encoding="utf-8") as f:
        f.write("// Generated by tools/gen_intrin.py -- do not edit. Shared by every chunk of the every-intrinsic\n"
                "// test; the statics are per translation unit on purpose (scratch only).\n"
                "#pragma once\n"
                '#include "kstl/intrin.hpp"\n\n'
                "static volatile unsigned long long g_sink;\n"
                "static volatile bool g_never = false;                  // guards intrinsics that must not run\n"
                "__declspec(align(64)) static unsigned char buf[8192];  // scratch for every pointer argument\n"
                "static int info4[4];                                   // int[4] parameters (cpuid)\n"
                "static unsigned __int64 qbuf[64];                      // size_t[] parameters (SGX, pconfig)\n"
                "static volatile unsigned __int64 g_mask = 0;           // __mmask arguments: must not be a constant (MSVC ICE)\n"
                "template <class T> static void sink(const T &v) { g_sink += *reinterpret_cast<const unsigned char *>(&v); }\n"
                'extern "C" int printf(const char *, ...);\n'
                'extern "C" unsigned long __cdecl _exception_code(void);   // valid inside an __except filter\n'
                "extern int g_privileged, g_unsupported, g_other;         // defined in main.cpp\n"
                "static unsigned long g_code;\n"
                "// Classify a fault. Privileged and unsupported instructions are EXPECTED in user mode on a\n"
                "// given CPU and do not fail the test; anything else does.\n"
                "static int note(const char *name, unsigned long code)\n"
                "{\n"
                "  if ( code == 0xC0000096ul ) { ++g_privileged;  printf(\"    %-36s privileged instruction (expected in user mode)\\n\", name); return 0; }\n"
                "  if ( code == 0xC000001Dul ) { ++g_unsupported; printf(\"    %-36s not supported by this CPU\\n\", name); return 0; }\n"
                "  ++g_other; printf(\"    %-36s FAULT 0x%08lX\\n\", name, code); return 1;\n"
                "}\n")
    LOCALS = ("  __m64 z_m64 = {}; (void)z_m64;\n"
              "  __m128 z_m128 = {}; __m128i z_m128i = {}; __m128d z_m128d = {};\n"
              "  __m256 z_m256 = {}; __m256i z_m256i = {}; __m256d z_m256d = {};\n"
              "  __m512 z_m512 = {}; __m512i z_m512i = {}; __m512d z_m512d = {};\n"
              "  __m128bh z_m128bh = {}; __m256bh z_m256bh = {}; __m512bh z_m512bh = {};\n"
              "  __m128h z_m128h = {}; __m256h z_m256h = {}; __m512h z_m512h = {};\n"
              "  (void)z_m128; (void)z_m128i; (void)z_m128d; (void)z_m256; (void)z_m256i; (void)z_m256d;\n"
              "  (void)z_m512; (void)z_m512i; (void)z_m512d; (void)z_m128bh; (void)z_m256bh; (void)z_m512bh;\n"
              "  (void)z_m128h; (void)z_m256h; (void)z_m512h; (void)info4; (void)qbuf;\n"
              # all-ones vectors (every lane nonzero, sign bits clear): divisors and gather masks
              f"  __m128 o_m128 = {{{{{', '.join(['1.f'] * 4)}}}}}; __m128d o_m128d = {{{{1.0, 1.0}}}}; __m128i o_m128i = {{{{{', '.join(['1'] * 16)}}}}};\n"
              f"  __m256 o_m256 = {{{{{', '.join(['1.f'] * 8)}}}}}; __m256d o_m256d = {{{{{', '.join(['1.0'] * 4)}}}}}; __m256i o_m256i = {{{{{', '.join(['1'] * 32)}}}}};\n"
              f"  __m512 o_m512 = {{{{{', '.join(['1.f'] * 16)}}}}}; __m512d o_m512d = {{{{{', '.join(['1.0'] * 8)}}}}}; __m512i o_m512i = {{{{{', '.join(['1'] * 64)}}}}};\n"
              "  (void)o_m128; (void)o_m128d; (void)o_m128i; (void)o_m256; (void)o_m256d; (void)o_m256i; (void)o_m512; (void)o_m512d; (void)o_m512i;\n")
    CH = 24
    plan = {}                                   # ns -> list of chunks (each a list of decls)
    nfiles = 1
    for ns, header, parent, desc, gate in FAMILIES:
        decls = fam_info[ns]["decls"]
        chunks = [decls[i:i + CH] for i in range(0, len(decls), CH)]
        plan[ns] = chunks
        for ci, chunk in enumerate(chunks):
            with open(os.path.join(BENCH_DIR, f"chunk_{ns}_{ci}.cpp"), "w", encoding="utf-8") as f:
                f.write(f"// Generated by tools/gen_intrin.py -- do not edit. {ns} intrinsics {ci * CH}..{ci * CH + len(chunk) - 1}.\n"
                        '#include "common.hpp"\n\n'
                        f"int chunk_{ns}_{ci}()   // returns the number of REAL faults (privileged/unsupported are expected)\n{{\n" + LOCALS + "  int bad = 0;\n")
                for d in chunk:
                    n = fn_name(d)
                    if n in NO_CALL or NO_CALL_RE.search(n):
                        f.write(f"  // {n}: declared, not called (see NO_CALL in gen_intrin.py)\n")
                        continue
                    call = f"{n}({synth_args(d)})"
                    stmt = f"{call};" if ret_type(d) == "void" else f"sink({call});"
                    if NEVER_RUN.match(n):
                        f.write(f"  if ( g_never ) {{ {stmt} }}   // compiled, never executed\n")
                    else:
                        f.write(f"  __try {{ {stmt} }} __except ( g_code = _exception_code(), 1 ) {{ bad += note(\"{n}\", g_code); }}\n")
                f.write("  return bad;\n}\n")
            nfiles += 1
    with open(os.path.join(BENCH_DIR, "main.cpp"), "w", encoding="utf-8") as f:
        f.write("// Generated by tools/gen_intrin.py -- do not edit. Calls EVERY intrinsic declared in kstl/intrin.hpp,\n"
                "// in translation units that include nothing else. Compiling and linking this is the proof that each\n"
                "// name is one MSVC accepts as an intrinsic (an unrecognised one would be an unresolved external).\n"
                "// Running it executes each family the CPU supports; every call sits in its own SEH guard, so a\n"
                "// privileged instruction (0xC0000096) or one this CPU lacks (0xC000001D) is tallied and the run\n"
                "// continues; any other fault is a real failure and is named.\n"
                "//   cl /nologo /std:c++17 /O2 /EHsc /MT /MP /I src bench\\intrin_all\\*.cpp /Fe:intrin_all.exe\n"
                '#include "common.hpp"\n\n'
                'extern "C" int printf(const char *, ...);\n'
                "static bool cpu_has(int leaf, int sub, int reg, int bit) { int r[4]; __cpuidex(r, leaf, sub); return ((r[reg] >> bit) & 1) != 0; }\n"
                "static bool os_avx() { if ( !cpu_has(1, 0, 2, 27) ) return false; return (_xgetbv(0) & 6) == 6; }\n"
                "static bool os_avx512() { if ( !os_avx() ) return false; return (_xgetbv(0) & 0xE0) == 0xE0; }\n\n")
        for ns, chunks in plan.items():
            for ci in range(len(chunks)):
                f.write(f"int chunk_{ns}_{ci}();\n")
        f.write("\nint g_privileged, g_unsupported, g_other;   // tallied by note() in every chunk unit\n\n")
        for ns, header, parent, desc, gate in FAMILIES:
            decls = fam_info[ns]["decls"]
            chunks = plan[ns]
            f.write(f"static int run_{ns}()   // returns the number of REAL faults in this family\n{{\n")
            f.write(f"  if ( !({gate}) )\n  {{\n    printf(\"  %-7s %5d intrinsics  compiled+linked; execution skipped, this CPU lacks the feature\\n\", \"{ns}\", {len(decls)});\n    return 0;\n  }}\n")
            f.write(f"  int p0 = g_privileged, u0 = g_unsupported, bad = 0;\n")
            for ci in range(len(chunks)):
                f.write(f"  bad += chunk_{ns}_{ci}();\n")
            f.write(f"  printf(\"  %-7s %5d intrinsics  executed; %d privileged, %d unsupported here, %d real faults\\n\", \"{ns}\", {len(decls)}, g_privileged - p0, g_unsupported - u0, bad);\n")
            f.write(f"  return bad;\n}}\n\n")
        f.write("int main()\n{\n  int bad = 0;\n"
                f"  printf(\"intrin_all_check: {total} intrinsics across {len(FAMILIES)} families, header-free. Every one compiled and linked.\\n\");\n")
        for ns, *_ in FAMILIES:
            f.write(f"  bad += run_{ns}();\n")
        f.write(f"  printf(\"%s: %d privileged (expected in user mode), %d unsupported by this CPU, %d real faults (sink=%llu)\\n\", bad == 0 ? \"ALL INTRINSICS OK\" : \"REAL FAULTS\", g_privileged, g_unsupported, bad, g_sink);\n"
                f"  return bad == 0 ? 0 : 1;\n}}\n")
    print(f"wrote {nfiles} files under {os.path.relpath(BENCH_DIR, ROOT)}")


if __name__ == "__main__":
    main()
