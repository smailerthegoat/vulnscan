# Playbook: memory-safety (C, C++, unsafe Rust)

**CWEs:** 787 out-of-bounds write · 125 out-of-bounds read · 416 use-after-free · 415 double free · 190/191 integer overflow/underflow leading to a bad allocation or index · 134 format string · 476 NULL dereference · 120/121/122 buffer overflow · 369 divide by zero · 401 leaks (low)

## Where to look
- Parsers of untrusted input (file formats, network protocols, headers, TLV, length-prefixed data). They are the highest yield.
- Length arithmetic: `len + 1`, `count * size`, subtracting a header size from an untrusted length, signed/unsigned mixing, truncation from `size_t` to `int`
- Copies: `memcpy`, `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`, manual loops writing `buf[i]` with an attacker-influenced bound
- Lifetimes: pointers kept after `free`/`realloc`, error paths that free and then continue, containers mutated while iterating, callbacks after the owner is destroyed
- `printf(user)`-style format strings
- Rust: `unsafe` blocks, `from_raw_parts`, `get_unchecked`, `transmute`, FFI boundaries, `set_len`

## Method
For each parser entry point, write down which fields are attacker-controlled, follow every size or index
computed from them to its use, and check each bounds check for off-by-one errors, overflow before the
check, and checks on the wrong variable. Cite the exact arithmetic in the attack path.
