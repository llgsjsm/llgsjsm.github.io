---
layout: post
title: "TISCDFCTF: wad-is-this"
categories: [ctf]
description: "a runic-obfuscated JavaScript challenge that hides 3 WebAssembly modules implementing a custom password checker"
---

## :: overview

| **Challenge** | wad-is-this |
| **Category** | Reverse Engineering |
| **Flag** | `TISCDCSG{the_f1ag_ch0sen_speci4lly_for_th3_wasm}` |

the challenge name is a pun - WAT is the WebAssembly text format. cute.

## :: first look

we get a single JS file: `wat-is-this.js`. opening it in an editor is immediately cursed:

```js
(()=>(
    ᚠ=+[],
    ᚢ=+!![],
    ᚦ=ᚢ+ᚢ,
    ᚨ=ᚦ+ᚦ,
    ...
```

the entire file is written with Elder Futhark runic characters as variable names - a variant of JSFuck where `0` and `1` are derived from `+[]` and `+!![]`, and everything else is built up from there. the actual logic is buried inside a massive string that gets `eval`'d.

the file is ~2.6MB of this.

## :: deobfuscation

the runic encoding is just cosmetic obfuscation on top of JSFuck-style arithmetic. the pattern:

```js
ᚠ=+[],       // 0
ᚢ=+!![],     // 1
ᚦ=ᚢ+ᚢ,      // 2
ᚨ=ᚦ+ᚦ,      // 4
ᚱ=ᚨ+ᚨ,      // 8
...
```

all variables are just integer constants. with find/replace substitution and some cleanup you get `deobfuscated.js`, which shows the real structure: the script builds two big `Uint8Array`s (`_c1` and `_d2`) used as lookup tables, then dynamically decrypts and instantiates three WebAssembly modules.

the decryption uses a small block cipher built from the lookup tables - each WASM binary is stored encrypted inside the JS and decrypted at runtime before `WebAssembly.instantiate` is called.

## :: extracting the WASM

the patched version adds:

```js
var _Mod=WebAssembly.Module, _Inst=WebAssembly.Instance;
```

and instruments the WASM write path to dump the decrypted bytes to disk:

```js
if(wb[0]===0&&wb[1]===0x61&&wb[2]===0x73&&wb[3]===0x6d){
    require("fs").writeFileSync("wasm_"+(globalThis.__wn++)+".wasm", Buffer.from(wb));
}
```

running it drops three files: `wasm_1.wasm`, `wasm_2.wasm`, `wasm_3.wasm`.

## :: wasm analysis

**wasm_1** - the primitive layer  
exports: `cmix`, `xs`, `memory`  
the `start` function runs on instantiation and uses an xorshift PRNG (`xs`) seeded with a constant to initialize three lookup tables in memory:
- `[64]` - 256-byte S-box (primary substitution)
- `[320]` - 256-byte S-box (secondary substitution)
- `[576]` - 16 x i32 key schedule words

`cmix` is the mixing primitive: `(a + b) rotl 7 xor (b rotl 5)`.

**wasm_2** - the check functions  
imports `cmix` and `memory` from wasm_1, exports: `derive`, `transcript`, `check_a` through `check_c`, `cross_ac`, `cross_ab`, `check_tr`, `transcript2`

`derive` walks 48 bytes at memory[0] with the key schedule and writes 48 derived bytes to memory[640].

`transcript` and friends each compute a 32-bit hash of memory regions, mixing through `cmix` and the S-boxes. each function focuses on a different byte range and rotation of the running state.

**wasm_3** - the final checker  
imports everything from wasm_1 and wasm_2. the key function is `check(ptr, len)`:

```wat
; must be exactly 48 bytes
local.get 1
global.get 0   ; 48
i32.ne
if ... return 0 ...

; hash the input, derive key material
call derive
call transcript → t

; check all six conditions (OR'd together - any nonzero means wrong)
(688[i32] XOR 712[i32] XOR t rotl 0) XOR check_a  →  OR into acc
(692[i32] XOR 716[i32] XOR t rotl 5) XOR check_b  →  OR into acc
(696[i32] XOR 720[i32] XOR t rotl 11) XOR check_c  →  OR into acc
...

; plus transcript2 XOR 800[i32]

acc == 0  →  return 1  (correct)
```

the constants at memory[688..736] and [712..736] are hardcoded in wasm_1's data sections, placed there at startup. the checks are essentially: "does the hash of your password, mixed through our S-box chain, match all six hardcoded values simultaneously?"

## :: getting the flag

since all checks are independent 32-bit comparisons that get OR'd, and the derive/transcript functions are purely deterministic, this is a one-way verifier; you can't algebraically invert it. 

the approach: patch `check` to print the value of each check result at each step, then look for what input makes them all zero. since the flag format is `TISCDCSG{...}` and the length must be exactly 48 we know the prefix. running the patched checker with the known prefix and brute-forcing the unknown segment (or using the fact that the check functions each only depend on a small slice of the derived bytes) lets you recover it chunk by chunk.

alternatively: patch the `check` export to always return 1 and just try to get the script to print the flag - but the flag is never stored plaintext, it's the password itself. the correct password **is** the flag, so:

> if `check(input, 48) == 1`, then `input` is the flag.

running the solver gives: **`TISCDCSG{the_f1ag_ch0sen_speci4lly_for_th3_wasm}`**

## :: tldr

1. runic JSFuck → deobfuscate to get the real script
2. patch JS to dump the three dynamically-decrypted WASM blobs
3. `wasm2wat` each blob to read the logic
4. wasm_1 builds S-boxes via xorshift, wasm_2 implements hash checks, wasm_3 is the final verifier
5. the correct 48-byte password is itself the flag
