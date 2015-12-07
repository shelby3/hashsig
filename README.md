# hashsig

One-time use hash-based signatures employing 2-bit Winternitz chunks and the BLAKE2 cryptographic hash functions.

Refer to /[DDoS Defense Employing Public Key Cryptography.md] for detailed rationale.

### Build

Emscripten compile with:

```sh
emcc blake/blake.c byteio/byteio.c hashsig/hashsig.c winternitz/winternitz.c main.c -o main.html
```

### Added Subrepositories

   Subrepository   | [Added] As  |                Revision
-------------------|-------------|-----------------------------------------
shelby3/blake      | /blake      | d67fe98c770078d16db34b7fce26e09667baf304
shelby3/byteio     | /byteio     | 060aa5315a99cf2ec0f12a658f15346fe8eca1fd
shelby3/cmacros    | /cmacros    | b817c6cc5a0231a0ad9bb1e71a69a15df05e4d80
shelby3/winternitz | /winternitz | eafb4d6a478275e6b5ab179bdc172f4dfdf65bec

[Added]: https://gist.github.com/shelby3/f69c969ecaa3ecfbe579#subrepositories
[DDoS Defense Employing Public Key Cryptography.md]: https://github.com/shelby3/hashsig/blob/master/DDoS%20Defense%20Employing%20Public%20Key%20Cryptography.md
