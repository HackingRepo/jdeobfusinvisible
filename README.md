This project is designed to undo deobfuscation of Hidden JS created by https://aem1k.com/invisible/encoder/.
This is useful for malware analysis and reverse engineering.

# Contributions
- All contributions are welcome under the Apache License.

# Usage

Basic (file-to-file)
```bash
python3 main.py -i obfuscated.js -o deobfuscated.js
```

Using stdin/stdout (pipe)
```bash
cat obfuscated.js | python3 main.py > deobfuscated.js
```

Quick example (paste an obfuscated blob)
```bash
echo 'PASTE_OBFUSCATED_CODE_HERE' | python3 main.py
```

Notes
- If main.py supports different CLI flags, substitute -i/-o with the script's actual options. If it doesn't accept flags, the stdin/stdout examples should work when the script reads from standard input and writes to standard output.
- For safety, avoid automatically executing decoded JavaScript. Inspect the output before running it in any environment.
- Consider adding a `--dry-run` or `--no-exec` option to show decoded output without executing it.

# Security
This tool can reveal potentially malicious code. Always inspect decoded output in a safe, sandboxed environment and do not run untrusted code on your host machine.
