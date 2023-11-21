# ThreadlessStompingKann
Combining 3 techniques (Threadless Injection + DLL Stomping + Caro-Kann) together to evade MDE.

A combination of the techniques Threadless Injection + DLL Stomping + Caro-Kann to evade Microsoft Defender for Endpoint using WinAPI.
Dummy metadata was added to the program to help bypass the execution of file with different original name.

This is the code used for my [blog post here](https://caueb.com/purple-team-lab/threadlessstompingkann/).

# Usage
Use the python script `encrypt.py` to XOR your payload and save it to a new file.
```bash
# python encrypt.py <input_file> <output_file>
python encrypt.py demon.bin caue.gif

# Host the payload
python -m http.server 80
```

Change the `PAYLOAD` variable value to your IP address and file name in the `main.c` file.

The custom shellcode in `hookShellcode` was created following the steps in the https://github.com/S3cur3Th1sSh1t/Caro-Kann and then extracted the hex bytes from the `decryptprotect.bin` file using [this script](https://gist.github.com/caueb/81c4b6b9cc89d9709cc5abc5e5beeb72).

# Credits
- CCob for his Threadless Inject: https://github.com/CCob/ThreadlessInject
- OtterHacker for his DEFCON31 presentation on Threadless Stomping: https://github.com/OtterHacker/Conferences/tree/main/Defcon31
- S3cur3Th1sSh1t for his Caro-Kann: https://github.com/S3cur3Th1sSh1t/Caro-Kann
