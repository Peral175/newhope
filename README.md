# This is for an academic project!
We are re-using the NewHope reference implementation to mask the NewHope protocol for our academic project.
Our implementation has been added to the ref folder.
Warning: This Code is not for industrial usage. It contains major efficiency issues.


Below are the instructions from the reference implementation.
### NewHopeBuild instructions (for unmasked NewHope)
To obtain and build the code, run the following sequence of commands:
```
 git clone https://github.com/newhopecrypto/newhope.git
 cd newhope/ref && make
 cd ../avx2 && make
```

## License
All code in this repository is in the public domain,
except for the files `PQCgenKAT.c`, `rng.c` and `rng.h`, 
which are copyrighted by NIST with "All rights reserved".
For Keccak, we are using public-domain
code from sources and by authors listed in 
comments on top of the respective files.
