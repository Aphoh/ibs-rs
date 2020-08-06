# ibs-rs
---------------
A couple of implementations of Identity-Based Signature Schemes (IBS) with linked papers.

This should not be used in production and is simple a proof-of-concept I wrote to help me understand these schemes.

Implementations:

- [x] [Hes02](https://link.springer.com/content/pdf/10.1007/3-540-36492-7_20.pdf)
    * Signing and Verifying take about the same amount of time
    * User secrets can be split between multiple TAs
- [x] [Pat02](https://eprint.iacr.org/2002/004.pdf) 
    * Signing requires no pairing calculations and is thus fairly efficient
    * Verifying only really requires one pairing computation
    * User secrets can be split between multiple TAs
- [x] [BLM05](https://link.springer.com/chapter/10.1007/11593447_28) 
    * Signing requires no pairing calculations and is thus fairly efficient
    * Verifying only requires one paring calculation and one group operation in `G_t`
    * User secrets cannot be split between multiple TAs without some sort of homomorphic encryption due to how the user secrets are generated
- [ ] [PJ06](https://eprint.iacr.org/2006/080.pdf)
- [ ] [CDC06](https://dl.acm.org/doi/10.1145/1146847.1146869)
- [ ] [Yi03](https://ieeexplore.ieee.org/document/1178892)
