# DDoS Defense Employing Public Key Cryptography

A fast rejection signature is an essential ingredient for asymmetric leverage against distributed denial-of-service in many scenarios.

### Distributed denial-of-service (DDoS)

At a high level of abstraction, the ontological taxonomy of denial-of-service attacks categorize into either A) network bandwidth flooding; or B) saturated consumption a resource other than bandwidth[1].

In both cases, the attacker gains leverage by exploiting some asymmetry in the consumption or (uncompensated) cost of the attacked resource.

Bandwidth flooding attacks other than amplification require the attacker to consume a symmetric (equivalent) quantity of bandwidth resources as victim. Any asymmetry in favor of the attacker is due to one or more of:

* amplification[2]
* low cost of a botnet
* out-of-band leverage in the form of financial extortion, removing competition, or (even geo-)political[3]

Asymmetries in favor of a potential victim of bandwidth flooding include:

* hosting providers typically do not charge for incoming bandwidth
* overprovisioning redundant nodes directly on, or on a plurality of distinct narrower pipes to, major internet backbones

### Authentication defense

Asymmetries in the consumption of resources other than bandwidth always depend on authentication of the source so the attacker can be blacklisted.

Other than fixing the design of a protocol to reduce the resource consumed, the only defense against overconsumption of a resource other than bandwidth flooding is authentication. For example this is evident from the “Common Defenses” listed in the RFC for SYN-ACK[4]. Even where “Deep Packet Inspection” is employed[2], this is a form of authenticating the attacker’s fingerprints (patterns).

Authentication of the source is not a potential asymmetry against bandwidth flooding attacks because the bandwidth has to be consumed regardless. Authentication can be employed at a network perimeter so flooding is not forwarded[5].

For the potential victim that has instituted sufficient redundancy to consume bandwidth flooding, asymmetries will be bounded by the cost of authentication relative to the attacker’s cost of creating new identities.

Authentication strategies with high asymmetric leverage (i.e. low resource cost compared to attacker’s cost) typically have a non-negligible false positive rate or are rendered ineffective. For example, filtering strategies which construct an ephemeral blacklist of offending IP addresses (i.e. a distributed attack) suffer from:

* legitimate user’s IPv4 address shared[6] with the botnet attacker; or
* spoofed source IP address; or
* free and disposable addresses due to botnets or IPv6 non-scarce address space

The RFC for SYN-ACK denial-of-service[7] mentions the latter two bulleted items as the reason that “make filtering an impotent solution” (referring to filtering by IP address).

The generative essence is that IP addresses are not generally substitutes for end-to-end principled identification such as public key signatures, because IP addresses are a network layer[8] detail which is and should be (according to the end-to-end principle) be opaque (and orthogonal) to the application on each end of the communication.

Static IP addresses may be suitable in a whitelist authentication scheme. Otherwise, a *public key* authentication is more robust than an IP blacklist. Even securely exchanging a symmetric key without a static IP whitelist requires (such as for SSL/TLS/HTTPS) some variant of a public key Diffie-Hellman exchange.

### Public key authentication

A public key cryptography (PKC) signature of the message being sent can serve as a form of authentication.

The fastest non-batch verification per core (or hyperthread) for a PKC signature scheme[9] based on number-theoretic security is ed25519 at 185k clock cycles on the latest generation Intel Xeon[10], i.e. roughly 18919 verifications per second. Although the roughly[11] equivalent 128-bit security[12], 3072-bit RSA (ronald3072) executes in 121k clock cycles[10], the verification speed and the (public key and signature) size of RSA scales exponentially worse than elliptic curve cryptography (ECC) at higher bit security[13][14][15][16].

Batch verification of ECC (such as for ed25519) is not appropriate against denial-of-service[17] because it does not verify which of the signatures in the batch failed.

Although PKC signature schemes not based on number-theoretic security (thus secure under a quantum computing model) nor hash-based, have verification ranging from twice (for multivariate-quadratic signatures[10][13]) up to perhaps a rough estimate of an order-of-magnitude faster (for Niederreiter CFS[18]), the size of the public keys is four[13] to five[18][19] orders-of-magnitude larger respectively. And these schemes have received much less cryptanalysis scrutiny.

Also it possible to speed up ed25519 by an unknown factor at the cost of doubling the public key size and increasing the signature size by 50%[20].

### Hash-based PKC signatures

Assuming the signed messages are uniformly distributed, verification of the fastest Winternitz configuration (the Merkle-Lamport case with 1-bit chunks) requires (n + log₂(n))÷2 *average* invocations of the n-bit output hash function, plus the cost of applying the hash function to n + log₂(n) n-bit hash function outputs. For a double pipe hash function design[21] such as BLAKE2, this latter cost will be roughly equivalent to the cost of ⌈(n + log₂(n))÷2⌉ invocations of the n-bit output hash function.

Employing instead Winternitz with a 2-bit chunk configuration and because the *average* invocations per every 2 bits of the signed message is unchanged, i.e. 2×(0+1)÷2 = (0+1+2+3)÷4, the latter cost can be roughly halved without significantly increasing the *average* invocations of the former cost.

Assuming there is no viable attack due to random messages (which are collisions), the security of a one-time hash-based PKC signature is equal to its second preimage resistance[22]. Thus to achieve the 128-bit security of ed25519 requires a 128-bit hash function. The performance of the fastest 256-bit hash function (BLAKE2s) on the comparable latest generation Intel Xeon[23] is roughly 350 clock cycles[24]. It may be possible to achieve 175 clock cycles if a 128-bit variant of Blake2 is invented[25] instead of using only 128 bits of the
Blake2s value. Thus employing 2 bit chunked Winternitz, the estimated comparable performance is: 175 × (128÷2 + log₂(3×128÷2)÷2) = 11867 + (either 175 × ⌈(128÷2 + ⌈log₂(3×128÷2)÷2⌉)÷2⌉ = 6125 or 350 × ⌈(128÷2 + ⌈log₂(3×128÷2)÷2⌉)÷4⌉ = 6300) = 17992 clock cycles, not counting the guesstimated 10% non-hash function overhead in the Winternitz verification algorithm. The public key is 16 bytes and the signature is 16 × (128÷2 + log₂(3×128÷2)÷2) = 1104 bytes.

Alternatively if the public key is increased to 1104 or 2208 bytes (2 or 1 bit chunks respectively), the aforementioned latter cost is eliminated reducing verification to 11867 clock cycles for the former cost. But this variant can only be used efficiently with one-time use signatures.

Increasing the number of possible signatures for each public key from one-time to N by employing a Merkle tree, adds log₂(N) more invocations of a hash function to the aforementioned smaller public key case. These log₂(N) invocations must employ a hash function which has double the bit security of the hash function employed for the Winternitz signature, because the security of the Merkle tree depends on the hash function’s collision resistance[26]— because A, B, and C in the following diagram can be random values.

```
           public key
              / \
             *   C
            / \
           *   B
          / \
Winternitz   A
```

The forward security of private keys is the hardness of computing the preimage of the PRNG (which may be a seeded cryptographic hash function) employed to generate the private keys[27], assuming one-time signature private keys are securely disposed after use. The verification of a Merkle tree is independent of any signing optimization[28].

Unlike ed25515, BLAKE2s can exploit AVX2 to achieve roughly double the throughput per core (or hyperthread)[25].

Thus verification of hash-based PKC signatures is estimated to be **roughly 20 times faster than ed25515** with the same public key size (except for the one-time signature which is 50% of the size) but more than one order-of-magnitude larger signature size at 128-bit security and the relative ratio doubling on every doubling of the bit security.

Unlike ECC, the bit security of hash-based signatures does not diminish significantly in a practical quantum computing model[22]. Yet it is conjectured that any future quantum computer will require a qubit for every bit of ECC security[29]. The greatest number of real qubits known to have been constructed so far is only five.

Thus an 8 core Xeon can verify more than 3 million hash-based signatures per second. Given 1104 byte signature size and assuming the payload message size is insignificant, that requires the attacker to have more than 3 gigabytes per second of network bandwidth. One 24 core Xeon server node could consume a 80 Gbps attack, or 160 Gbps for the 2208 byte signature size option. Assuming the payload is 1104 bytes, the hash-based signature can consume between 160 - 240 Gbps and the ed25519 signatures only 4 Gbps.

### Faster PKC signatures defense

In the oft-case where the PKC signature is *only* to rate limit the attacker by employing an ephemeral blacklist, the blacklist does not become eternal until after some number of violations, and/or a slower higher bit security PKC signature is verified after verification of a faster PKC signature so that the legitimate owner of the public key is not eternally blacklisted after an attacker computes a forged signature from a legitimate signature, then it may suffice to make the bit security of the length of the signed message only high enough so that forging is too high of an asymmetric cost for the attacker. Note that the bit security of the private key is not reduced.

For example if signed message must be recursively hashed such that it consumes 0.1 microsecond of compute resources and assuming the collision resistance of the hash function is not reduced from ideal, a 46-bit length of the signed message requires the attacker to expend on average 3,518,437 compute seconds per forgery. So retaining a 128-bit double pipe hash function (so the private key’s security is not reduced) but signing a message only 46 bits in length, reduces the comparable cost to: 175 × [(46÷2 + log₂(3×46÷2)÷2) + ⌈(46÷2 + ⌈log₂(3×46÷2)÷2⌉)÷2⌉] = 9285 clock cycles; which is 2 times faster than signing 128-bit messages. And thus roughly 40 times faster than ed25519, or actually 38.5 times due to additional 0.1 microsecond expended on the recursive hashing. These estimates assume that lookup in a blacklist is an insignificant factor, which is likely true since well designed hash tables consume on the order of 100 clock cycles per lookup[30].

### Distributed authentication

In the scenario where the same public key is accepted by numerous nodes performing the same service, the attacker has some stake which depends on access to the service (e.g. a UTXO cryptocurrency output), and if the violations are not relayed to all nodes, thus the attacker incurs no loss of the stake by attacking some but not all of the said nodes. Ditto if multiple violations are allowed per node (even without relaying) because the attacker can attack by consuming some but not all of the said allowance.

Relayed violations may help the attacker amplify the asymmetry w.r.t. bandwidth; and also if relayed violations are verified by every node when the nodes do not trust each other, thus amplifying the attack w.r.t. the asymmetry between verification and signing compute resources. If a sufficient stake at-risk is transferred upon a violation to the node interfacing with the attacker, the asymmetry is removed (inverted onto the attacker) for the interfacing node w.r.t. to incoming bandwidth, compute resources, and amplification of outgoing bandwidth. However, the asymmetry is amplified—for nodes processing relayed violations—w.r.t. compute resources (for untrusting nodes), incoming bandwidth, and (for a propagating network) outgoing bandwidth. As mentioned before in the oft-case that incoming bandwidth is free, the rare non-propagating network case wherein the interfacing node relays directly to all other nodes incurring all outgoing bandwidth cost, and if nodes trust each other (e.g. by blacklisting nodes which violate trust), the asymmetry for nodes processing relayed violations is limited to the (roughly equivalent) costs of processing a relayed (violating or non-violating) distributed state update such as an invalid or valid transaction in a cryptocurrency. However, in the oft-case of sane peer-to-peer networks that scale because each node interconnects only with some of the other nodes so that distributed state updates propagate across numerous nodes, the outgoing bandwidth costs are shared between all nodes. Thus in such propagating peer-to-peer networks, there is no asymmetry between nodes if all nodes verify all (violating or non-violating) distributed state updates; and the asymmetry is inverted onto to attacker w.r.t. to all nodes if the transferred sufficient at-risk stake for violating—and sufficient fees for non-violating state updates—are shared equally between all participating nodes.

Sharing economic inputs (for violating and non-violating distributed state updates) amongst all participating nodes requires a top-down global choice for the level of these inputs because otherwise an attacking node could lower the level making the costs asymmetric in favor of the attacker. If there is no cost or resource deposit for joining the distributed state network, a Sybil attack can destroy the equalized sharing. Yet sharing based on resources is unequalized w.r.t. to actual costs since in another form of a Sybil attack those possessing
more resources can split their resources to establish more nodes, while only performing verification once.

This dilemma is solvable in a free market driven paradigm where the interfacing node pays another node to relay. The interfacing node then chooses the at-risk stake (for violating) and fees (for non-violating) state updates. Assuming that becoming a node incurs some cost or resource deposit, the free market will reduce the cost of relaying and verification to the minimum. The aforementioned Sybil attacks on nodes are no longer effective because the attacker is paying the market cost of amplification, verification can be unified for all nodes, and splitting resource requirements only increases the costs on non-violating distributed state updates which has an upper bound due to the minimum resource requirement (can not be split ad infinitum). The bandwidth and compute resource costs may be insignificant at said upper bound relative to the average value of non-violating distributed state updates. Bandwidth costs on the order of one dollar per terabyte[31], verification costs can be unified and performed by a trusted node (thus for example potentially minimizing the bandwidth of the state update that needs to be relayed for example in the case of some design for a cryptocurrency), and the state update per node cost may be insignificant (such as updating the UTXO database in a cryptocurrency).

### Proof-of-work hash

An alternative or “prependage” [sic] to authentication is to rate limit the attacker by requiring the attacker to do an asymmetric quantity of computation compared to the computation the victim must do to verify that the work was done. The attacker can be required to produce a proof-of-work hash[32][33]—of the data being sent to the victim concatenated with a nonce—where the hash value meets some level of difficulty *k* such that the first *k* bits of the hash result are 0. This requires the attacker to compute the hash many times for different random nonce values until the hash value has the required *k* number of 0 bits. Whereas, the verifier only needs to compute hash once to verify the required *k* number of 0 bits.

Such an existential proof-of-work does not incur the complications of [distributed authentication](#distributed-authentication) because it contains all the information necessary to prove its existence. Whereas, the authentication of some distributed stake depends on the distributed coordination of the state of the said stake.

However unlike authentication, this pits the proof-of-work resources of legitimate participants against the attacker’s. If the attacker’s proof-of-work resources against a particular victim node is orders-of-magnitude greater than that of the participants on that node, then the participants are rate limited orders-of-magnitude more than the attacker. Additionally the attacker may have an asymmetric resource advantage—especially versus the legitimate participants who may be using general purpose computing hardware and retail electricity—for computing proof-of-work by employing the latest ASIC technology which may orders-of-magnitude more efficient than an Intel CPU and farming this work out to locations near hydropower generation plants where electricity costs ¼ of the retail cost. Participants are likely to favor a non-attacked node, thus unlike distributed authentication, the attacker can target individual nodes instead of the entire system of nodes. Therefor, proof-of-work is not a robust option for DDoS defense.

 # | References
---|---
[1]|<sub>https://en.wikipedia.org/w/index.php?title=Denial-of-service_attack&oldid=693394523#HTTP_POST_DoS_attack</sub>
[2]|<sub>https://en.wikipedia.org/w/index.php?title=Denial-of-service_attack&oldid=693394523#Reflected_.2F_spoofed_attack</sub><br/><sub>https://en.wikipedia.org/w/index.php?title=Denial-of-service_attack&oldid=693394523#Peer-to-peer_attacks</sub><br/>https://www.incapsula.com/ddos/attack-glossary/dns-amplification.html<br/>https://www.incapsula.com/ddos/attack-glossary/ntp-amplification.html
[3]|<sub>https://en.wikipedia.org/w/index.php?title=Denial-of-service_attack&oldid=693394523#Advanced_Persistent_DoS_.28APDoS.29</sub>
[4]|https://tools.ietf.org/html/rfc4987#section-3
[5]|https://en.wikipedia.org/w/index.php?title=Denial-of-service_attack&oldid=693394523#Clean_pipes
[6]|http://serverfault.com/questions/306837/how-many-computers-can-have-the-same-public-ip<br/><sub><sup>https://www.quora.com/How-many-home-customers-of-an-ISP-including-mobile-can-typically-share-the-same-IP-address-and-for-how-long</sup></sub>
[7]|https://tools.ietf.org/html/rfc4987#section-3.1
[8]|https://en.wikipedia.org/wiki/OSI_model#Layer_3:_Network_Layer
[9]|<sub>http://crypto.stackexchange.com/questions/559/what-is-the-signature-scheme-with-the-fastest-batch-verification-protocol-for-mu/</sub>
[10]|http://bench.cr.yp.to/results-sign.html#amd64-titan0
[11]|D. Naor et al, One-Time Signatures Revisited: Have They Become Practical?, §4.2 Selecting Hash Functions for FMTseq<br/>https://eprint.iacr.org/2005/442.pdf#page=8
[12]|D. Bernstein et al, High-speed high-security signatures, §1 Introduction<br/>http://ed25519.cr.yp.to/ed25519-20110705.pdf#page=2
[13]|D. Bernstein et al, High-speed high-security signatures, §1 Introduction: Comparison to other signature systems<br/>http://ed25519.cr.yp.to/ed25519-20110705.pdf#page=4
[14]|N. Sullivan, A (relatively easy to understand) primer on elliptic curve cryptography, Not a perfect trapdoor<br/><sub>http://arstechnica.com/security/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/2/</sub>
[15]|A. Corbellini, Elliptic Curve Cryptography: breaking security and a comparison with RSA<br/><sub>http://andrea.corbellini.name/2015/06/08/elliptic-curve-cryptography-breaking-security-and-a-comparison-with-rsa/</sub>
[16]|N. Jansma, Performance Comparison of Elliptic Curve and RSA Digital Signatures, Table 5-2: Key generation performance<br/>http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.129.7139&rep=rep1&type=pdf#page=6
[17]|D. Bernstein et al, High-speed high-security signatures, §5 Verifying signatures: Fast batch verification<br/>http://ed25519.cr.yp.to/ed25519-20110705.pdf#page=15
[18]|N. Courtois et al, How to achieve a McEliece-based Digital Signature Scheme, §8 Conclusion<br/>https://www.iacr.org/archive/asiacrypt2001/22480158.pdf#page=16
[19]|D. Bernstein et al, Post-Quantum Cryptography, Code-based cryptography, §2.2 CFS signature<br/>http://www.e-reading.club/bookreader.php/135832/Post_Quantum_Cryptography.pdf#page=107
[20]|D. Bernstein et al, High-speed high-security signatures, §5 Verifying signatures: Fast decompression<br/>http://ed25519.cr.yp.to/ed25519-20110705.pdf#page=13
[21]|https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction#Wide_pipe_construction
[22]|https://github.com/shelby3/winternitz/blob/master/Winternitz.md#unforgeability
[23]|http://bench.cr.yp.to/results-hash.html#amd64-titan0
[24]|https://github.com/floodyberry/blake2s-opt#i7-4770k
[25]|https://github.com/shelby3/blake/blob/master/blake/blake.h
[26]|D. Bernstein et al, Post-Quantum Cryptography, Hash-based Digital Signature Schemes, §7.3 Security of the Merkle signature scheme<br/>http://www.e-reading.club/bookreader.php/135832/Post_Quantum_Cryptography.pdf#page=92
[27]|D. Bernstein et al, Post-Quantum Cryptography, Hash-based Digital Signature Schemes, §3 One-time key-pair generation using an PRNG: Forward security<br/>http://www.e-reading.club/bookreader.php/135832/Post_Quantum_Cryptography.pdf#page=52
[28]|D. Bernstein et al, Post-Quantum Cryptography, Hash-based Digital Signature Schemes, §4 Authentication path computation<br/>http://www.e-reading.club/bookreader.php/135832/Post_Quantum_Cryptography.pdf#page=53
[29]|<sub>http://security.stackexchange.com/questions/33069/why-is-ecc-more-vulnerable-than-rsa-in-a-post-quantum-world</sub>
[30]|K. Ross, Efficient Hash Probes on Modern Processors, Figure 9: Splash tables versus lightly loaded hash tables on a Pentium 4<br/><sub>http://domino.research.ibm.com/library/cyberdig.nsf/papers/DF54E3545C82E8A585257222006FD9A2/$File/rc24100.pdf#page=8</sub>
[31]|1 Gbps unmetered connection costs $399 monthly at hivelocity.net
[32]|A. Back, Hashcash - A Denial of Service Counter-Measure, §3 The Hashcash cost-function<br/>http://www.hashcash.org/papers/hashcash.pdf#page=3
[33]|S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, §4. Proof-of-Work<br/>https://bitcoin.org/bitcoin.pdf#page=3