# Bitcoin-Quantum-Cryptography-
Implementation and timeline for Bitcoin Quantum upgrade
# Quantum-Resistant Bitcoin Wallet: Full Technical Specification

**Version:** 1.0  
**Date:** November 2025  
**Status:** Draft Specification

-----

## Executive Summary

This specification defines a quantum-resistant Bitcoin wallet architecture that protects against attacks from cryptographically-relevant quantum computers (CRQCs). The design employs NIST-standardized post-quantum cryptographic (PQC) algorithms while maintaining backward compatibility with existing Bitcoin infrastructure.

### Threat Model

**Primary Threat:** Shor’s algorithm enables quantum computers to:

- Break ECDSA by solving the Elliptic Curve Discrete Logarithm Problem (ECDLP)
- Derive private keys from exposed public keys in O(n³) time

**Timeline Estimate:** CRQCs capable of breaking Bitcoin’s secp256k1 curve estimated by 2030-2035.

**Protected Asset:** Private keys controlling Bitcoin UTXOs with exposed public keys.

-----

## 1. Architecture Overview

### 1.1 Hybrid Cryptographic Approach

The wallet employs a **dual-signature hybrid scheme** combining classical and post-quantum algorithms:

```
Transaction Authorization = ECDSA_Signature ⊕ PQC_Signature
Valid iff: ECDSA_Valid AND PQC_Valid
```

**Security Property:** Security level equals the stronger of the two schemes. If quantum computers break ECDSA, PQC signatures still protect funds. If PQC has undiscovered vulnerabilities, classical ECDSA provides fallback security.

### 1.2 System Components

1. **Key Generation Module** - PQC and classical keypair generation
1. **Signing Engine** - Hybrid signature creation
1. **Verification Module** - Dual signature validation
1. **Address Derivation** - Quantum-resistant address formats
1. **HD Wallet Structure** - BIP32-compatible PQC key derivation
1. **Transaction Builder** - Script construction for hybrid signatures
1. **Storage Layer** - Encrypted key material management

-----

## 2. Cryptographic Primitives

### 2.1 Selected Post-Quantum Algorithms

#### Primary: ML-DSA (Dilithium)

- **Type:** Module-Lattice Digital Signature Algorithm
- **Security Level:** ML-DSA-65 (NIST Level 3, equivalent to AES-192)
- **Public Key:** 1,952 bytes
- **Signature Size:** 3,293 bytes
- **Signing Speed:** ~0.5ms on modern CPU
- **Rationale:** Best balance of security, performance, and signature size

#### Backup: SLH-DSA (SPHINCS+)

- **Type:** Stateless Hash-Based Signature
- **Security Level:** SLH-DSA-128s (NIST Level 1, equivalent to AES-128)
- **Public Key:** 32 bytes
- **Signature Size:** 7,856 bytes
- **Signing Speed:** ~10ms
- **Rationale:** Conservative fallback with minimal security assumptions

#### Future Consideration: FN-DSA (Falcon)

- **Type:** Lattice-based (NTRU)
- **Signature Size:** 666 bytes (smallest)
- **Challenge:** Complex implementation, floating-point operations

### 2.2 Hash Functions (Quantum-Resistant)

- **Primary:** SHA-256 (Grover’s algorithm only reduces to 128-bit security, acceptable)
- **HMAC:** HMAC-SHA512 for key derivation
- **Address Hashing:** SHA-256 + RIPEMD-160 (existing Bitcoin standard)

### 2.3 Symmetric Encryption

- **Algorithm:** AES-256-GCM
- **Key Derivation:** Argon2id (memory-hard, side-channel resistant)
- **Usage:** Wallet file encryption, seed phrase protection

-----

## 3. Key Management

### 3.1 Key Generation

#### Seed Generation

```
Entropy Source: Hardware RNG (256 bits minimum)
Master Seed = Argon2id(Entropy || User_Passphrase || Salt)
Mnemonic = BIP39_Encode(Master_Seed) // 24 words
```

#### Hierarchical Key Derivation (BIP32-PQC Extension)

**Classical Path (BIP32):**

```
m / purpose' / coin_type' / account' / change / address_index
m / 44' / 0' / 0' / 0 / 0  (Bitcoin mainnet, first receive address)
```

**PQC Path (Proposed):**

```
m / purpose' / coin_type' / account' / pqc_type' / change / address_index
m / 888' / 0' / 0' / 1' / 0 / 0  (purpose=888 for PQC, pqc_type=1 for ML-DSA)
```

**Key Derivation Function:**

```python
# Pseudocode for PQC child key derivation
def derive_pqc_child_key(parent_seed, index):
    # Use HMAC-based KDF maintaining BIP32 compatibility
    hmac_key = HMAC-SHA512(key="Bitcoin PQC seed", data=parent_seed)
    child_seed = HMAC-SHA512(key=hmac_key, data=index || 0x00)
    
    # Generate ML-DSA keypair from deterministic seed
    (pqc_private_key, pqc_public_key) = ML_DSA_KeyGen(child_seed[0:32])
    
    # Generate classical ECDSA keypair
    ecdsa_private_key = int(child_seed[32:64]) mod n  # secp256k1 order
    ecdsa_public_key = ecdsa_private_key * G
    
    return {
        'pqc_sk': pqc_private_key,
        'pqc_pk': pqc_public_key,
        'ecdsa_sk': ecdsa_private_key,
        'ecdsa_pk': ecdsa_public_key,
        'chain_code': HMAC-SHA512(hmac_key, index || 0x01)[32:64]
    }
```

### 3.2 Key Storage

#### Storage Format (Encrypted)

```json
{
  "version": "1.0",
  "crypto": {
    "cipher": "AES-256-GCM",
    "kdf": "Argon2id",
    "kdf_params": {
      "iterations": 3,
      "memory": 65536,
      "parallelism": 4,
      "salt": "<base64>"
    },
    "iv": "<base64>",
    "tag": "<base64>"
  },
  "encrypted_data": {
    "master_seed": "<encrypted_base64>",
    "pqc_keys": "<encrypted_base64>",
    "ecdsa_keys": "<encrypted_base64>"
  },
  "metadata": {
    "created": "2025-11-02T00:00:00Z",
    "pqc_algorithm": "ML-DSA-65",
    "derivation_path": "m/888'/0'/0'"
  }
}
```

#### Hardware Security Module (HSM) Support

- Support for PKCS#11 interface
- Secure element integration for mobile wallets (iOS Secure Enclave, Android StrongBox)
- Never export unencrypted private keys

-----

## 4. Address Formats

### 4.1 PQC Address Structure

Due to large PQC public keys (1,952 bytes for ML-DSA), direct encoding in addresses is impractical.

#### Commitment-Based Approach

```
PQC_Commitment = SHA256(ML-DSA_PublicKey || ECDSA_PublicKey || Version)
PQC_Address = Base58Check("PQ" || PQC_Commitment[0:20])
```

**Address Format:**

- Prefix: “PQ” (version byte: 0x50)
- Payload: 20-byte hash commitment
- Checksum: 4-byte double SHA-256
- Example: `PQxyz123...` (34 characters)

#### Registration Transaction

First transaction from address MUST include:

```
OP_RETURN <version> <full_ml-dsa_pubkey> <full_ecdsa_pubkey>
```

This registers the public keys on-chain before revealing signatures.

### 4.2 Backward Compatibility Addresses

**Wrapped SegWit (P2SH-P2WPKH):**
For interfacing with legacy systems:

```
P2SH Address (starts with '3')
  └─ Redeems to: PQC Commitment Script
```

-----

## 5. Transaction Structure

### 5.1 Hybrid Signature Script

#### ScriptPubKey (Output Script)

```
OP_DUP
OP_HASH160
<PQC_Commitment_Hash>
OP_EQUALVERIFY
OP_CHECKSIG
OP_SWAP
<PQC_PublicKey_Hash>
OP_EQUALVERIFY
OP_CHECKPQCSIG_ML_DSA
```

#### ScriptSig (Input Script)

```
<ECDSA_Signature>
<ECDSA_PublicKey>
<ML-DSA_Signature>
<ML-DSA_PublicKey>
```

**Note:** Requires Bitcoin soft fork to add `OP_CHECKPQCSIG_ML_DSA` opcode. Until then, use Layer 2 or multisig workarounds.

### 5.2 Layer 2 Implementation (Pre-Fork)

#### Using 2-of-2 Multisig

```
Participant A: Classical ECDSA wallet (backward compatible)
Participant B: PQC-enabled wallet (this specification)

Transaction requires both signatures:
- ECDSA signature from A (standard Bitcoin)
- ML-DSA signature from B (verified off-chain or via oracle)
```

#### Timelock Escape Hatch

```
IF
  <Timelock: 6 months>
  CHECKSIGVERIFY <Emergency_Classical_Key>
ELSE
  <Standard hybrid verification>
ENDIF
```

Allows fund recovery if PQC implementation has bugs.

### 5.3 Transaction Fees

**Size Considerations:**

- Standard transaction: ~250 bytes
- PQC transaction: ~4,500 bytes (ML-DSA signature + pubkey)
- Fee multiplier: ~18x

**Mitigation Strategies:**

1. **Signature Aggregation:** Batch multiple inputs sharing same key
1. **Compressed Witness Data:** Use Taproot-like structures
1. **Off-chain Verification:** Lightning Network with PQC channels

-----

## 6. Signing Protocol

### 6.1 Signature Generation

```python
def sign_transaction(tx_hash, ecdsa_privkey, pqc_privkey):
    """
    Create hybrid signature for transaction
    
    Args:
        tx_hash: 32-byte transaction hash to sign
        ecdsa_privkey: secp256k1 private key
        pqc_privkey: ML-DSA-65 private key
    
    Returns:
        Hybrid signature object
    """
    # Step 1: Generate classical ECDSA signature
    ecdsa_sig = ecdsa_sign(tx_hash, ecdsa_privkey)
    
    # Step 2: Generate PQC signature over same hash
    pqc_sig = ml_dsa_sign(tx_hash, pqc_privkey)
    
    # Step 3: Create commitment binding both signatures
    commitment = SHA256(ecdsa_sig || pqc_sig || tx_hash)
    
    # Step 4: Package hybrid signature
    hybrid_sig = {
        'ecdsa': ecdsa_sig,
        'pqc': pqc_sig,
        'commitment': commitment,
        'version': 1
    }
    
    return hybrid_sig
```

### 6.2 Signature Verification

```python
def verify_hybrid_signature(tx_hash, hybrid_sig, ecdsa_pubkey, pqc_pubkey):
    """
    Verify hybrid signature
    
    Returns:
        Boolean indicating validity
    """
    # Verify commitment integrity
    expected_commitment = SHA256(
        hybrid_sig['ecdsa'] || 
        hybrid_sig['pqc'] || 
        tx_hash
    )
    if expected_commitment != hybrid_sig['commitment']:
        return False
    
    # Verify classical ECDSA signature
    if not ecdsa_verify(tx_hash, hybrid_sig['ecdsa'], ecdsa_pubkey):
        return False
    
    # Verify PQC signature
    if not ml_dsa_verify(tx_hash, hybrid_sig['pqc'], pqc_pubkey):
        return False
    
    return True  # Both signatures valid
```

### 6.3 Signature Serialization

```
[Version: 1 byte]
[ECDSA_Sig_Length: 2 bytes]
[ECDSA_Signature: variable, ~71 bytes]
[PQC_Sig_Length: 2 bytes]
[PQC_Signature: 3,293 bytes for ML-DSA-65]
[Commitment: 32 bytes]
```

**Total Size:** ~3,401 bytes per signature

-----

## 7. Security Considerations

### 7.1 Threat Analysis

|Attack Vector                  |Mitigation                                        |
|-------------------------------|--------------------------------------------------|
|Quantum computer breaks ECDSA  |PQC signature remains secure                      |
|Side-channel attacks on signing|Constant-time implementations, HSM isolation      |
|Public key reuse               |HD wallet generates new addresses per transaction |
|Malleability attacks           |Signature commitment binding prevents modification|
|Weak randomness                |Hardware RNG + HMAC-DRBG with additional entropy  |
|Implementation bugs in PQC     |Hybrid scheme + formal verification + audit       |

### 7.2 Key Exposure Scenarios

**Case 1: Public key never exposed (P2PKH, unspent)**

- Quantum threat: LOW (requires breaking SHA-256/RIPEMD-160)
- Action: No immediate migration required

**Case 2: Public key exposed (spent address)**

- Quantum threat: HIGH (public key available for ECDLP attack)
- Action: IMMEDIATE migration to PQC address

**Case 3: Hybrid address, PQC keys registered**

- Quantum threat: NONE (PQC signature required)
- Action: Secure, no migration needed

### 7.3 Cryptographic Security Levels

|Algorithm      |Classical Security|Quantum Security |NIST Level|
|---------------|------------------|-----------------|----------|
|secp256k1 ECDSA|128 bits          |0 bits (broken)  |-         |
|ML-DSA-65      |256 bits          |192 bits         |Level 3   |
|SLH-DSA-128s   |128 bits          |128 bits         |Level 1   |
|SHA-256        |256 bits          |128 bits (Grover)|-         |

### 7.4 Recommended Security Practices

1. **Key Rotation:** Migrate to fresh PQC addresses every 12 months
1. **Cold Storage:** Hardware wallets with PQC support for large holdings
1. **Multisig:** 2-of-3 with geographically distributed keys
1. **Audit Trail:** Log all signing operations with timestamps
1. **Emergency Recovery:** Encrypted backup seeds stored in secure vaults

-----

## 8. Implementation Requirements

### 8.1 Software Dependencies

#### Core Cryptography Libraries

- **liboqs** (Open Quantum Safe) - PQC algorithm implementations
- **libsecp256k1** - Bitcoin ECDSA operations
- **OpenSSL 3.x** - Symmetric encryption, hashing

#### Language-Specific Bindings

- Python: `oqs-python`, `coincurve`
- Rust: `oqs-sys`, `secp256k1`
- JavaScript/TypeScript: `node-oqs`, `secp256k1-node`

### 8.2 Performance Targets

|Operation             |Target Latency|Notes                              |
|----------------------|--------------|-----------------------------------|
|Key generation        |< 50ms        |One-time operation                 |
|Address derivation    |< 10ms        |Cached after first derivation      |
|Transaction signing   |< 100ms       |Dominant cost: ML-DSA signing      |
|Signature verification|< 50ms        |Verifier-side optimization critical|

### 8.3 Platform Support

**Desktop Wallets:**

- Windows 10+ (x64)
- macOS 12+ (Apple Silicon + Intel)
- Linux (x64, ARM64)

**Mobile Wallets:**

- iOS 15+ (Secure Enclave integration)
- Android 11+ (StrongBox support)

**Hardware Wallets:**

- Custom firmware for Ledger/Trezor
- Requires 512KB+ flash for PQC algorithms
- Secure Element with at least 128KB RAM

### 8.4 Testing Requirements

1. **Unit Tests:** 100% coverage of cryptographic primitives
1. **Integration Tests:** Full transaction lifecycle simulation
1. **Fuzzing:** AFL/libFuzzer on signature verification
1. **Side-Channel Testing:** Power analysis, timing attacks
1. **Testnet Deployment:** 6+ months before mainnet
1. **Third-Party Audit:** Minimum 2 independent security firms

-----

## 9. Migration Path

### 9.1 Phased Rollout

**Phase 1: Testnet (Months 0-6)**

- Deploy reference implementation on Bitcoin testnet
- Community testing and feedback
- Bug bounty program

**Phase 2: Soft Fork Proposal (Months 6-18)**

- BIP submission for `OP_CHECKPQCSIG` opcodes
- Miner and node operator signaling
- Activation threshold: 95% of blocks

**Phase 3: Layer 2 Launch (Months 12-24)**

- Lightning Network PQC channel implementation
- Sidechains with native PQC support
- Liquid Network integration

**Phase 4: Mainnet Hard Migration (Year 3+)**

- Protocol upgrade with PQC as default
- Legacy address deprecation timeline
- User education and wallet updates

### 9.2 User Migration Steps

1. **Backup:** Export existing seed phrases and private keys
1. **Update:** Install PQC-enabled wallet software
1. **Generate:** Create new PQC addresses
1. **Transfer:** Send funds from legacy addresses to PQC addresses
1. **Verify:** Confirm transactions with hybrid signatures
1. **Secure:** Delete legacy keys after migration complete

-----

## 10. Standards Compliance

### 10.1 Existing Bitcoin Standards

- **BIP32:** HD Wallet structure (extended for PQC paths)
- **BIP39:** Mnemonic seed phrases (24 words)
- **BIP44:** Multi-account hierarchy
- **BIP141:** SegWit (adapted for larger PQC signatures)
- **BIP174:** PSBT (Partially Signed Bitcoin Transactions)

### 10.2 New Standards (Proposed)

**BIP-PQC-001: Post-Quantum Address Format**

- Defines commitment-based address structure
- Registration transaction format
- Version numbering for future algorithms

**BIP-PQC-002: Hybrid Signature Scheme**

- Dual signature validation rules
- Serialization format
- Backward compatibility layer

**BIP-PQC-003: HD Wallet PQC Derivation**

- PQC key derivation paths
- Deterministic generation from BIP39 seeds
- Interoperability with existing wallets

### 10.3 NIST Standards

- **FIPS 203:** Module-Lattice-Based Key-Encapsulation (ML-KEM)
- **FIPS 204:** Module-Lattice-Based Digital Signature (ML-DSA)
- **FIPS 205:** Stateless Hash-Based Digital Signature (SLH-DSA)

-----

## 11. Reference Implementation

### 11.1 Repository Structure

```
pqc-bitcoin-wallet/
├── src/
│   ├── crypto/
│   │   ├── ml_dsa.rs         # ML-DSA wrapper
│   │   ├── ecdsa.rs          # secp256k1 wrapper
│   │   └── hybrid_sig.rs     # Hybrid signature logic
│   ├── keys/
│   │   ├── derivation.rs     # HD wallet key derivation
│   │   └── storage.rs        # Encrypted key storage
│   ├── address/
│   │   ├── pqc_address.rs    # PQC address generation
│   │   └── commitment.rs     # Key commitment scheme
│   ├── transaction/
│   │   ├── builder.rs        # Transaction construction
│   │   └── signing.rs        # Signature generation
│   └── wallet/
│       ├── core.rs           # Wallet management
│       └── api.rs            # JSON-RPC interface
├── tests/
│   ├── unit/
│   ├── integration/
│   └── vectors/              # Test vectors
├── docs/
│   ├── API.md
│   ├── SECURITY.md
│   └── MIGRATION.md
└── examples/
    ├── generate_wallet.rs
    ├── sign_transaction.rs
    └── verify_signature.rs
```

### 11.2 API Examples

#### Wallet Creation

```rust
use pqc_bitcoin_wallet::{Wallet, Network};

// Create new wallet with PQC support
let mut wallet = Wallet::new(Network::Bitcoin)?;

// Generate mnemonic
let mnemonic = wallet.generate_mnemonic()?;
println!("Seed phrase: {}", mnemonic);

// Derive first receiving address
let address = wallet.get_address(0, false)?;
println!("First PQC address: {}", address);
```

#### Transaction Signing

```rust
use pqc_bitcoin_wallet::{Transaction, SigningKey};

// Load wallet from encrypted file
let wallet = Wallet::load("wallet.json", "passphrase")?;

// Create transaction
let mut tx = Transaction::new();
tx.add_input(prev_txid, prev_vout, amount)?;
tx.add_output(recipient_address, send_amount)?;

// Sign with hybrid signature
let signed_tx = wallet.sign_transaction(&tx)?;

// Broadcast
client.broadcast_transaction(&signed_tx)?;
```

-----

## 12. Future Enhancements

### 12.1 Short-Term (1-2 Years)

- **Signature Aggregation:** Reduce transaction size for multiple inputs
- **Taproot Integration:** Hide PQC signatures until spend
- **Hardware Wallet Support:** Firmware for Ledger Nano X, Trezor Model T
- **Mobile SDK:** React Native and Flutter bindings

### 12.2 Medium-Term (2-5 Years)

- **Threshold Signatures:** PQC-based multi-party computation
- **Cross-Chain Bridges:** PQC-secured atomic swaps
- **Zero-Knowledge Proofs:** PQC-compatible ZK-SNARKs
- **Optimized Algorithms:** Next-generation smaller signatures (e.g., Falcon)

### 12.3 Long-Term (5+ Years)

- **Full Quantum Networks:** QKD integration for key exchange
- **Homomorphic Encryption:** Private transaction amounts with PQC
- **Post-Quantum Blockchain:** Purpose-built Layer 1 with native PQC
- **Regulatory Compliance:** Government-mandated PQC standards

-----

## 13. Governance and Maintenance

### 13.1 Project Governance

- **Lead Maintainer:** Open-source community elected
- **Technical Steering Committee:** 7 members, 2-year terms
- **Security Response Team:** 24/7 incident response
- **Update Cadence:** Quarterly releases, emergency patches as needed

### 13.2 Funding Model

- **Grant Funding:** Bitcoin Foundation, OpenSats
- **Corporate Sponsors:** Exchanges, custodians, wallet providers
- **Bug Bounties:** Up to $100,000 for critical vulnerabilities
- **Development Grants:** For contributor teams

### 13.3 Communication Channels

- **GitHub:** Issue tracking, pull requests
- **Mailing List:** Bitcoin-PQC-Dev@lists.linuxfoundation.org
- **Chat:** Matrix channel for real-time discussion
- **Blog:** Quarterly technical updates

-----

## 14. Conclusion

This specification provides a comprehensive blueprint for implementing quantum-resistant cryptography in Bitcoin wallets. The hybrid approach ensures security against both classical and quantum adversaries while maintaining backward compatibility with existing infrastructure.

### Key Takeaways

1. **Urgency:** CRQC timeline necessitates beginning migration now
1. **Hybrid Security:** Dual signatures provide defense-in-depth
1. **Practical Trade-offs:** Larger signatures acceptable for long-term security
1. **Gradual Migration:** Phased rollout minimizes disruption
1. **Open Standards:** Community consensus essential for adoption

### Next Steps

1. Review and refine this specification with cryptography experts
1. Implement reference wallet in Rust with full test coverage
1. Deploy to Bitcoin testnet for community testing
1. Submit BIPs for protocol-level PQC support
1. Coordinate with hardware wallet manufacturers
1. Educate users on quantum threats and migration timeline

**The quantum threat to Bitcoin is real but addressable. With proactive development and community coordination, we can secure Bitcoin’s future against quantum adversaries.**

-----

## Appendix A: Mathematical Foundations

### A.1 ML-DSA Security Proof Sketch

ML-DSA security reduces to the hardness of Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems on lattices.

**MLWE Problem:**
Given samples (aᵢ, bᵢ = aᵢ·s + eᵢ) where s is secret and eᵢ is small error, distinguish from uniform random.

**Hardness:** Best known quantum attack requires O(2^(n/2)) operations for security parameter n.

### A.2 Hybrid Signature Security Theorem

**Theorem:** If at least one of {ECDSA, ML-DSA} is EUF-CMA secure, then the hybrid scheme is EUF-CMA secure.

**Proof Sketch:** Adversary forging hybrid signature must forge both signatures. By reduction, if adversary succeeds with non-negligible probability, we can construct forger for the secure signature scheme, contradicting EUF-CMA security.

-----

## Appendix B: Test Vectors

### B.1 Key Derivation Test Vector

```
Master Seed (hex): 
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

Derivation Path: m/888'/0'/0'/1'/0/0

Expected ML-DSA Public Key (first 32 bytes, hex):
  a1b2c3d4e5f6071829...

Expected ECDSA Public Key (compressed, hex):
  02a1b2c3d4e5f6071829...

Expected PQC Address:
  PQxyz123abc456def789...
```

### B.2 Signature Test Vector

```
Message (hex):
  48656c6c6f20576f726c64  // "Hello World"

Private Keys: (from test vector B.1)

Expected ECDSA Signature (DER, hex):
  3045022100...

Expected ML-DSA Signature (first 32 bytes, hex):
  f1e2d3c4b5a6...

Expected Hybrid Signature Commitment (hex):
  9a8b7c6d5e4f3a2b1c0d...
```

-----

## Appendix C: Glossary

- **CRQC:** Cryptographically-Relevant Quantum Computer
- **PQC:** Post-Quantum Cryptography
- **ECDLP:** Elliptic Curve Discrete Logarithm Problem
- **ML-DSA:** Module-Lattice Digital Signature Algorithm (Dilithium)
- **SLH-DSA:** Stateless Hash-Based Digital Signature Algorithm (SPHINCS+)
- **EUF-CMA:** Existential Unforgeability under Chosen Message Attack
- **HD Wallet:** Hierarchical Deterministic Wallet
- **UTXO:** Unspent Transaction Output
- **BIP:** Bitcoin Improvement Proposal

-----

## Appendix D: References

1. NIST Post-Quantum Cryptography Standards (2024)
1. “Post-Quantum Cryptography for Bitcoin” - Bitcoin Core Mailing List
1. Open Quantum Safe Project Documentation
1. BIP32: Hierarchical Deterministic Wallets
1. “Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms” (2021)

-----

**Document Control**

- **Author:** GhostMinerz
- **Review Status:** Draft for Community Review
- **Last Updated:** November 2025
- **License:** MIT License (Open Source)
- **Contact:** 
