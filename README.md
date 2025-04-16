# Mango: Adaptive Cryptographic System

## What is Adaptive Cryptography?

Traditional ciphers apply a fixed sequence of operations to all input data, regardless of its structure. Mango introduces a new approach: **adaptive cryptography** — the idea that an encryption system should respond to the characteristics of the input itself.

Instead of treating all data equally, Mango **profiles the input**, determines its structure (e.g., random, natural, sequential), and dynamically selects an optimized transformation sequence designed to maximize entropy, dispersion, and cryptographic strength.

---

## How Mango Differs from Traditional Ciphers

Mango is not a drop-in AES clone — it is a full cryptographic workbench and cipher engine designed for adaptability and analysis. Key differences include:

- 🔀 **Input-Adaptive Sequences**  
  Each data type triggers a tailored transform path to maximize disruption of predictability.

- 🔁 **Atomic Transform Architecture**  
  Over 30 low-level transforms (e.g., bit shufflers, feedback mixers, pattern equalizers) can be composed into sequences.

- 📊 **Metric-Based Scoring**  
  Mango evaluates sequences against entropy, avalanche, bit variance, and other cryptographic metrics.

- ⚙️ **Reversible and Deterministic**  
  Every sequence is reversible, every output decryptable — no randomness is hidden from the user.

---

## Design Goals

Mango delivers **AES-class cryptographic strength** with **significantly faster execution**.  
Its adaptive engine analyzes input data in real time, **tailoring its encryption path** to maintain high entropy, diffusion, and unpredictability — even **outperforming AES** on structured or semi-structured data where static ciphers fall short.

| Goal                     | Achieved in Mango                          |
|--------------------------|--------------------------------------------|
| High throughput          | ✅ Significantly faster than AES (CLR)     |
| Cryptographic strength   | ✅ Passes avalanche, entropy, and periodicity tests |
| Tunability               | ✅ Transform rounds and sequence lengths tunable |
| Input sensitivity        | ✅ Profiles each input at runtime           |
| Transparency             | ✅ All decisions and outputs are inspectable |

---

### ⚡ Performance Comparison: Mango vs AES

| Category              | **Mango (CLR)**                                                      | **AES (Native)**                                                  |
|-----------------------|----------------------------------------------------------------------|-------------------------------------------------------------------|
| **Sequence**          | SubBytesFwdTx → SubBytesInvTx → ButterflyWithPairsFwdTx → ChunkedFbTx | Fixed AES rounds                                                  |
| **Global Rounds (GR)**| 6                                                                    | N/A                                                               |
| **Aggregate Score**   | **89.52**                                                            | 71.43                                                             |
| **Pass Count**        | **9 / 9**                                                            | 7 / 9                                                             |
| **Reversibility**     | ✅ PASS                                                              | ✅ PASS                                                           |
| **Entropy**           | ✅ 7.9541                                                            | ❌ 7.9505 (fail by 0.0018)                                        |
| **Bit Variance**      | ✅ 0.5005                                                            | ✅ 0.5003                                                         |
| **Sliding Window**    | ✅ 0.9067                                                            | ❌ 0.9157 (fail by 0.0130)                                        |
| **Frequency Dist.**   | ✅ 0.7461                                                            | ✅ 0.7390                                                         |
| **Periodicity**       | ✅ 1.0000                                                            | ✅ 1.0000                                                         |
| **Correlation**       | ✅ -0.026                                                            | ✅ -0.008                                                         |
| **Positional Mapping**| ✅ 0.0369                                                            | ✅ 0.0352                                                         |
| **Avalanche Score**   | ✅ 53.81                                                             | ✅ 50.09                                                          |
| **Key Dependency**    | ✅ 54.75                                                             | ✅ 50.20                                                          |
| **Encryption Time**   | **⚡ 2.71 ms**                                                       | 🐢 **171.01 ms**                                                  |

---

### 🧠 Key Observations
- 🔒 **Mango passed all 9/9 cryptographic metrics** — AES failed 2.
- ⚡ **Mango executed ~63× faster** than AES on this test input.
- 🧪 Mango’s entropy, avalanche, and diffusion scores **exceed AES**, particularly on structured or semi-random data.

---
## Quick Start

Mango supports two primary usage modes:

### 🧩 Run the Interactive Cryptographic Workbench

The Mango Workbench (`Mango.exe`) allows you to interactively assemble, test, and analyze cryptographic sequences composed of ~40 atomic transforms.  
You can build pipelines of arbitrary complexity, execute them, and view detailed metrics for strength, reversibility, and speed.

```
cd Workbench/bin
Mango.exe
```

From within the Workbench, you can:

Build and run custom transform sequences

Evaluate cryptographic strength using entropy, avalanche, and other metrics

Run comparative analysis against AES

Load curated sequences and benchmark results from prior Munge runs

### 🔧 Run a Minimal Standalone Example

If you're a developer or researcher interested in stepping through Mango's adaptive cryptographic engine in a minimal setting:

**Adaptive Cryptography (Single Block Mode)**

```
cd MangoAC/bin
MangoAC.exe
```

This example profiles a sample input, selects the best transform sequence for it, and performs a full encryption → decryption → verification cycle.

**Adaptive Cryptography in Block Mode**

```
cd MangoBM/bin
MangoBM.exe
```

This example demonstrates block-based encryption using Mango. It encrypts and decrypts multiple blocks of structured data, using a cached transform header in the first block.
Ideal for exploring how Mango might integrate into streaming or block-wise systems.

📘 Full documentation is available in: Workbench/Docs/