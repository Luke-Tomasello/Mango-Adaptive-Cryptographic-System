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

## Performance & Design Goals

Mango is designed to **outperform AES in speed**, and to **rival it in cryptographic robustness**, particularly when data is structured, repetitive, or semi-predictable.

| Goal                     | Achieved in Mango                          |
|--------------------------|--------------------------------------------|
| High throughput          | ✅ Significantly faster than AES (CLR)     |
| Cryptographic strength   | ✅ Passes avalanche, entropy, and periodicity tests |
| Tunability               | ✅ Transform rounds and sequence lengths tunable |
| Input sensitivity        | ✅ Profiles each input at runtime           |
| Transparency             | ✅ All decisions and outputs are inspectable |

---

## Quick Start

Mango includes two usage modes:

### 🔧 Run a Minimal Standalone Example
If you're a developer or researcher who wants to step through an example in code:

```bash
cd MangoAC/bin
MangoAC.exe
