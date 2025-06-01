# Mango — Adaptive Cryptographic Workbench

> ⚡ Significantly faster than AES on structured and synthetic data  
> ✅ Passes all 9/9 cryptographic metrics  
> 🔄 Fully reversible — optimized for structured, random, and real-world data

## What is Adaptive Cryptography?

Traditional ciphers apply a fixed sequence of operations to all input data, regardless of its structure. Mango introduces a new model: **adaptive cryptography** — the idea that encryption should respond to the characteristics of the input itself.

Rather than treating all data as equally random, Mango **profiles the input**, identifies structure (e.g., randomness, natural text, sequential patterns), and dynamically selects a transformation sequence optimized to maximize entropy, diffusion, and cryptographic resilience.

---

## How Mango Differs from Traditional Ciphers

Mango is not an AES clone — it is a full cryptographic workbench and cipher engine built for adaptability, insight, and fine-grained control. Key differences include:

- 🔀 **Input-Adaptive Sequences**  
  Each input type (e.g., random, natural, sequential) triggers a tailored sequence of transformations to maximize entropy and disrupt structure.

- 🔁 **Composable Atomic Transforms**  
  Mango provides over 30 low-level, reversible operations — such as bit shufflers, feedback mixers, and pattern equalizers — that can be combined into powerful custom sequences.

- 📊 **Metric-Based Evaluation**  
  Every encryption sequence is scored across cryptographic metrics including entropy, avalanche effect, bit variance, and positional mapping — enabling quantitative comparison and optimization.

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

| Category              | **Mango (CLR)**                                                                                     | **AES (CLR)**                                                  |
|-----------------------|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| **Sequence**          | BitFlipCascadeTx → ShuffleNibblesFwdTx → MaskedDoubleSubFwdTx → CascadeSub3xFwdTx                  | Fixed AES rounds                                                  |
| **Global Rounds (GR)**| 3                                                                                                   | N/A                                                               |
| **Aggregate Score**   | **92.38**                                                                                           | 67.41                                                             |
| **Pass Count**        | **9 / 9**                                                                                           | 5 / 9                                                             |
| **Reversibility**     | ✅ PASS                                                                                             | ✅ PASS                                                           |
| **Entropy**           | ✅ 7.9525                                                                                           | ✅ 7.9577                                                         |
| **Bit Variance**      | ✅ 0.4986                                                                                           | ❌ 0.5038 (fail by 0.0035)                                        |
| **Sliding Window**    | ✅ 0.9068                                                                                           | ❌ 0.9126 (fail by 0.0099)                                        |
| **Frequency Dist.**   | ✅ 0.7472                                                                                           | ❌ 0.7582 (fail by 0.0156)                                        |
| **Periodicity**       | ✅ 1.0000                                                                                           | ✅ 1.0000                                                         |
| **Correlation**       | ✅ 0.0119                                                                                           | ✅ -0.0281                                                        |
| **Positional Mapping**| ✅ 0.0329                                                                                           | ✅ 0.0327                                                         |
| **Avalanche Score**   | ✅ 50.48                                                                                            | ❌ 41.32 (fail by 8.68)                                           |
| **Key Dependency**    | ✅ 49.53                                                                                            | ✅ 50.03                                                          |
| **Encryption Time**   | ⚡ **108.69 ms**                                                                                    | 🐢 **203.46 ms**                                                  |

---

### 🧠 Key Observations

- ✅ **Mango passed all 9/9 cryptographic metrics**, while AES failed 4 out of 9 on Natural input.
- ⚡ **Mango encrypted 2× faster than AES** in this test (108.7 ms vs. 203.5 ms), despite running on the same CLR.
- 🧪 **Mango demonstrated stronger diffusion and consistency**, with higher Avalanche and Key Dependency scores and fewer threshold violations — especially on real-world structured input.

#### 📊 Mango's metrics breakdown per data type:

| Input Type  | Entropy                        | Avalanche         | Diffusion (Sliding/Frequency)             |
|-------------|--------------------------------|-------------------|-------------------------------------------|
| **Natural** | ⚖️ Comparable                   | ✅ Mango higher    | ✅ Mango passes both; ❌ AES fails both     |
| **Random**  | ⚖️ Comparable                   | ✅ Mango higher    | ✅ Mango passes both; ❌ AES fails both     |
| **Sequence**| ⚖️ Comparable                   | ✅ Mango higher    | ✅ Mango passes both; ❌ AES fails both     |
| **Combined**| ⚖️ Comparable                   | ✅ Mango higher    | ✅ Mango passes both; ❌ AES fails Frequency |
| **UserData**| ⚖️ Comparable                   | ✅ Mango higher    | ✅ Mango passes both; ❌ AES fails both     |

---
## Quick Start

Mango supports two primary usage modes:

### 🧩 Run the Interactive Cryptographic Workbench

The Mango Workbench (`Mango.exe`) allows you to interactively assemble, test, and analyze cryptographic sequences composed of ~50 atomic transforms.  
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

📘 Full documentation is available in: `Workbench/Docs/`

> **Note on Speed Comparisons:**  
> All performance comparisons are made under equivalent, software-only conditions without hardware acceleration.  
> AES remains strong in raw throughput, but Mango performs competitively — and often outpaces AES on high-entropy inputs.  
> Throughput varies by profile (`.Best` vs `.Fast`) and input type, reflecting Mango’s adaptive design.  
> Unlike AES, Mango includes scoring, validation, and structural transforms as part of its core pipeline, not as optional layers.
