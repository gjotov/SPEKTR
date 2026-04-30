# SPEKTR-26 | СПЕКТР-26

[English Version](#english) | [Русская версия](#russian)

---

<a name="english"></a>
## English
### High-Security Steganographic Crypto-System

**SPEKTR-26** is a professional-grade cryptographic tool designed for plausible deniability and hardware-bound data protection. It disguises encrypted data as common WAV audio files, making it invisible to DPI systems and forensic analysis.

#### Key Features:
- **Polymorphic Steganography**: Data is hidden inside valid LPCM WAV files.
- **Hardware Entanglement**: Encryption is bound to the host's CPU/Motherboard ID.
- **Panic Protocol**: Triggering a "Panic Key" shreds the data while showing a decoy.
- **Memory Safety**: Written in Rust with proactive zeroization of sensitive RAM.
- **ML-KEM (Kyber-1024)**: Post-Quantum secure key encapsulation, ensuring your data remains safe even against future quantum computer attacks.

[**Full Specification (EN)**](docs/SPEC_EN.md) | [**Quick Start Guide**](#usage)

---

<a name="russian"></a>
## Русский
### Скрытая криптосистема повышенной защищенности

**СПЕКТР-26** — это криптографическая система профессионального уровня, предназначенная для обеспечения правдоподобного отрицания и защиты данных с аппаратной привязкой. Система маскирует зашифрованные данные под обычные аудиофайлы WAV, делая их невидимыми для систем DPI и форензик-анализа.

#### Основные возможности:
- **Полиморфная стеганография**: Данные скрыты внутри валидных WAV-файлов.
- **Аппаратная привязка**: Шифрование привязано к уникальному ID процессора и материнской платы.
- **Протокол «Паника»**: Ввод ключа паники физически уничтожает данные, выдавая приманку.
- **Безопасность памяти**: Написано на Rust с принудительной очисткой ОЗУ (Zeroize).
- 

[**Полная спецификация (RU)**](docs/SPEC_RU.md) | [**Инструкция по запуску**](#usage)

---


<a name="usage"></a>
## Usage / Использование

### Build / Сборка
```bash
cargo build --release
```

---

## Roadmap / План развития

**SPEKTR-26** is constantly evolving. Below is our development path for 2026.
**СПЕКТР-26** постоянно развивается. Ниже представлен наш план разработки на 2026 гг.

### Phase 1: Tactical Hardening (Q1-Q2 2026)
- [x] **Core SPN Engine**: Implementation of deterministic chaos and dynamic S-Boxes.
- [x] **Post-Quantum Layer**: Integration of ML-KEM (Kyber-1024).
- [x] **MFA Keyfiles**: Support for external entropy sources (files) to bypass keyloggers.
- [ ] **Advanced Shredding**: Implementation of Gutmann method (35 passes) for data destruction.
- [ ] **Anti-VM Shield**: Heuristic detection of virtualization and debuggers (Anti-Forensics)

### Phase 2: Expansion (Q3-Q4 2026)
- [ ] **Encrypted P2P**: Secure post-quantum channel for direct container transmission.

### Phase 3: Hardware & Enterprise (2026-2027)
- [ ] **TPM 2.0 Integration**: Binding "Silicon DNA" to the hardware Trusted Platform Module.
- [ ] **SPEKTR-Token**: Custom USB hardware token for physical key storage.
- [ ] **Network Protocol**: A decentralized protocol for anonymous metadata-free data exchange.
- [ ] **Kernel-Level Protection**: Windows/Linux driver to protect process memory from dumping.
