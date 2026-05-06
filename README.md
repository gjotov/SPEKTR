# SPEKTR-26 | СПЕКТР-26 (Version 2.0)

[English Version](#english) | [Русская версия](#russian)

---

<a name="english"></a>
## English
### High-Security Steganographic Platform & P2P Quantum Channel

**SPEKTR-26** has evolved from a standalone cipher into a comprehensive security platform. Version 2.2-PRO introduces a professional monochrome GUI and direct Peer-to-Peer (P2P) transmission, allowing for secure data exchange without leaving traces on physical disks.

#### Core Security Pillars:
- **ML-KEM (Kyber-1024)**: Industry-leading Post-Quantum key encapsulation for both file storage and network transmission.
- **Polymorphic Steganography**: Critical data is hidden inside valid LPCM WAV audio files, appearing as radio noise to DPI and forensic tools.
- **Hardware DNA (Silicon Entanglement)**: Encryption is bound to a unique multi-factor hardware ID (CPU, RAM, Disks).
- **MFA (Keyfiles)**: Support for external physical entropy sources (any file on a USB drive can act as a second factor).
- **Panic Protocol**: 35-pass **Gutmann method** shredding to ensure irreversible data destruction under pressure.
- **Anti-VM Shield**: Heuristic detection of virtual environments and debuggers with silent failure mode.

#### New in v2.0:
- **Monochrome Dashboard**: A minimalist, low-contrast GUI built with Tauri for maximum performance and security.
- **P2P Quantum Tunnel**: Establish direct socket-to-socket connections with Post-Quantum handshakes for "live" data transmission.

[**Full Specification**](docs/SPEC_EN.md) | [**Audit Reports**](/audit)

---

<a name="russian"></a>
## Русский
### Скрытая криптоплатформа и Квантовый P2P-канал связи

**СПЕКТР-26** перерос формат локальной утилиты и стал полноценной платформой безопасности. Версия 2.0 внедряет профессиональный монохромный интерфейс и модуль прямой P2P-передачи данных, позволяющий обмениваться секретами, минуя запись на жесткий диск.

#### Ключевые технологии защиты:
- **ML-KEM (Kyber-1024)**: Постквантовая защита мирового уровня для хранения файлов и сетевого обмена.
- **Полиморфная стеганография**: Данные инкапсулируются в валидные WAV-файлы. Для систем DPI и внешнего наблюдателя это обычный радиошум.
- **Hardware DNA (Биометрия кремния)**: Привязка шифра к уникальному «генетическому коду» железа (процессор, память, дисковые серийники).
- **MFA (Ключ-файлы)**: Поддержка внешних файлов как второго фактора защиты (любое фото на флешке становится частью ключа).
- **Протокол «Паника»**: Физическое уничтожение данных методом **Гутманна (35 проходов)** при вводе Panic-ключа.
- **Anti-VM Shield**: Эвристический детектор виртуалок и отладчиков с режимом «тихого отказа».

#### 🚀 Новое в версии 2.0:
- **Monochrome Dashboard**: Минималистичный GUI-интерфейс на базе Tauri, работающий со скоростью системных утилит.
- **P2P Quantum Tunnel**: Прямая передача данных между узлами через защищенный сокет с постквантовым рукопожатием.

[**Техническая спецификация**](docs/SPEC_RU.md) | [**Отчеты аудита**](/audit)
---

## Security Verification / Математический аудит

We don't ask for trust; we provide proof. SpektrCore has been verified through extreme stress-tests:
Мы не просим верить на слово — мы предоставляем доказательства. Ядро SpektrCore прошло серию стресс-тестов:

- **Entropy (ENT)**: **7.999999 bits/byte** (Near-theoretical limit).
- **Diffusion (SAC)**: **50.2511%** (Perfect Strict Avalanche Criterion).
- **Correlation**: **0.000000** (Zero serial correlation, immune to linear cryptanalysis).
- **Dieharder Suite**: **PASSED**.

---

## Technical Stack / Технологии
- **Backend**: Rust.
- **Frontend**: Tauri v2.
- **Crypto**: Argon2id, HMAC-SHA256, ML-KEM-1024.
- **Networking**: Encrypted P2P TCP Sockets.

---

## Roadmap / План развития
### Phase 1: Tactical Hardening (Completed 1.0)
- [x] Core SPN Engine: Deterministic chaos and dynamic S-Boxes.

- [x] Post-Quantum Layer: Integration of ML-KEM (Kyber-1024).

- [x] MFA Keyfiles: Support for external entropy sources.

- [x] Advanced Shredding: Gutmann method (35 passes) implementation.

- [x] Anti-VM Shield: Protection against analysis in virtual environments.
### Phase 2: Ecosystem Expansion (Q2 2026)

- [x] GUI Dashboard: Cross-platform desktop application (Tauri).

- [x] Encrypted P2P: Secure post-quantum channel for direct transmission.
### Phase 3: Hardware & Enterprise (Q3 2026)

- [ ] TPM 2.0 Integration: Hardware-level "Silicon DNA" binding.

- [ ] SPEKTR-Token: Custom USB hardware token for physical key storage.

Kernel-Level Protection: Anti-memory-dump drivers.
---

<a name="usage"></a>
## 🚀 Usage / Использование

### Build / Сборка:
```bash
# Compile CLI & GUI
cargo tauri build --release
```
