# SPEKTR-26 | СПЕКТР-26

[English Version](#english) | [Русская версия](#russian)

---

<a name="english"></a>
## 🇬🇧 English
### High-Security Steganographic Crypto-System (Version 1.0)

**SPEKTR-26** is a professional-grade cryptographic tool designed for plausible deniability and hardware-bound data protection. It disguises encrypted data as common WAV audio files, making it invisible to DPI systems and forensic analysis.

#### Key Features:
- **Polymorphic Steganography**: Data is hidden inside valid LPCM WAV files (appears as radio noise).
- **Hardware Entanglement (Silicon DNA)**: Encryption is bound to the host's CPU/Motherboard ID. Data cannot be moved to another machine.
- **ML-KEM (Kyber-1024)**: Post-Quantum secure key encapsulation, ensuring safety against future quantum computer attacks.
- **MFA Keyfiles**: Support for external entropy sources (files) to bypass keyloggers.
- **Panic Protocol**: Triggering a "Panic Key" performs a 35-pass **Gutmann method** shredding while showing decoy data.
- **Anti-VM Shield**: Heuristic detection of virtualization and debuggers to prevent forensic analysis.
- **Memory Safety**: Written in Rust with proactive zeroization of sensitive RAM.

[**Full Specification (EN)**](docs/SPEC_EN.md) | [**Quick Start Guide**](#usage)

---

<a name="russian"></a>
## 🇷🇺 Русский
### Скрытая криптосистема повышенной защищенности (Версия 1.0)

**СПЕКТР-26** — это криптографическая система профессионального уровня, предназначенная для обеспечения правдоподобного отрицания и защиты данных с аппаратной привязкой. Система маскирует зашифрованные данные под обычные аудиофайлы WAV, делая их невидимыми для систем DPI и форензик-анализа.

#### Основные возможности:
- **Полиморфная стеганография**: Данные скрыты внутри валидных WAV-файлов (выглядят как радиопомехи).
- **Аппаратная привязка (Silicon DNA)**: Шифрование привязано к уникальному ID процессора и материнской платы. Дешифровка на другом устройстве невозможна.
- **ML-KEM (Kyber-1024)**: Постквантовая защита. Использование алгоритма Kyber-1024 гарантирует безопасность данных даже против квантовых компьютеров.
- **MFA Keyfiles**: Поддержка внешних файлов-ключей для защиты от кейлоггеров.
- **Протокол «Паника»**: Ввод ключа паники физически уничтожает данные методом **Гутманна (35 проходов)**, выдавая приманку.
- **Anti-VM Shield**: Эвристическое обнаружение виртуальных сред и отладчиков для защиты от анализа.
- **Безопасность памяти**: Написано на Rust с принудительной очисткой ОЗУ (Zeroize).

[**Полная спецификация (RU)**](docs/SPEC_RU.md) | [**Инструкция по запуску**](#usage)

---

<a name="usage"></a>
## 🚀 Usage / Использование

### Build / Сборка
```bash
cargo build --release
```
### Quick Commands / Быстрые команды
- Create container / Создать контейнер
```bash
./spektr create --output vault.wav --real-pass "Pass123" --real-data "Secret" --decoy-pass "Guest" --decoy-data "Fake" --keyfile ./my_key.jpg
```

- Open container / Открыть контейнер
```bash
./spektr open --input vault.wav --password "Pass123" --keyfile ./my_key.jpg
```

- Panic Shredding / Экстренное уничтожение
```bash
./spektr open --input vault.wav --password "Guest" --panic
```
