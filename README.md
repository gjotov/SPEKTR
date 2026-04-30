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

[**Полная спецификация (RU)**](docs/SPEC_RU.md) | [**Инструкция по запуску**](#usage)

---

<a name="usage"></a>
## Usage / Использование

### Build / Сборка
```bash
cargo build --release
