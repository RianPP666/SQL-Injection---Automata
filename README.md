# Mini-IDS: SQL Injection Detection System (2 Pola)

Sistem deteksi intrusi berbasis automata untuk mendeteksi serangan **SQL Injection**.

## Pola yang Dideteksi

| Pola | Contoh | Severity |
|------|--------|----------|
| Boolean-based | `' OR '1'='1` | HIGH |
| Comment-based | `admin'--` | HIGH |

## Struktur Proyek

```
mini-ids/
├── src/
│   ├── main.py         # Entry point
│   ├── lexer.py        # Lexical analyzer (DFA)
│   ├── parser.py       # Recursive descent parser
│   ├── automata.py     # DFA/NFA simulation
│   ├── semantic.py     # Semantic analyzer
│   ├── ir.py           # Intermediate representation
│   └── interpreter.py  # DSL interpreter
├── diagrams/           # PlantUML diagrams
├── docs/
│   └── LAPORAN_LENGKAP.md  # Laporan lengkap
├── tests/              # 5 test cases
└── README.md
```

## Cara Menjalankan

```bash
cd src

# Run 5 test cases
python main.py --test

# Mode interaktif
python main.py --interactive

# Analisis satu payload
python main.py --payload "id=1' OR '1'='1" --verbose
```

## Test Cases

| # | Input | Expected | Result |
|---|-------|----------|--------|
| 1 | `username=admin&password=123` | CLEAN | ✅ |
| 2 | `id=1' OR '1'='1` | BOOLEAN | ✅ |
| 3 | `id=1' OR 1=1` | BOOLEAN | ✅ |
| 4 | `admin'--` | COMMENT | ✅ |
| 5 | `user'#` | COMMENT | ✅ |

## Komponen

1. **Lexer** - Tokenisasi payload (DFA-based)
2. **Parser** - Recursive Descent berdasarkan CFG
3. **Automata** - Simulasi DFA untuk pattern matching
4. **Semantic** - Analisis semantik dan risk assessment
5. **IR** - Intermediate Representation
6. **Interpreter** - DSL untuk signature rules

## Mata Kuliah
Automata dan Teknik Kompilasi
