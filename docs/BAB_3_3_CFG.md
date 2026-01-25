# BAB 3.3 - Context-Free Grammar (CFG)

## 3.3.1 Definisi CFG

Context-Free Grammar (CFG) adalah aturan formal untuk mendefinisikan struktur pola serangan SQL Injection.

**G = (V, T, P, S)**

| Komponen | Nama | Penjelasan |
|----------|------|------------|
| G | Grammar | Keseluruhan aturan tata bahasa |
| V | Variables | Simbol yang bisa dipecah (non-terminal) |
| T | Terminals | Simbol akhir / token (tidak bisa dipecah) |
| P | Productions | Aturan bagaimana simbol dipecah |
| S | Start | Simbol awal untuk mulai parsing |

---

## 3.3.2 Komponen CFG (2 Pola)

### A. Himpunan Non-Terminal (V)

| No | Non-Terminal | Deskripsi |
|----|--------------|-----------|
| 1 | SQLInjection | Simbol awal |
| 2 | BooleanAttack | Pola serangan Boolean-based |
| 3 | CommentAttack | Pola serangan Comment-based |

### B. Himpunan Terminal (T)

| No | Terminal | Simbol | Contoh |
|----|----------|--------|--------|
| 1 | QUOTE | Tanda kutip | `'` |
| 2 | OR | Keyword OR | `OR` |
| 3 | COMMENT | Komentar SQL | `--` atau `#` |
| 4 | IDENTIFIER | Nama/teks | `admin`, `user` |

### C. Simbol Awal (S)

| Komponen | Nilai |
|----------|-------|
| S | SQLInjection |

### D. Aturan Produksi (P)

| No | Aturan | Penjelasan | Contoh Input |
|----|--------|------------|--------------|
| 1 | SQLInjection → BooleanAttack | Jika ada pola Boolean | `' OR '1'='1` |
| 2 | SQLInjection → CommentAttack | Jika ada pola Comment | `admin'--` |
| 3 | SQLInjection → ε | Jika tidak ada pola (aman) | `username=admin` |
| 4 | BooleanAttack → QUOTE OR QUOTE | Pola: `' OR '` | `'` + `OR` + `'` |
| 5 | CommentAttack → QUOTE COMMENT | Pola: `'--` atau `'#` | `'` + `--` |

---

## 3.3.3 Contoh Derivasi

### Contoh 1: Input `id=1' OR '1'='1`

| Langkah | Derivasi | Aturan |
|---------|----------|--------|
| 1 | SQLInjection | Start |
| 2 | BooleanAttack | Aturan 1 |
| 3 | QUOTE OR QUOTE | Aturan 4 |
| 4 | `'` OR `'` | Substitusi |

**Hasil:** ✅ SQL Injection (Boolean-based) terdeteksi!

### Contoh 2: Input `admin'--`

| Langkah | Derivasi | Aturan |
|---------|----------|--------|
| 1 | SQLInjection | Start |
| 2 | CommentAttack | Aturan 2 |
| 3 | QUOTE COMMENT | Aturan 5 |
| 4 | `'` `--` | Substitusi |

**Hasil:** ✅ SQL Injection (Comment-based) terdeteksi!

### Contoh 3: Input `username=admin`

| Langkah | Derivasi | Aturan |
|---------|----------|--------|
| 1 | SQLInjection | Start |
| 2 | ε (kosong) | Aturan 3 |

**Hasil:** ✅ Input aman, bukan SQL Injection

---

## 3.3.4 Hubungan CFG dengan Kode

| Non-Terminal | Fungsi di parser.py |
|--------------|---------------------|
| SQLInjection | `parse()` |
| BooleanAttack | `_parse_boolean_attack()` |
| CommentAttack | `_parse_comment_attack()` |
