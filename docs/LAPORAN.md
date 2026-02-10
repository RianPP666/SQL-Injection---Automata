# LAPORAN PROYEK

# Mini-IDS: Sistem Deteksi SQL Injection

### Mata Kuliah: Automata dan Teknik Kompilasi

---

## DAFTAR ISI

- BAB I PENDAHULUAN
- BAB II LANDASAN TEORI
- BAB III IMPLEMENTASI SISTEM
- BAB IV HASIL DAN PEMBAHASAN
- BAB V PENUTUP

---

## BAB I PENDAHULUAN

### 1.1 Latar Belakang

SQL Injection merupakan salah satu serangan siber yang paling umum dan berbahaya terhadap aplikasi web. Serangan ini bekerja dengan menyisipkan kode SQL berbahaya ke dalam input yang diterima oleh aplikasi, sehingga penyerang dapat mengakses, memodifikasi, atau menghapus data di database tanpa otorisasi.

Dalam proyek ini, kami mengembangkan **Mini-IDS (Intrusion Detection System)** yang memanfaatkan konsep **Automata dan Teknik Kompilasi** untuk mendeteksi serangan SQL Injection. Sistem ini menerapkan konsep Lexer, Parser, CFG (Context-Free Grammar), AST (Abstract Syntax Tree), DFA (Deterministic Finite Automaton), dan Regex untuk menganalisis input dan menentukan apakah input tersebut mengandung serangan SQL Injection.

### 1.2 Rumusan Masalah

1. Bagaimana menerapkan konsep Automata dan Teknik Kompilasi untuk mendeteksi serangan SQL Injection?
2. Bagaimana membangun sistem deteksi yang mampu mengidentifikasi pola Boolean-based dan Comment-based SQL Injection?

### 1.3 Tujuan

1. Menerapkan konsep Lexer, Parser, CFG, AST, dan DFA dalam sistem deteksi serangan.
2. Membangun Mini-IDS yang mampu mendeteksi 2 pola serangan SQL Injection: **Boolean-based** dan **Comment-based**.
3. Mendemonstrasikan pemahaman konsep Automata dan Teknik Kompilasi melalui implementasi nyata.

### 1.4 Batasan Masalah

1. Sistem hanya mendeteksi 2 pola SQL Injection: Boolean-based dan Comment-based.
2. Sistem tidak melakukan pencegahan atau pemblokiran secara real-time terhadap serangan.
3. Input yang dianalisis berupa string payload, bukan request HTTP secara langsung.

---

## BAB II LANDASAN TEORI

### 2.1 SQL Injection

SQL Injection adalah teknik serangan yang mengeksploitasi celah keamanan pada aplikasi yang berinteraksi dengan database. Penyerang menyisipkan kode SQL berbahaya melalui input pengguna untuk memanipulasi query database.

#### 2.1.1 Boolean-based SQL Injection

Serangan ini menyisipkan kondisi logika yang selalu bernilai benar (always true) ke dalam query SQL.

**Contoh:**
```
Input normal : username=admin
Input attack : id=1' OR '1'='1
```

Pada contoh di atas, `' OR '1'='1` akan membuat kondisi WHERE pada query SQL selalu bernilai TRUE, sehingga seluruh data dalam tabel dapat diakses.

#### 2.1.2 Comment-based SQL Injection

Serangan ini menggunakan karakter komentar SQL (`--` atau `#`) untuk mengabaikan sisa query asli, sehingga penyerang bisa melewati mekanisme autentikasi.

**Contoh:**
```
Input normal : username=admin
Input attack : admin'--
```

Pada contoh di atas, `'--` akan menutup string dan menjadikan sisa query sebagai komentar, sehingga pengecekan password diabaikan.

### 2.2 Lexer (Lexical Analyzer)

Lexer adalah komponen pertama dalam pipeline kompilasi yang bertugas memecah input string menjadi token-token. Setiap token memiliki tipe dan nilai.

**Contoh:**
```
Input: "admin'--"
Token: [IDENTIFIER("admin"), SQL_QUOTE("'"), SQL_COMMENT("--")]
```

### 2.3 CFG (Context-Free Grammar)

CFG adalah formalisme yang digunakan untuk mendefinisikan aturan sintaksis suatu bahasa. CFG terdiri dari 4 komponen:

| Komponen | Nama | Fungsi |
|----------|------|--------|
| **V** | Variable (Non-Terminal) | Simbol yang bisa dipecah lebih lanjut |
| **T** | Terminal | Simbol akhir (token dari Lexer) |
| **S** | Start Symbol | Titik awal parsing |
| **P** | Production Rules | Aturan penggantian/derivasi |

### 2.4 Parser dan AST

**Parser** adalah komponen yang membaca token dari Lexer dan mencocokkannya dengan aturan CFG. Hasil dari proses parsing adalah **AST (Abstract Syntax Tree)** — representasi pohon yang menggambarkan struktur input.

### 2.5 DFA (Deterministic Finite Automaton)

DFA adalah model komputasi yang terdiri dari himpunan state, alfabet input, fungsi transisi, state awal, dan himpunan state akhir (accept state). DFA membaca input satu per satu dan berpindah state berdasarkan fungsi transisi. Jika berakhir di state accept, input diterima (ACCEPT); jika tidak, input ditolak (REJECT).

**Komponen DFA:**

| Komponen | Simbol | Fungsi |
|----------|--------|--------|
| Himpunan State | Q | Kumpulan semua state |
| Alfabet | Σ | Simbol input yang valid |
| Fungsi Transisi | δ | Aturan perpindahan state |
| State Awal | q₀ | Titik mulai |
| State Akhir | F | State penerima (accept) |

### 2.6 Regex (Regular Expression)

Regex adalah pola teks yang digunakan untuk mencocokkan substring dalam input. Dalam proyek ini, regex digunakan oleh Lexer untuk tokenisasi dan oleh Automata untuk pattern matching.

---

## BAB III IMPLEMENTASI SISTEM

### 3.1 Arsitektur Sistem

Sistem Mini-IDS terdiri dari 4 file utama yang bekerja secara berurutan:

```
Input Payload
      │
      ▼
┌─ main.py ──────────────────────────────────┐
│  (Koordinator utama)                       │
│      │                                      │
│      ├──► lexer.py   → Token Stream         │
│      │                    │                  │
│      │                    ▼                  │
│      ├──► parser.py  → AST (CFG)            │
│      │                                      │
│      ├──► automata.py → ACCEPT/REJECT (DFA) │
│      │                                      │
│      └──► Gabung Hasil → BLOCK / ALLOW      │
└─────────────────────────────────────────────┘
```

### 3.2 Lexer (`lexer.py`)

**Fungsi:** Memecah input string menjadi token-token menggunakan regex.

**Token yang dikenali:**

| Token Type | Pattern Regex | Contoh |
|------------|---------------|--------|
| SQL_KEYWORD | `\b(OR\|AND\|SELECT)\b` | OR, AND |
| ALWAYS_TRUE | `('1'\s*=\s*'1'\|1\s*=\s*1)` | '1'='1', 1=1 |
| SQL_COMMENT | `(--\|#)` | --, # |
| SQL_QUOTE | `['"]` | ', " |
| SQL_OPERATOR | `(=\|<\|>)` | = |
| IDENTIFIER | `[a-zA-Z_][a-zA-Z0-9_]*` | admin, user |
| NUMBER | `\d+` | 1, 123 |

**Cara Kerja:**
1. Baca input dari posisi awal
2. Coba cocokkan setiap pattern regex satu per satu
3. Jika cocok, buat token dan geser posisi
4. Ulangi sampai seluruh input habis

**Contoh Proses Tokenisasi:**
```
Input: "id=1' OR '1'='1"

Langkah 1: "id"    → match [a-zA-Z_]+ → Token(IDENTIFIER, "id")
Langkah 2: "="     → match [=<>]      → Token(SQL_OPERATOR, "=")
Langkah 3: "1"     → match \d+        → Token(NUMBER, "1")
Langkah 4: "'"     → match ['"]       → Token(SQL_QUOTE, "'")
Langkah 5: "OR"    → match \b(OR)\b   → Token(SQL_KEYWORD, "OR")
Langkah 6: "'1'='1"→ match '1'='1'    → Token(ALWAYS_TRUE, "'1'='1")

Output: [IDENTIFIER, SQL_OPERATOR, NUMBER, SQL_QUOTE, SQL_KEYWORD, ALWAYS_TRUE, EOF]
```

### 3.3 Parser dan CFG (`parser.py`)

**Fungsi:** Mencocokkan token dengan aturan CFG dan menghasilkan AST.

#### 3.3.1 Definisi CFG

**G = (V, T, S, P)** dimana:

**V (Variable/Non-Terminal):**

| No | Non-Terminal | Keterangan |
|----|-------------|------------|
| 1 | SQLInjection | Start symbol |
| 2 | SQLPattern | Pola serangan |
| 3 | BooleanAttack | Serangan Boolean-based |
| 4 | CommentAttack | Serangan Comment-based |
| 5 | AlwaysTrue | Kondisi selalu benar |

**T (Terminal):**

| No | Terminal | Contoh |
|----|----------|--------|
| 1 | QUOTE | ' |
| 2 | OR / AND | OR, AND |
| 3 | COMMENT | --, # |
| 4 | NUMBER | 1 |
| 5 | EQUALS | = |

**S (Start Symbol):** SQLInjection

**P (Production Rules):**

| No | Aturan | Keterangan |
|----|--------|------------|
| 1 | SQLInjection → SQLPattern \| ε | Mulai: ada pola atau kosong |
| 2 | SQLPattern → BooleanAttack \| CommentAttack | Pola: Boolean atau Comment |
| 3 | BooleanAttack → QUOTE (OR\|AND) AlwaysTrue | Pola Boolean-based |
| 4 | CommentAttack → QUOTE COMMENT | Pola Comment-based |
| 5 | AlwaysTrue → NUMBER EQUALS NUMBER | Kondisi selalu benar |

#### 3.3.2 Proses Parsing (Recursive Descent)

Parser bekerja dengan teknik **Recursive Descent** — setiap aturan CFG diimplementasikan sebagai fungsi:

```python
def _parse_sql_injection(self):
    if self._is_boolean_attack():      # Cek aturan 3
        return self._parse_boolean_attack()
    if self._is_comment_attack():      # Cek aturan 4
        return self._parse_comment_attack()
    return None                        # ε (kosong/aman)
```

#### 3.3.3 Contoh Derivasi CFG

**Input:** `admin'--`

```
SQLInjection → SQLPattern         (Aturan 1)
             → CommentAttack      (Aturan 2)
             → QUOTE COMMENT      (Aturan 4)
             → ' --               (Substitusi terminal)
             → COCOK! ✅
```

**Input:** `' OR '1'='1`

```
SQLInjection → SQLPattern         (Aturan 1)
             → BooleanAttack      (Aturan 2)
             → QUOTE OR AlwaysTrue (Aturan 3)
             → ' OR NUMBER=NUMBER  (Aturan 5)
             → ' OR '1'='1'       (Substitusi terminal)
             → COCOK! ✅
```

#### 3.3.4 AST (Abstract Syntax Tree)

Hasil parsing berupa pohon AST:

**Input Berbahaya (`admin'--`):**
```
PayloadNode (is_malicious = true)
    └── SQLInjectionNode (type = COMMENT_BASED)
            ├── PAYLOAD ("admin'")
            └── SQL_COMMENT ("--")
```

**Input Aman (`username=admin`):**
```
PayloadNode (is_malicious = false)
    └── SafeNode ("Input aman, tidak ada serangan")
```

### 3.4 Automata / DFA (`automata.py`)

**Fungsi:** Verifikasi pattern serangan menggunakan DFA dan regex.

#### 3.4.1 DFA Boolean-based

Mendeteksi pola: `' OR '1'='1`

```
Definisi Formal:
  Q  = {q0, q1, q2, q3}
  Σ  = {', OR, AlwaysTrue}
  q0 = q0 (state awal)
  F  = {q3} (state akhir)

  Transisi:
  δ(q0, ')  = q1
  δ(q1, OR) = q2
  δ(q2, ')  = q3 (ACCEPT)
```

**Diagram:**
```
   ┌───┐   '   ┌───┐  OR  ┌───┐   '   ╔═══╗
   │q0 │──────►│q1 │─────►│q2 │──────►║q3 ║
   └───┘       └───┘      └───┘       ╚═══╝
  start                               ACCEPT
```

#### 3.4.2 DFA Comment-based

Mendeteksi pola: `'--` atau `'#`

```
Definisi Formal:
  Q  = {q0, q1, q2}
  Σ  = {', --, #}
  q0 = q0 (state awal)
  F  = {q2} (state akhir)

  Transisi:
  δ(q0, ')  = q1
  δ(q1, --) = q2 (ACCEPT)
  δ(q1, #)  = q2 (ACCEPT)
```

**Diagram:**
```
                    --
   ┌───┐   '   ┌───┐──────►╔═══╗
   │q0 │──────►│q1 │       ║q2 ║
   └───┘       └───┤──────►╚═══╝
  start            │   #
                   └────────────
```

#### 3.4.3 Simulasi DFA Step-by-Step

**Input:** `admin'--`

| Langkah | Baca | State Sekarang | Transisi | State Baru |
|---------|------|---------------|----------|------------|
| 1 | admin | q0 | tidak ada transisi | q0 |
| 2 | ' | q0 | δ(q0, ') = q1 | q1 |
| 3 | -- | q1 | δ(q1, --) = q2 | q2 |

**State akhir:** q2 ∈ F → **ACCEPT** (Serangan terdeteksi!)

#### 3.4.4 Pattern Regex

Selain DFA, sistem juga menggunakan regex untuk deteksi cepat:

| Pattern Regex | Tipe | Contoh Match |
|---------------|------|-------------|
| `'\s*(OR\|AND)\s*'` | BOOLEAN_BASED | `' OR '` |
| `(OR\|AND)\s+1\s*=\s*1` | BOOLEAN_BASED | `OR 1=1` |
| `'1'\s*=\s*'1'` | BOOLEAN_BASED | `'1'='1'` |
| `'--` | COMMENT_BASED | `'--` |
| `'#` | COMMENT_BASED | `'#` |

### 3.5 Main Program (`main.py`)

**Fungsi:** Entry point yang mengkoordinasikan semua komponen.

**Alur Eksekusi:**
1. Terima input payload dari user
2. Panggil Lexer → tokenisasi
3. Panggil Parser → buat AST (pakai CFG)
4. Panggil Automata → cek DFA/regex
5. Gabungkan hasil → BLOCK atau ALLOW

**Mode Eksekusi:**

| Mode | Command | Fungsi |
|------|---------|--------|
| Test | `python main.py --test` | Jalankan 5 test cases otomatis |
| Interactive | `python main.py --interactive` | Input manual berkali-kali |
| Payload | `python main.py --payload "..."` | Analisis 1 payload |

---

## BAB IV HASIL DAN PEMBAHASAN

### 4.1 Test Cases

Sistem diuji dengan 5 test cases yang mencakup input aman dan 2 pola serangan:

| No | Payload | Expected | Actual | Status |
|----|---------|----------|--------|--------|
| 1 | `username=admin&password=123` | CLEAN | CLEAN | ✅ PASS |
| 2 | `id=1' OR '1'='1` | BOOLEAN_BASED | BOOLEAN_BASED | ✅ PASS |
| 3 | `id=1' OR 1=1` | BOOLEAN_BASED | BOOLEAN_BASED | ✅ PASS |
| 4 | `admin'--` | COMMENT_BASED | COMMENT_BASED | ✅ PASS |
| 5 | `user'#` | COMMENT_BASED | COMMENT_BASED | ✅ PASS |

**Hasil: 5/5 test cases passed (100%)**

### 4.2 Pembahasan Per Test Case

#### Test Case 1: Input Aman
```
Input: username=admin&password=123
```
- **Lexer:** Menghasilkan token [IDENTIFIER, SQL_OPERATOR, IDENTIFIER, SPECIAL_CHAR, IDENTIFIER, SQL_OPERATOR, NUMBER]
- **Parser:** Tidak ada token SQL_KEYWORD (OR/AND) atau SQL_COMMENT (--/#), sehingga CFG tidak cocok dengan pola serangan manapun
- **Automata:** Regex tidak menemukan pattern serangan
- **Hasil:** CLEAN → ALLOW ✅

#### Test Case 2: Boolean-based (`' OR '1'='1`)
```
Input: id=1' OR '1'='1
```
- **Lexer:** Mengenali token SQL_KEYWORD("OR") dan ALWAYS_TRUE("'1'='1")
- **Parser:** CFG cocok: ada QUOTE + OR + AlwaysTrue → BooleanAttack
- **Automata:** Regex `'\s*(OR|AND)\s*'` mendeteksi pattern
- **Hasil:** BOOLEAN_BASED → BLOCK 🚨

#### Test Case 3: Boolean-based (`OR 1=1`)
```
Input: id=1' OR 1=1
```
- **Lexer:** Mengenali SQL_KEYWORD("OR") dan ALWAYS_TRUE("1=1")
- **Parser:** CFG cocok: BooleanAttack
- **Automata:** Regex `(OR|AND)\s+1\s*=\s*1` mendeteksi pattern
- **Hasil:** BOOLEAN_BASED → BLOCK 🚨

#### Test Case 4: Comment-based (`'--`)
```
Input: admin'--
```
- **Lexer:** Mengenali SQL_QUOTE("'") dan SQL_COMMENT("--")
- **Parser:** CFG cocok: ada QUOTE + COMMENT → CommentAttack
- **Automata:** Regex `'--` mendeteksi pattern
- **Hasil:** COMMENT_BASED → BLOCK 🚨

#### Test Case 5: Comment-based (`'#`)
```
Input: user'#
```
- **Lexer:** Mengenali SQL_QUOTE("'") dan SQL_COMMENT("#")
- **Parser:** CFG cocok: ada QUOTE + COMMENT → CommentAttack
- **Automata:** Regex `'#` mendeteksi pattern
- **Hasil:** COMMENT_BASED → BLOCK 🚨

### 4.3 Analisis Sistem

#### Kelebihan:
1. **Multi-layer detection:** Menggunakan Parser (CFG) dan Automata (DFA/Regex) secara bersamaan untuk meningkatkan akurasi.
2. **Menerapkan konsep Teknik Kompilasi:** Lexer, Parser, CFG, AST, dan DFA terintegrasi dalam satu sistem.
3. **100% akurasi** pada test cases yang diuji.

#### Keterbatasan:
1. Hanya mendeteksi 2 pola serangan (Boolean-based dan Comment-based).
2. Belum menangani UNION-based, Time-based, dan jenis SQL Injection lainnya.
3. Deteksi berbasis string matching, belum menganalisis konteks query SQL secara mendalam.

---

## BAB V PENUTUP

### 5.1 Kesimpulan

1. Konsep Automata dan Teknik Kompilasi berhasil diterapkan dalam sistem deteksi SQL Injection melalui komponen Lexer (tokenisasi), Parser (CFG dan AST), dan Automata (DFA dan Regex).
2. Sistem Mini-IDS mampu mendeteksi 2 pola serangan SQL Injection (**Boolean-based** dan **Comment-based**) dengan tingkat akurasi 100% pada 5 test cases yang diuji.
3. Penggabungan hasil dari Parser dan Automata memberikan deteksi yang lebih andal dibandingkan menggunakan satu metode saja.

### 5.2 Saran

1. Menambahkan pola deteksi SQL Injection lainnya seperti UNION-based dan Time-based.
2. Mengintegrasikan sistem dengan web server untuk deteksi secara real-time.
3. Menambahkan fitur logging dan pelaporan untuk analisis insiden keamanan.

---

## DAFTAR PUSTAKA

1. OWASP Foundation. (2023). *SQL Injection*. https://owasp.org/www-community/attacks/SQL_Injection
2. Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D. (2006). *Compilers: Principles, Techniques, and Tools (2nd Edition)*. Pearson.
3. Hopcroft, J. E., Motwani, R., & Ullman, J. D. (2006). *Introduction to Automata Theory, Languages, and Computation (3rd Edition)*. Pearson.
