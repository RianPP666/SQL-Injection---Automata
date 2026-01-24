# LAPORAN MINI-IDS: DETEKSI SQL INJECTION
## Mata Kuliah: Automata dan Teknik Kompilasi

---

# BAB 1 - PENDAHULUAN

## 1.1 Latar Belakang

SQL Injection merupakan salah satu serangan siber paling berbahaya yang menargetkan aplikasi web. Serangan ini memanfaatkan celah keamanan pada input yang tidak tervalidasi untuk menyisipkan kode SQL berbahaya ke dalam query database. Menurut OWASP (Open Web Application Security Project), SQL Injection secara konsisten masuk dalam daftar 10 kerentanan keamanan aplikasi web teratas.

Dalam konteks mata kuliah Automata dan Teknik Kompilasi, deteksi SQL Injection dapat diimplementasikan menggunakan konsep-konsep fundamental seperti:
- Finite Automata (DFA/NFA) untuk pattern matching
- Context-Free Grammar (CFG) untuk analisis sintaksis
- Lexical analysis untuk tokenisasi
- Parsing untuk pembangunan AST

## 1.2 Deskripsi Tema dan Studi Kasus

**Tema**: Keamanan Jaringan - Mini Intrusion Detection System (IDS)

**Studi Kasus**: Membangun sistem deteksi intrusi sederhana yang mampu mengenali pola serangan SQL Injection pada input HTTP request.

**Pola Serangan yang Dideteksi**:

| No | Tipe Serangan | Contoh | Deskripsi |
|----|---------------|--------|-----------|
| 1 | Boolean-based | `' OR '1'='1` | Menyisipkan kondisi yang selalu TRUE |
| 2 | Comment-based | `admin'--` | Menggunakan komentar SQL untuk mengabaikan sisa query |

## 1.3 Tujuan dan Batasan Sistem

**Tujuan**:
1. Mengimplementasikan lexer berbasis DFA untuk tokenisasi payload
2. Membangun parser recursive descent berdasarkan CFG
3. Melakukan simulasi automata untuk pattern matching
4. Menghasilkan sistem deteksi yang dapat mengidentifikasi 2 jenis SQL Injection

**Batasan**:
1. Sistem hanya mendeteksi 2 pola: Boolean-based dan Comment-based
2. Tidak mencakup deteksi serangan lain (XSS, LDAP Injection, dll)
3. Fokus pada konsep automata dan teknik kompilasi

---

# BAB 2 - LANDASAN TEORI

## 2.1 SQL Injection

SQL Injection adalah teknik serangan yang menyisipkan kode SQL berbahaya melalui input pengguna. Contoh:

```sql
-- Query normal:
SELECT * FROM users WHERE username='admin' AND password='secret'

-- Dengan SQL Injection (Boolean-based):
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='xxx'
-- Hasil: Kondisi OR '1'='1' selalu TRUE, bypass autentikasi!

-- Dengan SQL Injection (Comment-based):
SELECT * FROM users WHERE username='admin'--' AND password='xxx'
-- Hasil: Password diabaikan karena di-comment!
```

## 2.2 Finite Automata

**DFA (Deterministic Finite Automaton)** adalah model komputasi dengan:
- Himpunan state terbatas (Q)
- Alfabet input (Σ)
- Fungsi transisi deterministik (δ)
- State awal (q0)
- Himpunan state akhir (F)

DFA digunakan untuk mengenali pattern string yang sesuai dengan aturan tertentu.

## 2.3 Context-Free Grammar

**CFG** adalah tata bahasa formal untuk mendefinisikan struktur sintaksis bahasa. Terdiri dari:
- Simbol non-terminal (V)
- Simbol terminal (T)
- Aturan produksi (P)
- Simbol awal (S)

---

# BAB 3 - DESAIN DAN IMPLEMENTASI

## 3.1 Daftar Token dan Regular Expression

Token adalah unit terkecil yang dihasilkan oleh lexer. Berikut daftar token untuk Mini-IDS:

| Token | Regular Expression | Deskripsi | Contoh |
|-------|-------------------|-----------|--------|
| SQL_KEYWORD | `\b(OR\|AND\|SELECT\|FROM\|WHERE)\b` | Kata kunci SQL | OR, AND |
| SQL_QUOTE | `['\"]` | Tanda kutip | ' |
| SQL_COMMENT | `(--\|#)` | Komentar SQL | --, # |
| SQL_OPERATOR | `(=\|<\|>)` | Operator | = |
| ALWAYS_TRUE | `('1'\s*=\s*'1'\|1\s*=\s*1)` | Kondisi TRUE | '1'='1' |
| IDENTIFIER | `[a-zA-Z_][a-zA-Z0-9_]*` | Nama variabel | admin |
| NUMBER | `\d+` | Angka | 1, 123 |

### Proses Tokenisasi

```
Input: "id=1' OR '1'='1"

Token Stream:
1. IDENTIFIER("id")
2. SQL_OPERATOR("=")
3. NUMBER("1")
4. SQL_QUOTE("'")
5. SQL_KEYWORD("OR")
6. ALWAYS_TRUE("'1'='1'")
```

## 3.2 Sketsa NFA/DFA

### DFA untuk Boolean-based SQL Injection

```
Definisi Formal:
M = (Q, Σ, δ, q0, F)

Q  = {q0, q1, q2, q3}
Σ  = {', OR, other}
q0 = q0 (state awal)
F  = {q3} (state akhir)

Tabel Transisi δ:
┌───────┬─────┬──────┬───────┐
│ State │  '  │  OR  │ other │
├───────┼─────┼──────┼───────┤
│  q0   │ q1  │  -   │  q0   │
│  q1   │  -  │ q2   │  -    │
│  q2   │ q3  │  -   │  -    │
│  q3   │  -  │  -   │  -    │ (Accept)
└───────┴─────┴──────┴───────┘

Diagram:
     '        OR        '
→(q0) ────► (q1) ────► (q2) ────► ((q3))
                                   Accept
```

### DFA untuk Comment-based SQL Injection

```
Definisi Formal:
M = (Q, Σ, δ, q0, F)

Q  = {c0, c1, c2}
Σ  = {', --, #, other}
c0 = c0 (state awal)
F  = {c2} (state akhir)

Tabel Transisi δ:
┌───────┬─────┬──────┬─────┬───────┐
│ State │  '  │  --  │  #  │ other │
├───────┼─────┼──────┼─────┼───────┤
│  c0   │ c1  │  -   │  -  │  c0   │
│  c1   │  -  │ c2   │ c2  │  -    │
│  c2   │  -  │  -   │  -  │  -    │ (Accept)
└───────┴─────┴──────┴─────┴───────┘

Diagram:
     '        -- atau #
→(c0) ────► (c1) ────────► ((c2))
                            Accept
```

## 3.3 Context-Free Grammar (CFG)

### Definisi Formal

```
G = (V, T, P, S)

V = {SQLInjection, SQLPattern, BooleanAttack, CommentAttack, AlwaysTrue}
T = {QUOTE, OR, AND, SQL_COMMENT, NUMBER, EQUALS, IDENTIFIER}
S = SQLInjection
```

### Aturan Produksi (P)

```
(1)  SQLInjection  → SQLPattern
(2)  SQLInjection  → ε

(3)  SQLPattern    → BooleanAttack
(4)  SQLPattern    → CommentAttack

(5)  BooleanAttack → QUOTE OR AlwaysTrue
(6)  BooleanAttack → QUOTE AND AlwaysTrue

(7)  CommentAttack → Payload SQL_COMMENT

(8)  AlwaysTrue    → QUOTE NUMBER EQUALS QUOTE NUMBER
(9)  AlwaysTrue    → NUMBER EQUALS NUMBER
```

### Contoh Derivasi

**Input**: `id=1' OR '1'='1`

```
SQLInjection
  ⇒ SQLPattern                           [aturan 1]
  ⇒ BooleanAttack                        [aturan 3]
  ⇒ QUOTE OR AlwaysTrue                  [aturan 5]
  ⇒ QUOTE OR QUOTE NUMBER EQUALS QUOTE NUMBER   [aturan 8]
  ⇒ '     OR '     1      =      '     1
  
✓ ACCEPT - SQL Injection Detected!
```

## 3.4 Desain Parser (Recursive Descent)

Parser mengimplementasikan CFG menggunakan teknik Recursive Descent, dimana setiap non-terminal direpresentasikan sebagai fungsi:

```python
def parse(self):
    """SQLInjection → SQLPattern | ε"""
    sql_node = self._parse_sql_injection()
    if sql_node:
        return sql_node
    return SafeNode()

def _parse_sql_injection(self):
    """SQLPattern → BooleanAttack | CommentAttack"""
    if self._is_boolean_attack():
        return self._parse_boolean_attack()
    if self._is_comment_attack():
        return self._parse_comment_attack()
    return None
```

### Sketsa AST

```
         PayloadNode
         (is_malicious=true)
              │
              ▼
       SQLInjectionNode
       (type=BOOLEAN_BASED)
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
 QUOTE      KEYWORD   ALWAYS_TRUE
  (')       (OR)      ('1'='1')
```

## 3.5 Desain IR/DSL

### IR Opcodes

| Opcode | Deskripsi |
|--------|-----------|
| LOAD | Load payload ke memory |
| CHECK | Cek pattern SQL Injection |
| BLOCK | Blokir request berbahaya |
| ALLOW | Izinkan request aman |
| LOG | Catat event |
| HALT | Akhiri program |

### Contoh IR Program

```
Input: id=1' OR '1'='1

IR Program:
  0: LOAD payload
  1: CHECK BOOLEAN_BASED "' OR '"
  2: BLOCK BOOLEAN_BASED
  3: LOG DETECTED BOOLEAN_BASED
  4: HALT
```

### Alur Eksekusi

```
Input Payload
     │
     ▼
   Lexer ──────► Token Stream
     │
     ▼
   Parser ─────► AST
     │
     ▼
 Semantic ─────► Issues & Risk
     │
     ▼
  DFA/NFA ─────► Detection Result
     │
     ▼
 Response ─────► BLOCK / ALLOW
```

## 3.6 Simulasi Automata dan Contoh Input-Output

### Simulasi DFA Boolean-based

Input: `id=1' OR '1'='1`

```
State Trace:
q0 ──(id=1)──► q0 ──(')──► q1 ──(OR)──► q2 ──(')──► q3 (ACCEPT!)

Hasil: SQL Injection (Boolean-based) DETECTED
Action: BLOCK
```

### 5 Input Test Cases

| # | Input | Pola | Hasil |
|---|-------|------|-------|
| 1 | `username=admin&password=123` | - | ✅ CLEAN |
| 2 | `id=1' OR '1'='1` | Boolean | 🚨 DETECTED |
| 3 | `id=1' OR 1=1` | Boolean | 🚨 DETECTED |
| 4 | `admin'--` | Comment | 🚨 DETECTED |
| 5 | `user'#` | Comment | 🚨 DETECTED |

---

# BAB 4 - PENGUJIAN

## 4.1 Skenario Pengujian

### Test Case 1: Input Normal (Aman)
```
Input: username=admin&password=123
Expected: CLEAN (ALLOW)
Actual: CLEAN (ALLOW)
Status: ✅ PASS
```

### Test Case 2: Boolean-based SQL Injection
```
Input: id=1' OR '1'='1
Expected: BOOLEAN_BASED (BLOCK)
Actual: BOOLEAN_BASED (BLOCK)
Status: ✅ PASS
```

### Test Case 3: Boolean-based Variant
```
Input: id=1' OR 1=1
Expected: BOOLEAN_BASED (BLOCK)
Actual: BOOLEAN_BASED (BLOCK)
Status: ✅ PASS
```

### Test Case 4: Comment-based (Double Dash)
```
Input: admin'--
Expected: COMMENT_BASED (BLOCK)
Actual: COMMENT_BASED (BLOCK)
Status: ✅ PASS
```

### Test Case 5: Comment-based (Hash)
```
Input: user'#
Expected: COMMENT_BASED (BLOCK)
Actual: COMMENT_BASED (BLOCK)
Status: ✅ PASS
```

## 4.2 Hasil Pengujian

| Metrik | Nilai |
|--------|-------|
| Total Test Cases | 5 |
| Passed | 5 |
| Failed | 0 |
| Success Rate | 100% |

---

# BAB 5 - KESIMPULAN

## 5.1 Kesimpulan

1. Sistem Mini-IDS berhasil diimplementasikan menggunakan konsep automata dan teknik kompilasi
2. DFA berhasil digunakan untuk pattern matching SQL Injection
3. Parser Recursive Descent berhasil mengidentifikasi struktur serangan berdasarkan CFG
4. Sistem mampu mendeteksi 2 jenis SQL Injection: Boolean-based dan Comment-based
5. Semua 5 test cases berhasil dieksekusi dengan benar

## 5.2 Saran Pengembangan

1. Menambahkan pola SQL Injection lainnya (UNION-based, Time-based)
2. Mengimplementasikan deteksi serangan lain (XSS, LDAP Injection)
3. Menambahkan machine learning untuk deteksi anomali
4. Integrasi dengan web application firewall (WAF)
