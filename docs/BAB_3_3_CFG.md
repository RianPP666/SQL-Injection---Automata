# BAB 3.3 - Context-Free Grammar (CFG)

## 3.3.1 Definisi CFG

Context-Free Grammar (CFG) adalah tata bahasa formal yang digunakan untuk mendefinisikan 
struktur sintaksis dari pola serangan SQL Injection. CFG memungkinkan kita untuk 
mendeskripsikan hierarki dan urutan token yang membentuk sebuah serangan.

Secara formal, CFG didefinisikan sebagai 4-tuple:

**G = (V, T, P, S)**

Dimana:
- **V** = Himpunan simbol non-terminal (variabel)
- **T** = Himpunan simbol terminal (token)
- **P** = Himpunan aturan produksi
- **S** = Simbol awal (start symbol)

---

## 3.3.2 Komponen CFG untuk SQL Injection Detection

### A. Himpunan Non-Terminal (V)

| Non-Terminal | Deskripsi |
|--------------|-----------|
| SQLInjection | Simbol awal, merepresentasikan seluruh input |
| SQLPattern | Pola serangan SQL Injection |
| BooleanAttack | Serangan berbasis kondisi boolean |
| UnionAttack | Serangan berbasis UNION SELECT |
| CommentAttack | Serangan berbasis SQL comment |
| StackedQuery | Serangan berbasis stacked query |
| AlwaysTrue | Kondisi yang selalu bernilai true |
| ColumnList | Daftar kolom dalam SELECT |
| Payload | Konten umum/payload |

### B. Himpunan Terminal (T)

| Terminal | Deskripsi | Contoh |
|----------|-----------|--------|
| QUOTE | Tanda kutip | ' atau " |
| OR | Keyword OR | OR |
| AND | Keyword AND | AND |
| UNION | Keyword UNION | UNION |
| ALL | Keyword ALL | ALL |
| SELECT | Keyword SELECT | SELECT |
| SQL_COMMENT | Komentar SQL | -- atau # atau /* |
| SEMICOLON | Titik koma | ; |
| SQL_KEYWORD | Keyword SQL lainnya | DROP, DELETE, INSERT |
| IDENTIFIER | Nama variabel/kolom | username, id |
| NUMBER | Angka | 1, 123 |
| EQUALS | Operator sama dengan | = |
| COMMA | Koma | , |
| STRING | String literal | 'admin' |

### C. Simbol Awal (S)

**S = SQLInjection**

---

## 3.3.3 Aturan Produksi (P)

Berikut adalah aturan produksi dalam notasi BNF (Backus-Naur Form):

```
(1)  SQLInjection  → SQLPattern
(2)  SQLInjection  → ε

(3)  SQLPattern    → BooleanAttack
(4)  SQLPattern    → UnionAttack
(5)  SQLPattern    → CommentAttack
(6)  SQLPattern    → StackedQuery

(7)  BooleanAttack → QUOTE OR AlwaysTrue
(8)  BooleanAttack → QUOTE AND AlwaysTrue

(9)  UnionAttack   → UNION SELECT ColumnList
(10) UnionAttack   → UNION ALL SELECT ColumnList

(11) CommentAttack → Payload SQL_COMMENT

(12) StackedQuery  → SEMICOLON SQL_KEYWORD Payload

(13) AlwaysTrue    → QUOTE NUMBER EQUALS QUOTE NUMBER
(14) AlwaysTrue    → NUMBER EQUALS NUMBER

(15) ColumnList    → IDENTIFIER
(16) ColumnList    → IDENTIFIER COMMA ColumnList

(17) Payload       → IDENTIFIER Payload
(18) Payload       → NUMBER Payload
(19) Payload       → STRING Payload
(20) Payload       → ε
```

---

## 3.3.4 Penjelasan Aturan Produksi

### Aturan 1-2: SQLInjection (Start Symbol)
- Aturan (1): Jika terdeteksi pola serangan, maka merupakan SQL Injection
- Aturan (2): Jika tidak ada pola (ε), maka input aman

### Aturan 3-6: SQLPattern
Mendefinisikan 4 jenis serangan SQL Injection yang dideteksi:
- **BooleanAttack**: Serangan dengan kondisi selalu true
- **UnionAttack**: Serangan dengan UNION SELECT
- **CommentAttack**: Serangan dengan komentar SQL
- **StackedQuery**: Serangan dengan query bertumpuk

### Aturan 7-8: BooleanAttack
```
Pattern: ' OR '1'='1  atau  ' AND '1'='1
```
Terdiri dari QUOTE, diikuti OR/AND, diikuti kondisi AlwaysTrue.

### Aturan 9-10: UnionAttack
```
Pattern: UNION SELECT column1, column2, ...
Pattern: UNION ALL SELECT column1, column2, ...
```
Terdiri dari UNION, opsional ALL, diikuti SELECT dan daftar kolom.

### Aturan 11: CommentAttack
```
Pattern: admin'-- atau query#
```
Payload diikuti dengan SQL comment untuk mengabaikan sisa query.

### Aturan 12: StackedQuery
```
Pattern: ; DROP TABLE users
```
Semicolon diikuti SQL keyword berbahaya dan payload tambahan.

### Aturan 13-14: AlwaysTrue
```
'1'='1'  → QUOTE NUMBER EQUALS QUOTE NUMBER
1=1      → NUMBER EQUALS NUMBER
```
Kondisi yang selalu menghasilkan TRUE.

### Aturan 15-16: ColumnList (Rekursif)
```
column1, column2, column3
```
Daftar kolom yang dipisahkan koma, bersifat rekursif.

---

## 3.3.5 Contoh Derivasi

### Contoh 1: Input `id=1' OR '1'='1`

```
Langkah derivasi:

  SQLInjection
    ⇒ SQLPattern                           [aturan 1]
    ⇒ BooleanAttack                        [aturan 3]
    ⇒ QUOTE OR AlwaysTrue                  [aturan 7]
    ⇒ QUOTE OR QUOTE NUMBER EQUALS QUOTE NUMBER    [aturan 13]
    ⇒ '     OR '     1      =      '     1         [substitusi terminal]

Hasil: ✓ ACCEPT - SQL Injection (Boolean-based) Detected!
```

### Contoh 2: Input `UNION SELECT username, password FROM users`

```
Langkah derivasi:

  SQLInjection
    ⇒ SQLPattern                           [aturan 1]
    ⇒ UnionAttack                          [aturan 4]
    ⇒ UNION SELECT ColumnList              [aturan 9]
    ⇒ UNION SELECT IDENTIFIER COMMA ColumnList     [aturan 16]
    ⇒ UNION SELECT IDENTIFIER COMMA IDENTIFIER     [aturan 15]
    ⇒ UNION SELECT username   ,     password       [substitusi terminal]

Hasil: ✓ ACCEPT - SQL Injection (Union-based) Detected!
```

### Contoh 3: Input `admin'--`

```
Langkah derivasi:

  SQLInjection
    ⇒ SQLPattern                           [aturan 1]
    ⇒ CommentAttack                        [aturan 5]
    ⇒ Payload SQL_COMMENT                  [aturan 11]
    ⇒ IDENTIFIER Payload SQL_COMMENT       [aturan 17]
    ⇒ IDENTIFIER ε SQL_COMMENT             [aturan 20]
    ⇒ admin       --                       [substitusi terminal]

Hasil: ✓ ACCEPT - SQL Injection (Comment-based) Detected!
```

### Contoh 4: Input `username=admin` (Aman)

```
Langkah derivasi:

  SQLInjection
    ⇒ ε                                    [aturan 2]

Hasil: ✓ Input aman, bukan SQL Injection
```

---

## 3.3.6 Hubungan CFG dengan Implementasi

CFG di atas diimplementasikan dalam program menggunakan teknik **Recursive Descent Parser**. 
Setiap non-terminal direpresentasikan sebagai fungsi dalam kode:

| Non-Terminal | Fungsi di parser.py |
|--------------|---------------------|
| SQLInjection | `parse()` |
| SQLPattern | `_parse_sql_injection()` |
| BooleanAttack | `_parse_boolean_attack()` |
| UnionAttack | `_parse_union_attack()` |
| CommentAttack | `_parse_comment_attack()` |
| StackedQuery | `_parse_stacked_query()` |

Contoh implementasi:

```python
def parse(self):
    # SQLInjection → SQLPattern | ε
    sql_node = self._parse_sql_injection()
    if sql_node:
        return sql_node  # SQLPattern
    return SafeNode()    # ε (input aman)

def _parse_sql_injection(self):
    # SQLPattern → BooleanAttack | UnionAttack | ...
    if self._has_pattern(['UNION']):
        return self._parse_union_attack()
    elif self._has_boolean_pattern():
        return self._parse_boolean_attack()
    elif self._has_comment():
        return self._parse_comment_attack()
    elif self._has_semicolon():
        return self._parse_stacked_query()
    return None
```
