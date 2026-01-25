# BAB 3.4 - Desain Parser dan Sketsa AST

## 3.4.1 Jenis Parser

| Item | Nilai |
|------|-------|
| Jenis Parser | Recursive Descent Parser |
| Strategi | Top-Down Parsing |
| Alasan Pemilihan | Mudah diimplementasikan dan sesuai untuk CFG sederhana |

**Recursive Descent Parser** adalah teknik parsing dimana setiap non-terminal dalam CFG diimplementasikan sebagai sebuah fungsi. Parser membaca token dari kiri ke kanan dan membangun AST secara top-down.

---

## 3.4.2 Hubungan CFG dengan Fungsi Parser

| Non-Terminal (CFG) | Fungsi di `parser.py` | Tugas |
|--------------------|----------------------|-------|
| SQLInjection | `parse()` | Entry point, memulai parsing |
| BooleanAttack | `_parse_boolean_attack()` | Deteksi pola `' OR '` |
| CommentAttack | `_parse_comment_attack()` | Deteksi pola `'--` atau `'#` |

---

## 3.4.3 Algoritma Parser

```
ALGORITMA: Recursive Descent Parser untuk SQL Injection

INPUT : Daftar token dari Lexer
OUTPUT: AST (Abstract Syntax Tree)

LANGKAH:
1. MULAI
2. Terima token dari Lexer
3. Panggil fungsi parse()
4. JIKA ada token QUOTE diikuti OR/AND:
     a. Panggil _parse_boolean_attack()
     b. Buat node SQLInjectionNode(BOOLEAN_BASED)
5. JIKA ada token QUOTE diikuti COMMENT (-- atau #):
     a. Panggil _parse_comment_attack()
     b. Buat node SQLInjectionNode(COMMENT_BASED)
6. JIKA tidak ada pola serangan:
     a. Buat node SafeNode()
7. Kembalikan AST
8. SELESAI
```

---

## 3.4.4 Flowchart Parser

```
                    ┌─────────────┐
                    │   START     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Terima Token│
                    │ dari Lexer  │
                    └──────┬──────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ Ada pola       │
              ┌───│ QUOTE + OR?    │───┐
              │   └────────────────┘   │
          [Ya]│                        │[Tidak]
              ▼                        ▼
    ┌──────────────────┐     ┌────────────────┐
    │ parse_boolean()  │     │ Ada pola       │
    │ Return:          │ ┌───│ QUOTE+COMMENT? │───┐
    │ BOOLEAN_BASED    │ │   └────────────────┘   │
    └────────┬─────────┘ │                        │
             │       [Ya]│                        │[Tidak]
             │           ▼                        ▼
             │ ┌──────────────────┐     ┌──────────────┐
             │ │ parse_comment()  │     │ Return:      │
             │ │ Return:          │     │ SafeNode     │
             │ │ COMMENT_BASED    │     │ (Input Aman) │
             │ └────────┬─────────┘     └──────┬───────┘
             │          │                      │
             └──────────┴──────────┬───────────┘
                                   │
                                   ▼
                            ┌─────────────┐
                            │ Return AST  │
                            └──────┬──────┘
                                   │
                                   ▼
                            ┌─────────────┐
                            │    END      │
                            └─────────────┘
```

---

## 3.4.5 Sketsa AST (Abstract Syntax Tree)

### A. Struktur Node AST

| Class | Deskripsi | Atribut |
|-------|-----------|---------|
| PayloadNode | Node root | is_malicious, attack_type |
| SQLInjectionNode | Node serangan | injection_type (BOOLEAN/COMMENT) |
| SafeNode | Node input aman | - |

### B. AST untuk Input `id=1' OR '1'='1` (Boolean-based)

```
              PayloadNode
          (is_malicious = true)
          (attack_type = BOOLEAN)
                  │
                  ▼
          SQLInjectionNode
        (type = BOOLEAN_BASED)
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
    QUOTE      KEYWORD   ALWAYS_TRUE
     (')        (OR)      ('1'='1')
```

### C. AST untuk Input `admin'--` (Comment-based)

```
              PayloadNode
          (is_malicious = true)
          (attack_type = COMMENT)
                  │
                  ▼
          SQLInjectionNode
        (type = COMMENT_BASED)
                  │
          ┌───────┴───────┐
          ▼               ▼
       QUOTE          COMMENT
        (')             (--)
```

### D. AST untuk Input `username=admin` (Aman)

```
              PayloadNode
          (is_malicious = false)
                  │
                  ▼
              SafeNode
        (Input tidak berbahaya)
```

---

## 3.4.6 Implementasi Kode Parser

```python
class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
    
    def parse(self):
        """Entry point - SQLInjection → BooleanAttack | CommentAttack | ε"""
        root = PayloadNode()
        
        # Cek Boolean-based
        if self._is_boolean_attack():
            node = self._parse_boolean_attack()
            root.add_child(node)
            root.is_malicious = True
            root.attack_type = "BOOLEAN_BASED"
        
        # Cek Comment-based
        elif self._is_comment_attack():
            node = self._parse_comment_attack()
            root.add_child(node)
            root.is_malicious = True
            root.attack_type = "COMMENT_BASED"
        
        # Input aman
        else:
            root.add_child(SafeNode())
            root.is_malicious = False
        
        return root
    
    def _is_boolean_attack(self):
        """Cek apakah ada pola QUOTE + OR"""
        has_quote = any(t.type == TokenType.SQL_QUOTE for t in self.tokens)
        has_or = any(t.type == TokenType.SQL_KEYWORD and t.value == 'OR' for t in self.tokens)
        return has_quote and has_or
    
    def _is_comment_attack(self):
        """Cek apakah ada pola QUOTE + COMMENT"""
        return any(t.type == TokenType.SQL_COMMENT for t in self.tokens)
```

---

## 3.4.7 Contoh Proses Parsing

### Input: `admin'--`

| Langkah | Proses | Hasil |
|---------|--------|-------|
| 1 | Terima token: [IDENTIFIER, QUOTE, COMMENT] | - |
| 2 | Panggil `parse()` | - |
| 3 | Cek `_is_boolean_attack()` | False |
| 4 | Cek `_is_comment_attack()` | True |
| 5 | Panggil `_parse_comment_attack()` | SQLInjectionNode |
| 6 | Set `is_malicious = True` | - |
| 7 | Return AST | ✅ Comment-based detected |
