# BAB 3.5 - Desain IR/DSL dan Alur Eksekusi

## 3.5.1 Pengertian IR (Intermediate Representation)

| Item | Penjelasan |
|------|------------|
| Definisi | Representasi antara antara AST dan aksi akhir |
| Tujuan | Mempermudah eksekusi, debugging, dan logging |
| Bentuk | Kumpulan instruksi sederhana (opcode + argumen) |

---

## 3.5.2 Daftar Opcode IR

| No | Opcode | Fungsi | Argumen | Contoh |
|----|--------|--------|---------|--------|
| 1 | LOAD | Load payload ke memory | payload | `LOAD "admin'--"` |
| 2 | CHECK | Cek pattern serangan | tipe serangan | `CHECK BOOLEAN_BASED` |
| 3 | BLOCK | Blokir request berbahaya | tipe | `BLOCK COMMENT_BASED` |
| 4 | ALLOW | Izinkan request aman | - | `ALLOW` |
| 5 | LOG | Catat event ke log | status, tipe | `LOG DETECTED BOOLEAN` |
| 6 | HALT | Akhiri eksekusi | - | `HALT` |

---

## 3.5.3 Contoh IR Program

### Input Berbahaya: `admin'--`

```
IR Program:
  0: LOAD "admin'--"
  1: CHECK COMMENT_BASED
  2: BLOCK COMMENT_BASED
  3: LOG "DETECTED" "COMMENT_BASED"
  4: HALT

Hasil: 🚨 BLOCK
```

### Input Berbahaya: `' OR '1'='1`

```
IR Program:
  0: LOAD "' OR '1'='1"
  1: CHECK BOOLEAN_BASED
  2: BLOCK BOOLEAN_BASED
  3: LOG "DETECTED" "BOOLEAN_BASED"
  4: HALT

Hasil: 🚨 BLOCK
```

### Input Aman: `username=admin`

```
IR Program:
  0: LOAD "username=admin"
  1: ALLOW
  2: HALT

Hasil: ✅ ALLOW
```

---

## 3.5.4 Pengertian DSL (Domain Specific Language)

| Item | Penjelasan |
|------|------------|
| Definisi | Bahasa khusus untuk mendefinisikan pola serangan |
| Tujuan | Memudahkan penambahan signature baru tanpa ubah kode |
| Bentuk | File konfigurasi dengan format tertentu |

---

## 3.5.5 Format Signature DSL

| Field | Tipe | Deskripsi |
|-------|------|-----------|
| name | string | Nama signature |
| pattern | regex | Pola yang dicari |
| severity | enum | HIGH / MEDIUM / LOW |
| action | enum | BLOCK / ALERT |
| message | string | Pesan deteksi |

### Contoh Signature untuk 2 Pola:

```
SIGNATURE boolean_sqli_1
  PATTERN: '\s*(OR|AND)\s*'
  SEVERITY: HIGH
  ACTION: BLOCK
  MESSAGE: "SQL Injection (Boolean-based) terdeteksi"

SIGNATURE comment_sqli_1
  PATTERN: '--
  SEVERITY: HIGH
  ACTION: BLOCK
  MESSAGE: "SQL Injection (Comment --) terdeteksi"

SIGNATURE comment_sqli_2
  PATTERN: '#
  SEVERITY: HIGH
  ACTION: BLOCK
  MESSAGE: "SQL Injection (Comment #) terdeteksi"
```

---

## 3.5.6 Alur Eksekusi

```
┌─────────────┐
│    AST      │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│IR Generator │ → Ubah AST menjadi IR Program
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ IR Program  │ → [LOAD, CHECK, BLOCK/ALLOW, LOG, HALT]
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Interpreter │ → Jalankan instruksi satu per satu
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Response   │ → BLOCK (berbahaya) / ALLOW (aman)
└─────────────┘
```

---

## 3.5.7 Contoh Alur Lengkap

### Input: `admin'--`

| Langkah | Komponen | Proses | Hasil |
|---------|----------|--------|-------|
| 1 | Lexer | Tokenisasi | [IDENTIFIER, QUOTE, COMMENT] |
| 2 | Parser | Build AST | SQLInjectionNode(COMMENT) |
| 3 | IR Generator | Generate IR | [LOAD, CHECK, BLOCK, LOG, HALT] |
| 4 | Interpreter | Execute | Action = BLOCK |
| 5 | Response | Output | 🚨 SQL Injection Detected! |

---

## 3.5.8 Implementasi Kode

### IR Generator

```python
class IRGenerator:
    def generate(self, ast):
        program = IRProgram()
        program.emit(Opcode.LOAD, "payload")
        
        if ast.is_malicious:
            program.emit(Opcode.CHECK, ast.attack_type)
            program.emit(Opcode.BLOCK, ast.attack_type)
            program.emit(Opcode.LOG, "DETECTED", ast.attack_type)
        else:
            program.emit(Opcode.ALLOW)
        
        program.emit(Opcode.HALT)
        return program
```

### IR Interpreter

```python
class IRInterpreter:
    def execute(self, program):
        for inst in program.instructions:
            if inst.opcode == Opcode.BLOCK:
                return {'action': 'BLOCK'}
            elif inst.opcode == Opcode.ALLOW:
                return {'action': 'ALLOW'}
            elif inst.opcode == Opcode.HALT:
                break
```
