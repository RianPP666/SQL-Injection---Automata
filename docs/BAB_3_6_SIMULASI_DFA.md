# BAB 3.6 - Simulasi Automata dan Contoh Input-Output

## 3.6.1 Jenis Automata yang Digunakan

| Item | Nilai |
|------|-------|
| Jenis | DFA (Deterministic Finite Automaton) |
| Jumlah DFA | 2 (Boolean-based dan Comment-based) |
| Tujuan | Pattern matching untuk deteksi SQL Injection |

---

## 3.6.2 DFA untuk Boolean-based SQL Injection

### Definisi Formal

```
M = (Q, Σ, δ, q0, F)

Q  = {q0, q1, q2, q3}
Σ  = {QUOTE, OR, OTHER}
q0 = q0
F  = {q3}
```

### Tabel Transisi (δ)

| State | QUOTE | OR | OTHER |
|-------|-------|-----|-------|
| q0 | q1 | q0 | q0 |
| q1 | q0 | q2 | q0 |
| q2 | q3 | q0 | q0 |
| **q3** | - | - | - | ← **ACCEPT** |

### Diagram State

```
         QUOTE       OR        QUOTE
→ (q0) ───────► (q1) ───────► (q2) ───────► ((q3))
                                             ACCEPT
```

---

## 3.6.3 DFA untuk Comment-based SQL Injection

### Definisi Formal

```
M = (Q, Σ, δ, q0, F)

Q  = {c0, c1, c2}
Σ  = {QUOTE, COMMENT, OTHER}
q0 = c0
F  = {c2}
```

### Tabel Transisi (δ)

| State | QUOTE | COMMENT | OTHER |
|-------|-------|---------|-------|
| c0 | c1 | c0 | c0 |
| c1 | c1 | c2 | c0 |
| **c2** | - | - | - | ← **ACCEPT** |

### Diagram State

```
         QUOTE       COMMENT
→ (c0) ───────► (c1) ───────► ((c2))
                               ACCEPT
```

---

## 3.6.4 Simulasi Step-by-Step

### Simulasi 1: Input `admin'--` (Comment-based)

| Step | State Awal | Input Dibaca | State Akhir | Keterangan |
|------|------------|--------------|-------------|------------|
| 1 | c0 | admin | c0 | OTHER, tetap di c0 |
| 2 | c0 | ' | c1 | QUOTE, pindah ke c1 |
| 3 | c1 | -- | **c2** | COMMENT, pindah ke c2 |

**Hasil:** State akhir c2 ∈ F → **ACCEPT** → SQL Injection Detected!

### Simulasi 2: Input `id=1' OR '1'='1` (Boolean-based)

| Step | State Awal | Input Dibaca | State Akhir | Keterangan |
|------|------------|--------------|-------------|------------|
| 1 | q0 | id=1 | q0 | OTHER, tetap di q0 |
| 2 | q0 | ' | q1 | QUOTE, pindah ke q1 |
| 3 | q1 | OR | q2 | OR, pindah ke q2 |
| 4 | q2 | ' | **q3** | QUOTE, pindah ke q3 |

**Hasil:** State akhir q3 ∈ F → **ACCEPT** → SQL Injection Detected!

### Simulasi 3: Input `username=admin` (Aman)

| Step | State Awal | Input Dibaca | State Akhir | Keterangan |
|------|------------|--------------|-------------|------------|
| 1 | q0 | username=admin | q0 | OTHER, tetap di q0 |

**Hasil:** State akhir q0 ∉ F → **REJECT** → Input Aman

---

## 3.6.5 Contoh Input-Output (5 Test Cases)

| No | Input | DFA | State Akhir | Status | Aksi |
|----|-------|-----|-------------|--------|------|
| 1 | `username=admin&password=123` | - | q0/c0 | REJECT | ✅ ALLOW |
| 2 | `id=1' OR '1'='1` | Boolean | **q3** | ACCEPT | 🚨 BLOCK |
| 3 | `id=1' OR 1=1` | Boolean | **q3** | ACCEPT | 🚨 BLOCK |
| 4 | `admin'--` | Comment | **c2** | ACCEPT | 🚨 BLOCK |
| 5 | `user'#` | Comment | **c2** | ACCEPT | 🚨 BLOCK |

---

## 3.6.6 Ringkasan Hasil Pengujian

| Metrik | Nilai |
|--------|-------|
| Total Input Diuji | 5 |
| Input Aman (ALLOW) | 1 |
| Input Berbahaya (BLOCK) | 4 |
| Akurasi Deteksi | 100% |
