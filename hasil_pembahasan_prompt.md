## Konteks Paper

Kamu diminta menulis bagian **Hasil dan Pembahasan** (`\section{Hasil dan Pembahasan}`) untuk paper akademik berjudul:

> **"Analisis Keamanan Jaringan pada Infrastruktur AWS Berbasis Terraform Menggunakan SMT Solver Z3"**

Paper ditulis dalam **Bahasa Indonesia**, format LaTeX dengan class `IAENGtran` (mirip IEEEtran). Gaya penulisan: formal, teknis, akademik. Setiap klaim didukung kutipan `\cite{}`.

---

## Infrastruktur yang Diverifikasi

Konfigurasi Terraform yang digunakan terdiri dari:

| Resource | Detail |
|---|---|
| VPC | `10.0.0.0/16` |
| Public Subnet sub1 | `10.0.0.0/24`, us-east-1a |
| Public Subnet sub2 | `10.0.1.0/24`, us-east-1b |
| Private Subnet sub3 | `10.0.2.0/24`, us-east-1a (via NAT GW) |
| Private Subnet sub4 | `10.0.3.0/24`, us-east-1b (via NAT GW) |
| Public Route Table | `0.0.0.0/0 → igw-*` |
| Private Route Table | `0.0.0.0/0 → nat-*` (bukan IGW) |
| webSg | Ingress: port 22 & 80 dari `0.0.0.0/0`; Egress: semua |
| albSg | Ingress: port 80 & 443 dari `0.0.0.0/0`; Egress: semua |
| bastionSg | Ingress: port 22 dari `203.0.113.0/24` saja |
| dbSg | Ingress: port 3306 dari `10.0.0.0/16` saja; Egress: port 443 |
| EC2 webserver1 | Public sub1, pakai webSg |
| EC2 webserver2 | Public sub2, pakai webSg |
| EC2 bastion | Public sub1, pakai bastionSg |
| EC2 appserver | Private sub3, pakai webSg |
| EC2 dbserver | Private sub4, pakai dbSg |
| ALB myalb | Across sub1 & sub2, pakai webSg |
| S3 example | `abhisheksterraform2023project` |
| S3 logs | `my-access-logs-bucket-demo` |
| S3 backup | `my-backup-bucket-demo` |

---

## Output Aktual Tool (Hasil Verifikasi Z3)

Program dijalankan dengan perintah `python main.py` terhadap `tests/sample_plan.json`.

### Resources Parsed
```
Resources parsed: 4 subnets, 4 security groups, 2 route tables,
                  5 EC2 instances, 1 ALBs, 3 S3 Buckets
```

### Hasil Lengkap
```
=================================================================
  AWS Infrastructure Security Verifier (Z3 SMT)
=================================================================

  SECURITY VERIFICATION RESULTS
  ---------------------------------------------------------------
  [SCENARIO 1] Internet->EC2 SSH          : SAT   VULNERABLE
    counterexample: [ec2_ip_ssh=167772928]   -> 10.0.3.0

  [SCENARIO 1] Internet->EC2 HTTP         : SAT   VULNERABLE
    counterexample: [ec2_ip_http=167772672]  -> 10.0.2.0

  [SCENARIO 2] Bypass ALB                 : SAT   VULNERABLE
    counterexample: [bypass_ec2_ip=167772160,     -> 10.0.0.0
                     bypass_internet_ip=4127129600 -> 245.255.0.0]

  [SCENARIO 3] Subnet Isolation           : UNSAT SAFE

  [SCENARIO 4] Unrestricted Egress        : SAT   VULNERABLE
    counterexample: [egress_src_ip=167772160]  -> 10.0.0.0

  [SCENARIO 5] After Fix - SSH            : UNSAT SAFE
  [SCENARIO 5] After Fix - Egress         : UNSAT SAFE
  ---------------------------------------------------------------

  Summary: 4 VULNERABLE  |  3 SAFE
```

---

## Penjelasan Tiap Skenario (untuk pembahasan)

### Skenario 1 — SSH & HTTP Reachability (SAT = VULNERABLE)

**Cara kerja Z3:**
- Variabel: `internet_ip` (BitVec 32), `ec2_ip` (BitVec 32)
- Constraint 1: `ec2_ip ∈ salah satu subnet`
- Constraint 2: `internet_ip ∈ CIDR yang diizinkan SG untuk port target`
- Constraint 3: `port = target_port`

**Temuan:**
- `webSg` membuka port 22 dan 80 ke `0.0.0.0/0`, sehingga constraint 2 menjadi trivially true
- Z3 menemukan counterexample:
  - SSH: `ec2_ip = 10.0.3.0` (sub4 — private subnet dbserver)
  - HTTP: `ec2_ip = 10.0.2.0` (sub3 — private subnet appserver)
- Catatan penting: model Skenario 1 memeriksa apakah *ada* SG yang membuka port tersebut dan *ada* subnet yang memuat IP tersebut, tanpa memaksa korelasi spesifik antara SG–EC2–Subnet per-instance. Ini adalah simplifikasi model yang disengaja untuk membuktikan potensi kerentanan secara konservatif (menangkap semua SG yang bermasalah).
- Root cause: `webSg` dipakai bersama oleh webserver1, webserver2, dan appserver — padahal appserver di private subnet seharusnya punya SG sendiri yang lebih ketat.

### Skenario 2 — Bypass ALB (SAT = VULNERABLE)

**Cara kerja Z3:**
- Variabel: `bypass_internet_ip` (BitVec 32), `bypass_ec2_ip` (BitVec 32)
- Constraint 1: `ec2_ip ∈ VPC CIDR (10.0.0.0/16)`
- Constraint 2: `internet_ip ∉ VPC CIDR` (ini adalah host internet sungguhan)
- Constraint 3: SG EC2 mengizinkan port 80 dari CIDR tertentu

**Temuan:**
- `webSg` mengizinkan port 80 dari `0.0.0.0/0` — artinya constraint 2 dan 3 kompatibel
- Z3 menemukan: `bypass_internet_ip = 245.255.0.0` (IP publik) bisa mencapai `bypass_ec2_ip = 10.0.0.0` langsung
- Ini membuktikan ALB **bukan** satu-satunya pintu masuk: EC2 bisa diakses langsung dari internet
- Root cause: ALB dan EC2 memakai SG yang sama (`webSg`). Seharusnya EC2 punya SG terpisah yang hanya mengizinkan ingress dari SG ALB, bukan dari `0.0.0.0/0`.

### Skenario 3 — Subnet Isolation (UNSAT = SAFE)

**Cara kerja Z3:**
- Variabel: `x` (BitVec 32)
- Constraint 1: `x ∈ 10.0.0.0/24` → `(x & 0xFFFFFF00) = 0x0A000000`
- Constraint 2: `x ∈ 10.0.1.0/24` → `(x & 0xFFFFFF00) = 0x0A000100`

**Temuan:**
- `0x0A000000 ≠ 0x0A000100`, kedua constraint kontradiktif → UNSAT
- Tidak ada IP yang bisa berada di dua subnet berbeda secara serentak
- Empat subnet (`10.0.0.0/24`, `10.0.1.0/24`, `10.0.2.0/24`, `10.0.3.0/24`) semuanya non-overlapping
- Ini membuktikan isolasi antar-subnet terjaga secara matematis

### Skenario 4 — Unrestricted Egress (SAT = VULNERABLE)

**Cara kerja Z3:**
- Variabel: `egress_src_ip` (BitVec 32), `egress_port` (BitVec 16)
- Constraint 1: `egress_src_ip ∈ subnet`
- Constraint 2: egress SG mengizinkan semua traffic (protocol `-1`, `0.0.0.0/0`)
- Constraint 3: route table punya default route ke IGW

**Temuan:**
- `webSg` memiliki egress rule: all traffic (`-1`) ke `0.0.0.0/0` → constraint 2 trivially true
- Z3 menemukan: EC2 dengan `egress_src_ip = 10.0.0.0` bisa mengirim traffic ke internet tanpa pembatasan port
- Ini membentuk saluran eksfiltrasi data: jika EC2 dikompromis, attacker bisa mengirim data ke mana saja
- Root cause: egress rule terlalu permisif, seharusnya dibatasi hanya ke port yang diperlukan (misal: hanya TCP/443)

### Skenario 5 — Post-Fix Verification (UNSAT = SAFE)

**Konfigurasi setelah perbaikan (hardcoded dalam `FIXED_EC2_SG`):**
```
Ingress SSH: from 10.0.0.0/16 only (bukan 0.0.0.0/0)
Egress:      TCP/443 only (bukan all-traffic)
```

**Cara kerja Z3 — SSH fix:**
- Constraint 1: `internet_ip ∉ VPC CIDR` (ini IP publik)
- Constraint 2: SG mewajibkan `internet_ip ∈ VPC CIDR` (aturan baru)
- → Kontradiksi → UNSAT → SSH dari internet terbukti diblokir

**Cara kerja Z3 — Egress fix:**
- Constraint 1: `egress_port ∈ [443, 443]` (hanya port 443 diizinkan)
- Constraint 2: `egress_port ≠ 443` (kita coba cari port lain)
- → Kontradiksi → UNSAT → eksfiltrasi port sembarang terbukti tidak mungkin

---

## Tabel Ringkasan Hasil

| Skenario | Pemeriksaan | Hasil | Interpretasi |
|---|---|---|---|
| 1 | Internet → EC2 SSH (port 22) | **SAT** | VULNERABLE: webSg buka port 22 ke 0.0.0.0/0 |
| 1 | Internet → EC2 HTTP (port 80) | **SAT** | VULNERABLE: webSg buka port 80 ke 0.0.0.0/0 |
| 2 | EC2 dapat dicapai langsung tanpa ALB | **SAT** | VULNERABLE: ALB bukan satu-satunya entry point |
| 3 | Overlap subnet sub1/sub2 | **UNSAT** | SAFE: subnet non-overlapping terbukti matematis |
| 4 | Egress tak terbatas / eksfiltrasi | **SAT** | VULNERABLE: semua port & protokol bisa keluar |
| 5 | Setelah fix — SSH | **UNSAT** | SAFE: SSH sekarang hanya dari VPC CIDR |
| 5 | Setelah fix — Egress | **UNSAT** | SAFE: egress dibatasi hanya TCP/443 |

**Summary: 4 VULNERABLE \| 3 SAFE**

---

## Referensi yang Tersedia di Paper

Gunakan `\cite{}` untuk referensi ini (sudah ada di bibliography):
- `\cite{de2008z3}` — Z3 SMT Solver (de Moura & Bjørner, 2008)
- `\cite{rahman2019seven}` — Seven security smells in IaC
- `\cite{rahman2020gang}` — Gang of eight IaC security study
- `\cite{backes2018semantic}` — ZELKOVA (AWS IAM policy verification dengan SMT)
- `\cite{chiari2022static}` — Static analysis untuk IaC
- `\cite{guerriero2019adoption}` — Adoption of IaC in industry
- `\cite{verdet2023exploring}` — Security di Terraform open-source projects
- `\cite{Lepiller2021}` — Update sniping vulnerability in IaC
- `\cite{sissodiya2025formal}` — Formal verification untuk Kubernetes
- `\cite{de2020formal}` — DOML-MC model checker untuk IaC
- `\cite{hu2023characterizing}` — Characterizing IaC security alerts
- `\cite{inbook}` — Bit-vector theory

---

## Instruksi Penulisan

Tulis bagian `\section{Hasil dan Pembahasan}` dalam **LaTeX** dengan format `IAENGtran` (mirip IEEEtran), **Bahasa Indonesia**, gaya akademik formal.

**Struktur yang harus ditulis:**

```
\section{Hasil dan Pembahasan}

\subsection{Hasil Ekstraksi dan Parsing Arsitektur}
- Update teks yang sudah ada di paper:
  Sekarang bukan "2 subnet, 1 SG, 1 RT, 1 EC2" tapi:
  "4 subnet (2 publik + 2 privat), 4 Security Group, 2 Route Table,
   5 EC2 instance, 1 ALB, 3 S3 bucket"
- Jelaskan infrastruktur yang diperluas (publik+privat, NAT GW, dsb.)

\subsection{Hasil Skenario 1: Keterjangkauan Internet ke EC2}
- Hasil: SAT VULNERABLE untuk SSH dan HTTP
- Jelaskan counterexample Z3 (IP konkret, konversi ke dotted decimal)
- Analisis root cause: webSg pakai 0.0.0.0/0
- Cantumkan constraint Z3 yang digunakan

\subsection{Hasil Skenario 2: Bypass Application Load Balancer}
- Hasil: SAT VULNERABLE
- Jelaskan counterexample (bypass_internet_ip=245.255.0.0, bypass_ec2_ip=10.0.0.0)
- Analisis: webSg dipakai bersama ALB dan EC2 → ALB bukan sole entry point
- Constraint yang membuktikan: internet_ip ∉ VPC ∧ internet_ip ∈ 0.0.0.0/0

\subsection{Hasil Skenario 3: Isolasi Antar-Subnet}
- Hasil: UNSAT SAFE
- Jelaskan mengapa: 4 subnet non-overlapping
- Tunjukkan constraint Z3: (x & mask1) = net1 ∧ (x & mask2) = net2 → kontradiksi
- Implikasi: tidak ada tumpang tindih CIDR

\subsection{Hasil Skenario 4: Egress Tak Terbatas}
- Hasil: SAT VULNERABLE
- Jelaskan counterexample (egress_src_ip=10.0.0.0)
- Analisis: protocol "-1" + 0.0.0.0/0 + IGW = saluran eksfiltrasi terbuka

\subsection{Hasil Skenario 5: Verifikasi Setelah Perbaikan}
- Hasil: UNSAT SAFE untuk keduanya
- Jelaskan fix yang diterapkan (SSH restricted ke VPC CIDR, egress ke TCP/443 only)
- Tunjukkan kontradiksi logika yang menyebabkan UNSAT
- Konfirmasi bahwa fix benar-benar menutup celah yang ditemukan skenario 1 & 4

\subsection{Pembahasan}
- Rangkuman keseluruhan: 4 VULNERABLE, 3 SAFE
- Bandingkan pendekatan formal verification vs rule-based linting:
  * Rule-based (Checkov, tfsec) hanya deteksi per-resource, tidak bisa
    buktikan bahwa kombinasi SG+Subnet+RouteTable membentuk celah secara holistis
  * Z3 menghasilkan counterexample konkret (IP address yang membuktikan celah)
  * UNSAT memberikan jaminan matematis yang tidak bisa diberikan oleh linting
- Diskusikan temuan utama:
  * Berbagi SG antara ALB dan EC2 adalah miskonfigurasi umum (skenario 2)
  * Egress tak terbatas sering diabaikan tapi kritis untuk data exfiltration (skenario 4)
  * Skenario 5 membuktikan tool dapat digunakan untuk validasi fix
- Keterbatasan pendekatan:
  * Model Skenario 1 tidak menerapkan korelasi per-instance (SG–EC2–Subnet),
    sehingga mengidentifikasi seluruh SG bermasalah secara konservatif
  * Tidak menangani kebijakan IAM atau enkripsi data (di luar scope jaringan)
  * sample_plan.json adalah mock, bukan output `terraform show -json` asli
```

**Gaya penulisan:**
- Setiap formula/constraint Z3 ditulis dalam LaTeX math mode
- Setiap counterexample dikonversi ke IP dotted-decimal (misal: `167772160 = 10.0.0.0`)
- Gunakan `\texttt{}` untuk nama resource, variabel, dan port
- Gunakan tabel LaTeX untuk ringkasan hasil (seperti yang sudah ada di metodologi)
- Panjang total bagian ini sekitar 600–900 kata
- Tidak perlu tulis ulang bagian lain (Pendahuluan, Metodologi, Kesimpulan)
- Mulai langsung dari `\subsection{Hasil Ekstraksi dan Parsing Arsitektur}`

---

## Catatan Teknis Tambahan

**Konversi IP counterexample:**
- `167772160` = `0x0A000000` = `10.0.0.0` (network address sub1, 10.0.0.0/24)
- `167772928` = `0x0A000300` = `10.0.3.0` (network address sub4, 10.0.3.0/24)
- `167772672` = `0x0A000200` = `10.0.2.0` (network address sub3, 10.0.2.0/24)
- `4127129600` = `0xF5FF0000` = `245.255.0.0` (IP publik di luar VPC)

**Kenapa Z3 memilih IP tersebut:**
Z3 mencari nilai BitVec 32-bit *terkecil* (atau paling mudah ditemukan) yang memenuhi semua constraint. Untuk `ec2_ip`, Z3 memilih network address dari subnet yang memenuhi `Or(ip ∈ sub1, ip ∈ sub2, ip ∈ sub3, ip ∈ sub4)`. Untuk `internet_ip`, Z3 memilih sembarang IP di luar `10.0.0.0/16`.

**Pemodelan Bit-Vector:**
```
ip_in_subnet(ip, network, mask) ≡ (ip AND mask) == network
Contoh: (ip AND 0xFFFFFF00) == 0x0A000000  ← ip ∈ 10.0.0.0/24
```

**Kenapa Skenario 2 khususnya penting:**
Skenario 2 mendemonstrasikan kemampuan unik formal verification: ia membuktikan bahwa property "ALB adalah sole entry point" TIDAK terpenuhi dalam konfigurasi ini, padahal tidak ada satu aturan tunggal pun yang secara eksplisit membolehkan bypass ALB — kerentanan ini muncul dari kombinasi dua resource (webSg yang terlalu permisif + fakta bahwa EC2 menggunakan SG yang sama dengan ALB).
