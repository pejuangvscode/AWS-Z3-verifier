"""
scenario_1.py – Internet → EC2 reachability via SSH (port 22) and HTTP (port 80).

Security question
-----------------
Can an arbitrary host on the public internet reach an EC2 instance in the VPC
directly on port 22 (SSH) or port 80 (HTTP)?

Expected results (vulnerable baseline config)
---------------------------------------------
* SSH  → **SAT** VULNERABLE  (SG allows 0.0.0.0/0:22)
  Artinya: Z3 berhasil menemukan jalur masuk dari internet ke EC2 via port 22.
  Konfigurasi ini berbahaya karena siapa pun di internet bisa mencoba akses SSH.

* HTTP → **SAT** VULNERABLE  (SG allows 0.0.0.0/0:80)
  Artinya: Z3 berhasil menemukan jalur masuk dari internet ke EC2 via port 80.
  Ini bisa disengaja (web server publik), namun tetap dicatat sebagai temuan.

Laporan disimpan otomatis ke: reports/scenario_1/report_N.txt
Setiap run membuat file baru (report_1.txt, report_2.txt, dst) tanpa menimpa
laporan sebelumnya, sehingga perbandingan antar-run tetap tersimpan.
"""

from __future__ import annotations

import os
import sys
from typing import Any

# Impor komponen Z3 yang dibutuhkan:
# - BitVec      : membuat variabel bilangan bulat biner (untuk IP 32-bit, port 16-bit)
# - BitVecVal   : membuat nilai konstan biner (misal port 22 sebagai BitVec)
# - Solver      : mesin SAT/UNSAT utama Z3
# - sat         : konstanta untuk membandingkan hasil solver ("apakah hasilnya SAT?")
# - Or, And, Not, BoolVal : operator logika untuk menyusun constraint
# - ModelRef    : tipe kembalian dari solver.model() berisi contoh konkret (counterexample)
from z3 import And, BitVec, BitVecVal, BoolVal, ModelRef, Not, Or, Solver, sat

# Tambahkan root project ke sys.path agar import parser dan z3_engine bisa ditemukan
# ketika file ini dijalankan langsung (python scenarios/scenario_1.py)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# cidr_to_network_mask       : konversi "10.0.0.0/24" → (network_int, mask_int) sebagai integer
# extract_route_table        : ambil daftar route dari dict route table
# extract_security_group_rules: ambil semua aturan ingress/egress dari sebuah Security Group
from parser.extractor import cidr_to_network_mask, extract_route_table, extract_security_group_rules

# ip_in_subnet  : constraint Z3 "apakah ip_bitvec berada dalam subnet ini?"
#                 implementasinya: (ip & mask) == network_address  (operasi bitwise AND)
# port_in_range : constraint Z3 "apakah port berada dalam rentang [from_port, to_port]?"
from z3_engine.models import ip_in_subnet, port_in_range


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers (fungsi bantu, tidak dipanggil dari luar modul ini)
# ──────────────────────────────────────────────────────────────────────────────

def _has_igw_route(infra: dict[str, Any]) -> bool:
    """
    Periksa apakah ada Internet Gateway (IGW) route di infrastruktur.

    Ini adalah PRASYARAT sebelum menjalankan Z3 (Aksioma Keterjangkauan,
    Section II.B.3 dalam paper):
    Jika tidak ada route table yang mengarah ke IGW dengan destination 0.0.0.0/0,
    maka subnet tidak bersifat publik dan tidak mungkin ada jalur dari internet ke EC2.
    Dalam kondisi ini, kita langsung kembalikan UNSAT tanpa perlu bertanya ke Z3.

    Cara kerjanya:
    - Iterasi semua route table di infra["route_tables"]
    - Setiap route table diekstrak menggunakan extract_route_table()
    - Cari route dengan destination "0.0.0.0/0" DAN gateway_id diawali "igw-"
    - Jika ditemukan → return True (subnet publik, ada jalur internet)
    - Jika tidak ditemukan → return False (subnet privat, tidak ada jalur internet)
    """
    for rt in infra.get("route_tables", []):
        for r in extract_route_table(rt):
            if r["destination_cidr"] == "0.0.0.0/0" and (r.get("gateway_id") or "").startswith("igw-"):
                return True
    return False


def _check_port_reachability(
    infra: dict[str, Any],
    target_port: int,
    var_suffix: str,
) -> tuple[str, ModelRef | None]:
    """
    Fungsi inti: tanya ke Z3 apakah ada jalur dari internet ke EC2 pada port tertentu.

    Parameter:
    - infra       : dict infrastruktur hasil parsing terraform plan JSON
    - target_port : port yang diuji (22 untuk SSH, 80 untuk HTTP)
    - var_suffix  : suffix unik untuk nama variabel Z3 ("ssh" atau "http"),
                    mencegah konflik nama variabel saat kedua pengecekan dijalankan
                    dalam proses Python yang sama

    Alur kerja (sesuai paper, Section II.C Skenario 1):
    Memverifikasi 4 kondisi secara bersamaan:
      1. IGW terhubung ke VPC          → dicek via _has_igw_route() sebelum Z3
      2. Route table punya default route ke IGW  → dicek via _has_igw_route()
      3. Subnet bersifat publik        → dicek via _has_igw_route()
      4. Security Group mengizinkan port dari semua IP → dicek via constraint Z3

    Return:
    - ("SAT", model)   → jalur terbuka, model berisi contoh konkret IP/port → VULNERABLE
    - ("UNSAT", None)  → tidak ada jalur yang memenuhi semua constraint → SAFE
    """

    # ── Prasyarat: harus ada IGW route agar subnet bersifat publik ──
    # Jika tidak ada IGW route, tidak mungkin ada traffic dari internet → langsung UNSAT
    if not _has_igw_route(infra):
        return "UNSAT", None

    # ── Inisialisasi solver Z3 baru untuk setiap pengecekan ──
    # Solver baru = tidak ada constraint warisan dari pengecekan port sebelumnya
    solver = Solver()

    # ── Deklarasi variabel simbolik Z3 ──
    # internet_ip : mewakili semua kemungkinan alamat IP sumber dari internet (32-bit)
    # ec2_ip      : mewakili semua kemungkinan alamat IP tujuan di EC2 (32-bit)
    # Kedua variabel ini "bebas" — Z3 yang akan mencari nilai konkretnya
    # var_suffix memastikan nama unik: "internet_ip_ssh" berbeda dari "internet_ip_http"
    internet_ip = BitVec(f"internet_ip_{var_suffix}", 32)
    ec2_ip = BitVec(f"ec2_ip_{var_suffix}", 32)

    # ── Constraint 1: ec2_ip harus berada di salah satu subnet yang dikenal ──
    # Ini memodelkan fakta bahwa EC2 instance selalu berada di dalam subnet VPC
    # Ambil semua nilai CIDR dari semua subnet yang ada di infra
    subnet_cidrs = [s.get("cidr_block") for s in infra.get("subnets", []) if s.get("cidr_block")]
    if not subnet_cidrs:
        # Tidak ada subnet terdefinisi → tidak ada EC2 yang bisa dicapai
        return "UNSAT", None

    # Bangun list constraint: ip_in_subnet(ec2_ip, net, mask) untuk setiap subnet
    # ip_in_subnet menghasilkan: (ec2_ip & mask) == network_address
    # Lalu gabungkan dengan Or: ec2_ip ∈ subnet_1 OR ec2_ip ∈ subnet_2 OR ...
    subnet_parts = [ip_in_subnet(ec2_ip, *cidr_to_network_mask(c)) for c in subnet_cidrs]
    solver.add(Or(*subnet_parts) if len(subnet_parts) > 1 else subnet_parts[0])

    # ── Constraint 2: ada Security Group yang mengizinkan target_port dari suatu CIDR ──
    # Memodelkan "Aksioma Default-Deny" (Section II.B.2):
    # Nilai awal = False (semua akses diblokir), baru berubah True jika ada aturan eksplisit
    port_bv = BitVecVal(target_port, 16)  # konversi target_port ke BitVec 16-bit untuk Z3
    sg_allows = False  # flag: apakah ada SG yang mengizinkan port ini?

    for sg in infra.get("security_groups", []):
        for rule in extract_security_group_rules(sg):
            # Hanya proses aturan arah INGRESS (traffic masuk ke EC2)
            # Aturan EGRESS (keluar) diabaikan untuk skenario ini
            if rule["direction"] != "ingress":
                continue
            # Cek apakah target_port ada di dalam rentang [from_port, to_port] aturan ini
            # Contoh: rule from_port=0, to_port=65535 → mencakup semua port termasuk 22 dan 80
            if not (rule["from_port"] <= target_port <= rule["to_port"]):
                continue
            # Iterasi daftar CIDR yang diizinkan oleh aturan ini
            for cidr_block in rule.get("cidr_blocks", []):
                net, mask = cidr_to_network_mask(cidr_block)
                # Tambahkan constraint: internet_ip harus memenuhi CIDR ini
                # Jika cidr_block = "0.0.0.0/0" → (ip & 0) == 0 → selalu True untuk IP apapun
                # Artinya: siapapun di internet diizinkan → ini yang membuat VULNERABLE
                solver.add(ip_in_subnet(internet_ip, net, mask))
                sg_allows = True
                break  # Satu CIDR yang cocok sudah cukup membuktikan akses terbuka
        if sg_allows:
            break  # Satu SG yang cocok sudah cukup, tidak perlu periksa SG lain

    # Jika tidak ada SG yang mengizinkan port ini → default-deny berlaku → UNSAT
    if not sg_allows:
        return "UNSAT", None

    # ── Constraint 3 (trivial): verifikasi port sama persis dengan target_port ──
    # port_in_range(port_bv, target_port, target_port) → target_port ≤ port_bv ≤ target_port
    # Ini selalu True karena port_bv sudah didefinisikan sebagai target_port,
    # tapi membantu Z3 menyertakan informasi port dalam counterexample model
    solver.add(port_in_range(port_bv, target_port, target_port))

    # ── Jalankan solver Z3 ──
    # Z3 mencari SATU kombinasi nilai (internet_ip, ec2_ip) yang memenuhi SEMUA constraint
    # SAT   = ditemukan kombinasi valid → jalur dari internet ke EC2 terbuka → VULNERABLE
    # UNSAT = tidak ada kombinasi yang memenuhi semua constraint sekaligus → SAFE
    result = solver.check()
    if result == sat:
        # solver.model() berisi nilai konkret variabel yang membuktikan celah
        # Contoh: ec2_ip_ssh = 167772160 (desimal) = 10.0.0.0 (IP pertama subnet 10.0.0.0/24)
        return "SAT", solver.model()
    return "UNSAT", None


# ──────────────────────────────────────────────────────────────────────────────
# Public API — fungsi-fungsi ini yang dipanggil oleh main.py
# ──────────────────────────────────────────────────────────────────────────────

def run_ssh_reachability(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """
    Jalankan pengecekan keterjangkauan SSH (port 22) dari internet ke EC2.

    Memverifikasi apakah konfigurasi Security Group memungkinkan siapapun
    di internet mengakses EC2 via SSH. Port 22 terbuka ke 0.0.0.0/0 adalah
    pola "invalid IP address binding" yang diklasifikasikan sebagai security smell
    oleh Rahman et al. [4] dalam paper.

    Return:
    - ("SAT", model)  → SSH terbuka dari internet → VULNERABLE
    - ("UNSAT", None) → SSH tidak bisa dicapai dari internet → SAFE
    """
    return _check_port_reachability(infra, 22, "ssh")


def run_http_reachability(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """
    Jalankan pengecekan keterjangkauan HTTP (port 80) dari internet ke EC2.

    Memverifikasi apakah EC2 bisa diakses langsung via HTTP dari internet.
    Dalam arsitektur Day-24 yang benar, HTTP seharusnya masuk melalui ALB
    (Application Load Balancer) terlebih dahulu, bukan langsung ke EC2.

    Return:
    - ("SAT", model)  → HTTP terbuka langsung ke EC2 dari internet → VULNERABLE
    - ("UNSAT", None) → HTTP tidak bisa dicapai langsung dari internet → SAFE
    """
    return _check_port_reachability(infra, 80, "http")


# ──────────────────────────────────────────────────────────────────────────────
# Standalone entry point
# Dijalankan ketika: python scenarios/scenario_1.py
# Berbeda dengan main.py yang menjalankan semua skenario sekaligus,
# file ini hanya menjalankan Skenario 1 saja dan menyimpan laporannya
# secara terpisah di: reports/scenario_1/report_N.txt
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Tentukan path default ke sample_plan.json (mock terraform plan)
    # os.path.abspath(__file__)     → path absolut file ini: .../scenarios/scenario_1.py
    # os.path.dirname(...)          → .../scenarios/
    # os.path.dirname(...) dua kali → root project: .../AWS-Z3-verifier/
    _default_plan = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "sample_plan.json",
    )
    # Jika ada argumen CLI (python scenario_1.py path/ke/plan.json), gunakan itu
    # Jika tidak ada argumen, gunakan sample_plan.json bawaan (tidak perlu kredensial AWS)
    _plan_file = sys.argv[1] if len(sys.argv) > 1 else _default_plan

    from parser.parser import load_and_parse
    from report import Reporter  # modul auto-increment report writer

    # Parse terraform plan JSON → dict infrastruktur terstruktur
    # Hasilnya berisi keys: vpc, subnets, security_groups, route_tables, ec2_instances, dst
    _infra = load_and_parse(_plan_file)

    # Buat objek Reporter dengan scope "scenario_1"
    # - Otomatis buat folder reports/scenario_1/ jika belum ada
    # - Tentukan nomor file berikutnya (report_1.txt, report_2.txt, dst)
    # - Catat waktu mulai untuk ditulis di laporan
    _rpt = Reporter("scenario_1")

    # ── Jalankan dan tampilkan pengecekan SSH ──
    _r_ssh, _m_ssh = run_ssh_reachability(_infra)
    _v_ssh = "VULNERABLE" if _r_ssh == "SAT" else "SAFE"
    print(f"[SCENARIO 1] Internet→EC2 SSH  : {_r_ssh:<1} {_v_ssh}")
    if _m_ssh:
        # Tampilkan counterexample: nilai konkret variabel Z3 yang membuktikan celah ada
        # Contoh output: ec2_ip_ssh=167772160 → artinya 10.0.0.0 bisa dicapai dari internet
        print(f"  Counterexample: {_m_ssh}")
    # Daftarkan hasil ke reporter (disimpan di memori, belum ditulis ke file)
    _rpt.add_result("Internet→EC2 SSH (port 22)", _r_ssh, _m_ssh)

    # ── Jalankan dan tampilkan pengecekan HTTP ──
    _r_http, _m_http = run_http_reachability(_infra)
    _v_http = "VULNERABLE" if _r_http == "SAT" else "SAFE"
    print(f"[SCENARIO 1] Internet→EC2 HTTP : {_r_http:<1} {_v_http}")
    if _m_http:
        print(f"  Counterexample: {_m_http}")
    _rpt.add_result("Internet→EC2 HTTP (port 80)", _r_http, _m_http)

    # ── Simpan semua hasil ke file laporan ──
    # Reporter menulis file reports/scenario_1/report_N.txt dengan:
    # - Timestamp mulai dan selesai
    # - Semua baris hasil (label, SAT/UNSAT, counterexample jika ada)
    # - Ringkasan: X VULNERABLE | Y SAFE
    _rpt.save()