# Rancangan Tahap 1 — Rust Network Management System

## Asumsi yang diajukan

Spesifikasi belum memilih skala, bentuk UI, atau database. Rancangan ini memakai asumsi awal berikut; semuanya dapat diubah sebelum implementasi:

| Keputusan | Usulan | Alasan |
|---|---|---|
| Skala awal | 50–500 perangkat, satu instance layanan | Cukup untuk memvalidasi polling dan alert tanpa menambah kompleksitas klaster lebih dini. |
| UI | REST API + WebSocket; frontend terpisah di tahap berikutnya | Memisahkan lifecycle UI dari collector dan memudahkan integrasi dashboard. |
| Database | PostgreSQL 17 + TimescaleDB 2.x | Relasional untuk inventori/alert/user, hypertable untuk metrik bertimestamp. |
| Bentuk proyek | Satu crate Rust modular, bukan workspace multi-crate | Batas modul internal sudah memadai untuk satu layanan dan lebih mudah dibangun pada tahap awal. |

## Arsitektur dan alur data

1. **API dan autentikasi** — Axum menyediakan `/api/v1` untuk inventori, discovery, metrik, rule, dan riwayat alert serta endpoint WebSocket untuk event langsung. Middleware memverifikasi JWT dan menerapkan RBAC: `admin`, `operator`, `viewer`. Mutasi dibatasi per peran; viewer hanya membaca.
2. **Application/domain** — Use case mengatur CRUD, validasi, discovery, polling, evaluasi rule, dan transisi status. Domain berisi tipe perangkat/metrik/alert serta error yang tidak bergantung pada Axum, SQLx, atau driver jaringan.
3. **Discovery** — Permintaan discovery hanya untuk CIDR yang diizinkan konfigurasi dan pemanggil berwenang. Target diproses dengan batas concurrency/rate dan timeout; hasil ICMP/SNMP dinormalisasi, lalu perangkat baru disimpan tanpa menimpa inventori/kredensial yang sudah ada.
4. **Polling** — Scheduler mengambil perangkat aktif, menjadwalkan ICMP/TCP/SNMP dengan jitter, batas global `Semaphore`, timeout per probe, dan batas per-target. Task tidak dibuat tanpa batas: pekerjaan menunggu slot semaphore dan hasil masuk ke kanal `mpsc` berbatas.
5. **Storage metrik** — Writer menggabungkan hasil dan menulis batch ke hypertable `metrics` melalui SQLx; status ringkas perangkat diperbarui di `devices`. Query SQL aplikasi menggunakan macro SQLx yang divalidasi saat build melalui database skema/dev atau metadata offline `.sqlx` yang dibuat oleh CI.
6. **Alert engine** — Evaluator menerapkan consecutive-failure dan recovery-success, lalu melakukan upsert state per pasangan rule/perangkat. Perubahan `ok → warning → critical → resolved` disimpan atomik bersama event audit dan baris transactional outbox. Cooldown mengirim notifikasi hanya pada transisi atau pengulangan yang diizinkan rule.
7. **Notifikasi dan streaming** — Dispatcher mengirim outbox via `reqwest`, memakai retry/backoff dan hasil idempoten, tanpa menahan proses polling. API mempublikasikan status/alert ke WebSocket. Setelah reconnect atau kehilangan pesan, dashboard mengambil snapshot terbaru lewat REST.
8. **Shutdown** — SIGINT/SIGTERM memulai `CancellationToken`: server berhenti menerima koneksi baru, scheduler menghentikan penjadwalan, task berjalan dibatasi waktu, writer mengosongkan buffer, lalu pool database ditutup.

## Batas modul yang disarankan

```text
rust-nms/
├── Cargo.toml
├── Cargo.lock                 # dibuat saat resolusi dependensi tahap implementasi
├── ARCHITECTURE.md
├── migrations/
│   └── 0001_initial.sql
├── config/
│   └── default.toml
└── src/
    ├── main.rs
    ├── lib.rs
    ├── app.rs                 # wiring dan lifecycle
    ├── config.rs
    ├── api/
    │   ├── mod.rs
    │   ├── auth.rs
    │   ├── devices.rs
    │   ├── discovery.rs
    │   ├── metrics.rs
    │   ├── alerts.rs
    │   ├── websocket.rs
    │   └── errors.rs
    ├── domain/
    │   ├── mod.rs
    │   ├── device.rs
    │   ├── metric.rs
    │   ├── alert.rs
    │   ├── user.rs
    │   └── error.rs
    ├── application/
    │   ├── mod.rs
    │   ├── inventory.rs
    │   ├── discovery.rs
    │   ├── polling.rs
    │   └── alerting.rs
    ├── infrastructure/
    │   ├── mod.rs
    │   ├── db/
    │   ├── network/            # icmp.rs, tcp.rs, snmp.rs
    │   ├── crypto.rs
    │   └── webhook.rs
    └── workers/
        ├── mod.rs
        ├── scheduler.rs
        ├── metrics_writer.rs
        └── notification_dispatcher.rs
```

Struktur ini adalah rencana, bukan modul implementasi. Driver SNMP dipisahkan di balik batas infrastruktur karena `async-snmp` masih pre-1.0 dan API dapat berubah. Dokumentasi crate menyatakan dukungan klien SNMPv1/v2c/v3 USM berbasis Tokio; detail SNMPv3/USM tersedia di [docs.rs](https://docs.rs/async-snmp/latest/async_snmp/v3/) dan [repositori proyek](https://github.com/lukeod/async-snmp).

## Keamanan, operasi, dan batas kapasitas

- Kredensial SNMP community, SNMPv3 auth/privacy, SSH private key, dan konfigurasi endpoint dienkripsi aplikasi sebelum masuk database menggunakan AES-256-GCM. Simpan kunci di secret manager atau environment terlindungi, bukan di database atau repo; envelope ciphertext harus membawa versi kunci dan nonce. Ikat konteks ciphertext ke ID perangkat/field sebagai associated data, jangan pernah kirim ciphertext/rahasia pada respons API atau log.
- Password akun disimpan sebagai hash Argon2id, bukan ciphertext. JWT berumur pendek dan diverifikasi per route; kunci penandatanganan berasal dari secret store.
- Discovery dan polling merupakan kemampuan probe jaringan: batasi dengan CIDR allowlist eksplisit, autentikasi/otorisasi, rate limit, audit trail, timeout, dan batas task. Webhook generic wajib menolak loopback, link-local, alamat privat yang tidak diizinkan, dan redirect yang melanggar kebijakan egress untuk mencegah SSRF.
- `metrics` tidak diberi kebijakan retensi otomatis dalam migrasi awal. Tentukan retensi/kompresi berdasarkan kebutuhan histori dan disk sebelum menerapkannya; jangan menghapus histori secara diam-diam.
- Gunakan `tracing` terstruktur, tetapi redaksi header Authorization, community string, key, token, URL webhook sensitif, dan payload autentikasi.
- Kapasitas awal ditentukan melalui konfigurasi (mis. maksimum task simultan dan interval polling), bukan nilai yang dikodekan permanen. Ukur durasi probe, backlog kanal, waktu tulis batch, pool saturation, dan lag WebSocket sebelum menaikkan skala.

## Status implementasi

- Implementasi saat ini mencakup API REST/WebSocket, autentikasi/RBAC, inventori dan discovery terbatas, polling ICMP/TCP/SNMP, alerting, transactional outbox, serta dispatcher provider.
- Migrasi aditif mencakup daftar port TCP hingga 32 per perangkat, identitas seri alert, dan baseline counter IF-MIB yang menyimpan nilai penuh.
- Polling SNMP mengambil CPU dari `hrProcessorLoad`, memori dari baris RAM `hrStorage`, serta rate interface dari `ifHC*Octets` dengan fallback `if*Octets`. Sampel pertama, reboot, discontinuity, perubahan lebar, dan reset counter yang tidak aman tidak menghasilkan rate.
- Build/test terhadap PostgreSQL 17 + TimescaleDB 2.x tetap perlu diverifikasi pada lingkungan integrasi; validasi lokal terhadap PostgreSQL 16 saja tidak membuktikan kompatibilitas penuh.

## Asumsi produk yang disetujui

Implementasi mengikuti asumsi **skala 50–500 perangkat**, **REST API + WebSocket**, dan **PostgreSQL 17 + TimescaleDB 2.x**. Polling dan tiket WebSocket saat ini ditujukan untuk satu instance layanan.
