# Rust NMS

Fondasi aplikasi menyediakan bootstrap Axum, PostgreSQL, migrasi, login JWT/RBAC, health checks, CRUD inventori perangkat, serta discovery CIDR berbasis ICMP dengan allowlist dan batas konkurensi. Worker polling periodik menguji ICMP, port TCP yang dikonfigurasi per perangkat, port SSH legacy bila kredensial SSH tersedia, serta SNMP v2c/v3 bila tersedia; status, metrik, transisi alert, dan transactional outbox disimpan ke PostgreSQL/TimescaleDB. Status perangkat dan transisi alert tersedia melalui WebSocket terautentikasi.

## Persyaratan

- Rust 1.94 atau lebih baru
- PostgreSQL 17 dengan TimescaleDB 2.x terpasang dan ekstensi `timescaledb` tersedia
- `DATABASE_URL` untuk memeriksa query SQLx pada waktu kompilasi, atau metadata offline `.sqlx` yang dihasilkan melalui `cargo sqlx prepare`

## Konfigurasi

Salin `.env.example` menjadi `.env`, lalu isi `NMS_DATABASE_URL`, `NMS_JWT_SECRET` (minimal 32 byte), dan `NMS_CREDENTIAL_KEY_HEX` (tepat 32 byte dalam 64 karakter heksadesimal). Jangan commit `.env` atau menggunakan nilai contoh sebagai secret.

Pada startup pertama, saat tabel `users` masih kosong, set `NMS_BOOTSTRAP_ADMIN_EMAIL` dan `NMS_BOOTSTRAP_ADMIN_PASSWORD` (minimal 16 karakter). Akun admin hanya dibuat jika belum ada pengguna; variabel bootstrap dapat dihapus setelahnya. Aplikasi menjalankan migrasi tertanam saat startup, termasuk pembuatan hypertable TimescaleDB.

Discovery nonaktif secara default. Untuk mengaktifkannya, isi `NMS_DISCOVERY_CIDRS` dengan daftar CIDR yang dipisahkan koma dan hanya mencakup jaringan yang Anda kelola. `NMS_MAX_PROBE_CONCURRENCY` mengatur batas global probe polling dan discovery (1–512; default 32). Scheduler mengecek perangkat aktif setiap detik dan hanya memulai perangkat yang jatuh tempo menurut `poll_interval_seconds`; probe dalam satu perangkat berjalan serial agar batas global tetap akurat. Shutdown menghentikan penjadwalan baru dan menunggu probe aktif yang dibatasi timeout perangkat.

## Build dan jalankan

```sh
DATABASE_URL="$NMS_DATABASE_URL" cargo check
DATABASE_URL="$NMS_DATABASE_URL" cargo test
DATABASE_URL="$NMS_DATABASE_URL" cargo run
```

Listener default hanya mengikat `127.0.0.1:8080`; atur `NMS_LISTEN_ADDR` jika deployment memerlukan bind address lain. Endpoint readiness akan gagal bila database tidak dapat diakses.

## Endpoint saat ini

- `GET /health/live` — proses hidup.
- `GET /health/ready` — koneksi database siap.
- `POST /api/v1/auth/login` — login JSON `{ "email": "...", "password": "..." }`; mengembalikan JWT HS256 dengan masa berlaku 15 menit.
- `POST /api/v1/auth/ws-ticket` — tukar JWT valid menjadi tiket WebSocket satu kali yang berlaku 30 detik.
- `POST /api/v1/discovery/scans` — scan CIDR yang berada seluruhnya di dalam allowlist, misalnya `{ "cidr": "192.168.1.0/24" }`; hanya admin/operator, maksimal 1024 alamat per permintaan. Probe ICMP yang berhasil ditambahkan sebagai perangkat baru dengan tipe `other`; inventori yang sudah ada tidak ditimpa.
- `GET /api/v1/devices?page=1&per_page=50` — daftar berpaginasi.
- `GET /api/v1/devices/{id}` — detail tanpa mengembalikan ciphertext atau rahasia.
- `POST /api/v1/devices` — buat perangkat. `tcp_probe_ports` opsional menerima hingga 32 port unik (1–65535), misalnya `[22, 80, 443]`.
- `PUT /api/v1/devices/{id}` — ganti seluruh representasi perangkat; kredensial yang tidak disertakan akan dihapus. Khusus `tcp_probe_ports`, field yang tidak disertakan mempertahankan daftar sebelumnya; kirim `[]` untuk menghapus semua port TCP tambahan.
- `DELETE /api/v1/devices/{id}` — soft-delete, menonaktifkan perangkat tanpa menghapus histori.
- `GET /api/v1/alerts/rules`, `POST /api/v1/alerts/rules`, dan `PUT /api/v1/alerts/rules/{id}` — baca, buat, atau ganti rule beserta daftar `endpoint_ids`-nya. `PATCH /api/v1/alerts/rules/{id}/enabled` menerima `{ "is_enabled": false }` untuk menonaktifkan evaluasi rule. Metric yang didukung: `icmp_reachable`, `icmp_latency_ms`, `tcp_reachable`, `tcp_connect_latency_ms`, `snmp_reachable`, `sys_uptime_seconds`, `snmp_cpu_percent`, `snmp_memory_used_percent`, `snmp_if_in_bps`, dan `snmp_if_out_bps`. `series_key` opsional memilih satu seri untuk metric TCP/interface (mis. `port=443` atau `ifIndex=2`); tanpa selector, rule interface tidak valid, sedangkan rule TCP tanpa selector tetap mencocokkan seri legacy. Rule juga menerima `comparison`, threshold warning/kritis, jumlah kegagalan berturut-turut, jumlah sukses pemulihan, selector perangkat, dan `endpoint_ids`.
- `POST /api/v1/alerts/preflight` — simulasi draft rule pada histori satu perangkat/seri (maksimum 7 hari dan 500 sampel), mengembalikan transisi, estimasi coverage/gap, dan preview payload endpoint provider terpilih. Operasi ini hanya membaca data; tidak menulis alert/outbox, mengirim HTTP, atau menerbitkan WebSocket event. Rahasia endpoint dikecualikan atau disamarkan. Lihat [panduan preflight alert](docs/alert-preflight.md).
- `GET /api/v1/alerts` — snapshot status alert terbaru; `GET /api/v1/alerts/events` — riwayat transisi.
- `GET /api/v1/webhooks`, `POST /api/v1/webhooks`, dan `PUT /api/v1/webhooks/{id}` — baca, buat, atau ganti konfigurasi notifikasi. `provider` dapat berupa `generic` (default), `telegram`, `slack`, atau `discord`: generic memakai `url` dan `bearer_token` opsional; Telegram memakai `bot_token` dan `chat_id`; Slack memakai URL incoming webhook `https://hooks.slack.com/services/...`; Discord memakai URL `https://discord.com/api/webhooks/{id}/{token}`. `PATCH /api/v1/webhooks/{id}/enabled` menerima `{ "is_enabled": false }`; antrean pengiriman tertahan selama endpoint nonaktif dan dilanjutkan saat diaktifkan kembali. Koneksi memakai HTTPS port 443, hanya menerima resolusi DNS publik, mematok IP hasil resolusi, dan menolak redirect. Seluruh konfigurasi provider (termasuk URL, token, dan Telegram `chat_id`) dienkripsi serta tidak dikembalikan oleh API. Lihat [kontrak dan sumber resmi provider](docs/webhook-providers.md).
- `GET /api/v1/ws` — stream event `device.status`, `alert.transition`, dan `stream.gap`. Untuk browser, panggil endpoint tiket dengan bearer JWT, lalu tawarkan subprotocol `cue-events-v1` dan `cue-ticket.<ticket>` saat membuka WebSocket. Tiket dihapus saat dipakai. Setelah `stream.gap`, ambil ulang snapshot melalui REST.

Kirim `Authorization: Bearer <token>` pada route perangkat, alert, dan webhook. Admin dan operator dapat mengubah inventori, rule, dan endpoint; viewer hanya dapat membaca. Credential fields untuk SNMP/SSH dienkripsi sebelum ditulis; respons hanya menyertakan boolean `has_snmp_credentials` dan `has_ssh_credentials`.

## Catatan tahap ini

Polling merekam `icmp_reachable` dan latensi ICMP; `tcp_reachable` dan latensi koneksi untuk tiap `tcp_probe_ports` serta port SSH legacy bila kredensial SSH tersedia; `snmp_reachable`; `sys_uptime_seconds`; dan, bila agent menyediakan MIB terkait, `snmp_cpu_percent` (rata-rata `hrProcessorLoad`), `snmp_memory_used_percent` (baris RAM `hrStorage`), `snmp_if_in_bps`, serta `snmp_if_out_bps`. `sysName` dan `sysDescr` disimpan sebagai metadata perangkat. TCP hanya memeriksa koneksi port; worker tidak melakukan autentikasi SSH. Seri TCP memakai identitas `port=<nomor>` dan seri interface memakai `ifIndex=<indeks>`; nama/deskripsi interface disertakan sebagai metadata bila agent memberikannya. Interface rate dihitung dari delta counter IF-MIB per interval, memilih counter 64-bit `ifHC*Octets` bila tersedia dan memakai counter 32-bit `if*Octets` sebagai fallback. Sampel awal tidak menghasilkan rate; rate juga dilewati saat reboot, perubahan `ifCounterDiscontinuityTime`, perubahan lebar counter, atau penurunan counter yang tidak aman terdeteksi. Counter tersimpan persis sebagai teks desimal untuk mempertahankan nilai 64-bit dan baseline bertahan melewati restart. Kegagalan walk CPU/RAM/interface yang opsional tidak mengubah status dasar SNMP reachable. Status `up` berarti semua probe yang dikonfigurasi berhasil, `degraded` berarti sebagian berhasil, dan `down` berarti tidak ada probe yang berhasil. Alert mengevaluasi metric yang masuk, menerapkan consecutive-failure dan recovery-success, lalu menyimpan state terpisah per seri, event, dan outbox secara atomik dengan transaksi poll. Dispatcher mengirim notifikasi menggunakan payload provider terkait melalui outbox secara serial, tanpa proxy atau redirect, dengan timeout dan retry eksponensial; satu pesan berisi ID event agar penerima dapat melakukan deduplikasi. Polling dan tiket WebSocket saat ini berlaku untuk satu instance layanan; scheduler terdistribusi belum disediakan.

Cooldown notifikasi menekan pengiriman ulang selama alert tetap terbuka; eskalasi ke kritis dan pemulihan tetap diberitahukan.

SNMPv3 privacy `AES` dianjurkan. `DES` tersedia hanya untuk interoperabilitas legacy dan lemah terhadap brute force; `3DES` juga lebih lambat dan tidak dianjurkan untuk deployment baru. `async-snmp` menyediakan implementasi DES/3DES serta key extension Reeder untuk kombinasi yang memerlukannya.

Login dan pembuatan tiket belum memiliki rate limit per akun/IP; letakkan pembatasan di reverse proxy sebelum membuka endpoint ke jaringan tidak tepercaya. Migrasi perlu dijalankan terhadap PostgreSQL dengan TimescaleDB yang terpasang. Uji query compile-time dan unit test tidak menggantikan uji integrasi penuh pada PostgreSQL 17 + TimescaleDB 2.x. Payload generic, Telegram, Slack, dan Discord kini didukung; pengiriman langsung ke akun provider tidak dilakukan dalam smoke test.
