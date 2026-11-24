# Preflight draft alert

`POST /api/v1/alerts/preflight` mensimulasikan draft rule pada histori satu perangkat dan satu seri, lalu merender contoh payload untuk satu endpoint webhook yang dipilih. Route memerlukan bearer JWT dengan peran admin atau operator.

## Request

Kirim objek `rule` memakai field draft yang sama seperti pembuatan rule, disertai `device_id`, `endpoint_id`, `start_at`, dan `end_at` berformat RFC 3339. `endpoint_id` harus menjadi salah satu nilai di `rule.endpoint_ids`. Perangkat harus aktif, belum dihapus, dan cocok dengan `device_selector` pada draft.

Contoh bentuk request:

```json
{
  "rule": {
    "name": "CPU tinggi",
    "metric_name": "snmp_cpu_percent",
    "comparison": "gte",
    "warning_threshold": 70,
    "critical_threshold": 90,
    "consecutive_failures": 2,
    "recovery_successes": 2,
    "device_selector": {},
    "endpoint_ids": ["00000000-0000-4000-8000-000000000001"]
  },
  "device_id": "00000000-0000-4000-8000-000000000002",
  "endpoint_id": "00000000-0000-4000-8000-000000000001",
  "start_at": "2026-11-20T00:00:00Z",
  "end_at": "2026-11-23T00:00:00Z"
}
```

Rentang harus positif, berakhir di masa lalu, dan tidak lebih dari 7 hari. Query dibatasi maksimum 501 baris untuk mendeteksi kelebihan; jika lebih dari 500 sampel ditemukan, request ditolak dan rentang perlu dipersempit. Sampel diambil dalam urutan waktu untuk tepat satu `metric_name` dan `series_key` (seri skalar memakai string kosong).

## Hasil simulasi

`transitions` berisi hanya perubahan state yang diprediksi, termasuk eskalasi dan pemulihan. Replay dimulai dari state `ok` dengan penghitung nol; state alert aktif saat ini tidak digunakan sebagai baseline. Aturan ambang serta penghitung kegagalan/sukses menggunakan fungsi transisi yang sama dengan evaluasi polling live.

`sample_coverage` menyertakan jumlah sampel, estimasi jumlah sampel berdasar `poll_interval_seconds`, estimasi persentase coverage, dan gap internal. Sebuah gap internal dihitung bila jarak antara dua sampel berurutan lebih dari dua kali interval polling perangkat. Estimasi coverage adalah indikator kasar; ia bukan jaminan bahwa setiap metric memang dipancarkan pada setiap polling.

`notification_preview` menampilkan payload provider terpilih (`generic`, `telegram`, `slack`, atau `discord`) untuk transisi pertama. Bila tidak ada transisi, preview berupa contoh format `ok` ke `warning` dan ditandai `example_only`; itu bukan prediksi pengiriman. ID alert pada payload generik serta ID event di pesan provider merupakan penanda preview, karena ID aktual baru tersedia ketika event live dibuat.

## Batas keamanan dan efek samping

Preflight hanya menjalankan query baca untuk perangkat, konfigurasi endpoint, dan metrik. Ia tidak membuat atau mengubah baris `alerts`, `alert_events`, maupun `notification_outbox`; tidak mengirim HTTP, memanggil dispatcher, atau menerbitkan event WebSocket. Validasi webhook hanya memeriksa konfigurasi lokal—tidak melakukan DNS lookup atau koneksi ke provider.

Rahasia konfigurasi endpoint tidak dikembalikan atau dicatat ke log. URL webhook dan bearer credential tidak dimasukkan ke payload preview; `chat_id` Telegram ditampilkan sebagai `[REDACTED]`. Konfigurasi didekripsi hanya di memori untuk memvalidasi serta merender preview.
