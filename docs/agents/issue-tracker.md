# Issue tracker: Markdown lokal

Isu dan spesifikasi untuk repo ini disimpan sebagai berkas Markdown di `.scratch/`.

## Konvensi

- Satu fitur per direktori: `.scratch/<slug-fitur>/`.
- Spesifikasi fitur disimpan di `.scratch/<slug-fitur>/spec.md`.
- Tiap tiket implementasi berupa satu berkas di `.scratch/<slug-fitur>/issues/<NN>-<slug>.md`, dimulai dari `01`; jangan gabungkan beberapa tiket dalam satu berkas.
- Status pekerjaan dicatat pada baris `Status:` di dekat bagian atas tiket.
- Komentar dan riwayat percakapan ditambahkan di bagian `## Comments` pada akhir berkas.

## Operasi tracker

- Jika skill meminta menerbitkan isu atau spesifikasi, buat berkas di bawah `.scratch/<slug-fitur>/` (buat direktori bila belum ada).
- Jika skill meminta mengambil tiket, baca berkas pada path atau nomor yang dirujuk pengguna.
