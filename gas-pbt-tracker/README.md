# PBT Tracker (Google Apps Script)

Versi yang sudah dikeraskan (hardened) dari PBT Tracker: password ter-hash,
setiap aksi data mewajibkan sesi login yang valid, rate limiting OTP/login,
dan pustaka export dimuat lazy supaya halaman ringan.

## File

- `Kode.gs` — server logic (auth, sesi, rate limit, CRUD PBT).
- `index.html` — UI (Bootstrap, export PDF/Excel/PNG dimuat saat dipakai).
- `appsscript.json` — manifest deployment.

## Setup

1. Buat/pakai Google Sheet dengan ID di `SPREADSHEET_ID` (`Kode.gs` baris 20).
   Sheet `Users` dan `PBTData` dibuat otomatis saat pertama dipakai, dengan
   kolom `Users`: `Email | PasswordHash | Salt | Role | OTP | OTPExpiry`.
2. Push project ini ke Apps Script (clasp, atau copy-paste manual ke editor
   script.google.com yang terhubung ke Sheet tersebut).
3. Di editor Apps Script, jalankan fungsi `setupInitialAdmin` **sekali** untuk
   membuat akun admin PUR (`PURA` / `Ternate2026`) dengan password ter-hash.
   **Segera login dan pertimbangkan mengganti password default ini** —
   siapa pun yang tahu kredensial default bisa approve/reject data.
4. Deploy → New deployment → Web app:
   - Execute as: **Me**
   - Who has access: **Anyone** (aplikasi punya login sendiri, tidak
     memerlukan akun Google)
5. Bagikan URL `.../exec` ke pengguna.

## Kenapa berubah dari versi awal

- **Password plaintext → hash SHA-256 + salt per akun.** Sebelumnya kolom
  `Password` di Sheet Users tersimpan apa adanya — siapa pun yang bisa
  membuka spreadsheet (editor/viewer lain, atau log akses) langsung melihat
  semua password pengguna.
- **Tidak ada verifikasi sesi di server.** Semua fungsi (`getPBTData`,
  `submitPBT`, `updateStatusPBT`) sebelumnya bisa dipanggil langsung dari
  console browser oleh siapa pun yang membuka URL web app, tanpa login sama
  sekali — termasuk meng-approve/reject data. Sekarang setiap panggilan
  mewajibkan token sesi yang didapat dari `loginUser`, dan `updateStatusPBT`
  memverifikasi role `PUR` di server (bukan hanya disembunyikan di UI).
- **Rate limiting.** `sendOTP` dibatasi cooldown 60 detik + kuota
  harian per email & global (mencegah spam email ke pihak lain / pemborosan
  kuota `MailApp`). Login dikunci 15 menit setelah 5 kali gagal berturut-turut
  (mencegah brute force password).
- **Sanitasi input.** Semua teks bebas (uraian, keterangan, nama, dst)
  dibatasi panjangnya dan dinetralkan bila diawali `= + - @` untuk mencegah
  *formula injection* saat data dibuka di Google Sheets/Excel.
- **Kunci konkurensi (`LockService`).** Semua operasi tulis dibungkus lock
  agar aman diakses ratusan user bersamaan tanpa data balapan (race
  condition) saat registrasi/submit/approve.
- **`emailPenginput` diambil dari sesi server**, bukan dikirim dari client —
  sebelumnya client bebas mengisi nilai apa pun untuk kolom ini.
- **`X-Frame-Options` dikembalikan ke default** (sebelumnya `ALLOWALL`, yang
  membuat halaman login bisa disisipkan sebagai iframe tak terlihat di situs
  lain — celah *clickjacking*).
- **Pustaka export (jsPDF/xlsx/html2canvas) di-lazy-load**, hanya diunduh
  saat tombol Excel/PDF/PNG ditekan — mempercepat waktu buka halaman.
- Fungsi `testAuthorization` (mengirim email tes) dihapus dari kode produksi
  karena secara default tetap bisa dipanggil siapa pun lewat
  `google.script.run` walau tidak dipakai di UI.

## Catatan skala (≈500 pengguna)

- Sesi (`CacheService`) bertahan maksimal 6 jam (batas platform), lalu
  pengguna perlu login ulang — ini batas Google, bukan pilihan desain.
- Kuota `MailApp`: akun Gmail biasa ±100 email/hari, akun Google Workspace
  ±1500/hari. Dengan 500 pengguna yang mendaftar OTP di hari yang sama,
  gunakan akun Workspace untuk deployment ini agar tidak kehabisan kuota
  (batas global harian sudah dijaga di `Kode.gs` lewat `OTP_MAX_TOTAL_PER_DAY`,
  sesuaikan dengan kuota akun yang dipakai).
- Data tetap disimpan di Google Sheets — cocok untuk skala ratusan
  pengguna/ribuan baris. Jika volume transaksi PBT tumbuh sangat besar
  (puluhan ribu baris aktif), pertimbangkan migrasi ke database (mis.
  Firestore/Cloud SQL) di kemudian hari.
