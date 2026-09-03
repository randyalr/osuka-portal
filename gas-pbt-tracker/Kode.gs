/**
 * PBT Tracker - Server (Google Apps Script)
 *
 * Perubahan keamanan utama dibanding versi awal:
 *  - Password disimpan sebagai hash (SHA-256 + salt per user), bukan plain text.
 *  - Setiap fungsi sensitif (getPBTData, submitPBT, updateStatusPBT) mewajibkan
 *    token sesi yang valid - sebelumnya fungsi-fungsi ini bisa dipanggil oleh
 *    siapa pun yang membuka URL web app (lewat console browser) tanpa login.
 *  - updateStatusPBT sekarang memverifikasi role "PUR" di server, bukan hanya
 *    disembunyikan di UI.
 *  - Rate limiting untuk OTP (cooldown + kuota harian) dan lockout percobaan
 *    login yang gagal, untuk mencegah spam email / brute force.
 *  - Input disanitasi (dibatasi panjangnya, dan dinetralkan bila diawali
 *    karakter pemicu formula seperti = + - @) untuk mencegah "formula
 *    injection" pada Google Sheets / hasil export Excel.
 *  - Semua operasi tulis ke Sheet dibungkus LockService agar aman saat
 *    diakses banyak user (ratusan) secara bersamaan.
 */

const SPREADSHEET_ID = "1mdUfnGnIJ6ThUyFZriAiwtzQJhSV_m3rkxK2nASqwM0";

const SHEET_USERS = "Users";
const SHEET_PBT = "PBTData";

// Sesi disimpan di CacheService (maksimum TTL platform = 6 jam / 21600 detik).
const SESSION_TTL_SECONDS = 21600;

// Rate limit OTP.
const OTP_COOLDOWN_SECONDS = 60;
const OTP_MAX_PER_EMAIL_PER_DAY = 5;
const OTP_MAX_TOTAL_PER_DAY = 400; // jaga kuota MailApp harian
const OTP_EXPIRY_MINUTES = 10;

// Lockout login.
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_SECONDS = 900; // 15 menit
const LOGIN_FAIL_WINDOW_SECONDS = 900;

function getCache_() {
  return CacheService.getScriptCache();
}

function getSS() {
  try {
    if (SPREADSHEET_ID && SPREADSHEET_ID !== "") {
      return SpreadsheetApp.openById(SPREADSHEET_ID);
    }
    return SpreadsheetApp.getActiveSpreadsheet();
  } catch (e) {
    Logger.log("Error Buka Spreadsheet: " + e.message);
    return null;
  }
}

function doGet() {
  return HtmlService.createTemplateFromFile('index')
    .evaluate()
    .setTitle('PBT Tracker')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.DEFAULT);
}

/* =========================================================
 * Utilitas keamanan
 * ========================================================= */

function isValidEmail_(email) {
  return typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// Membatasi panjang teks & menetralkan karakter pemicu formula
// (mencegah "CSV/formula injection" saat data dibuka di Sheets/Excel).
function sanitizeText_(value, maxLen) {
  let s = (value === null || value === undefined) ? "" : value.toString().trim();
  if (maxLen && s.length > maxLen) s = s.substring(0, maxLen);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return s;
}

// Menghapus penanda netralisasi di atas saat data ditampilkan kembali ke UI.
function displayText_(value) {
  if (value === null || value === undefined) return "";
  const s = value.toString();
  return /^'[=+\-@]/.test(s) ? s.substring(1) : s;
}

function generateSalt_() {
  return Utilities.getUuid().replace(/-/g, "") + Utilities.getUuid().replace(/-/g, "");
}

function hashPassword_(password, salt) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + salt,
    Utilities.Charset.UTF_8
  );
  return bytes.map(function (b) {
    const v = b < 0 ? b + 256 : b;
    const hex = v.toString(16);
    return hex.length === 1 ? "0" + hex : hex;
  }).join("");
}

function verifyPassword_(password, salt, hash) {
  return hashPassword_(password, salt) === hash;
}

/* ---- Sesi login ---- */

function createSession_(email, role) {
  const token = Utilities.getUuid() + Utilities.getUuid();
  getCache_().put("sess_" + token, JSON.stringify({ email: email, role: role }), SESSION_TTL_SECONDS);
  return token;
}

function getSession_(token) {
  if (!token) return null;
  const raw = getCache_().get("sess_" + token);
  if (!raw) return null;
  try {
    const data = JSON.parse(raw);
    // Sliding expiration: perpanjang sesi selama masih aktif digunakan.
    getCache_().put("sess_" + token, raw, SESSION_TTL_SECONDS);
    return data;
  } catch (e) {
    return null;
  }
}

function destroySession_(token) {
  if (token) getCache_().remove("sess_" + token);
}

// Kembalikan { session } jika token valid & role diizinkan, atau { error } jika tidak.
function requireAuth_(token, allowedRoles) {
  const session = getSession_(token);
  if (!session) {
    return { error: { success: false, message: "Sesi Anda telah berakhir. Silakan login kembali.", sessionExpired: true } };
  }
  if (allowedRoles && allowedRoles.length && allowedRoles.indexOf(session.role) === -1) {
    return { error: { success: false, message: "Anda tidak memiliki akses untuk aksi ini." } };
  }
  return { session: session };
}

function logoutUser(token) {
  destroySession_(token);
  return { success: true };
}

/* ---- Rate limit OTP ---- */

function otpDailyStore_() {
  const props = PropertiesService.getScriptProperties();
  const today = Utilities.formatDate(new Date(), "Asia/Jakarta", "yyyyMMdd");
  const raw = props.getProperty("OTP_DAILY");
  let store = raw ? JSON.parse(raw) : null;
  if (!store || store.date !== today) {
    store = { date: today, counts: {}, total: 0 };
  }
  return store;
}

function saveOtpDailyStore_(store) {
  PropertiesService.getScriptProperties().setProperty("OTP_DAILY", JSON.stringify(store));
}

/* ---- Lockout login ---- */

function isLoginLocked_(username) {
  return !!getCache_().get("ll_" + username.toLowerCase());
}

function recordLoginFailure_(username) {
  const key = "lf_" + username.toLowerCase();
  const cache = getCache_();
  const count = Number(cache.get(key) || 0) + 1;
  cache.put(key, String(count), LOGIN_FAIL_WINDOW_SECONDS);
  if (count >= LOGIN_MAX_ATTEMPTS) {
    cache.put("ll_" + username.toLowerCase(), "1", LOGIN_LOCK_SECONDS);
    cache.remove(key);
  }
}

function clearLoginFailures_(username) {
  const cache = getCache_();
  cache.remove("lf_" + username.toLowerCase());
  cache.remove("ll_" + username.toLowerCase());
}

/* =========================================================
 * Setup awal - dijalankan SEKALI secara manual dari editor
 * Apps Script (bukan dipanggil dari client) untuk membuat
 * sheet Users + akun admin PUR dengan password ter-hash.
 * ========================================================= */

function setupInitialAdmin() {
  const ss = getSS();
  if (!ss) throw new Error("Spreadsheet tidak ditemukan.");

  let sheet = ss.getSheetByName(SHEET_USERS);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_USERS);
    sheet.appendRow(["Email", "PasswordHash", "Salt", "Role", "OTP", "OTPExpiry"]);
  }

  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] && data[i][0].toString().trim().toUpperCase() === "PURA") {
      Logger.log("Akun admin PURA sudah ada, tidak dibuat ulang.");
      return;
    }
  }

  // GANTI password default ini segera setelah setup melalui Sheet
  // (hitung ulang hash dengan hashPassword_ jika ingin mengganti manual).
  const defaultPassword = "Ternate2026";
  const salt = generateSalt_();
  const hash = hashPassword_(defaultPassword, salt);
  sheet.appendRow(["PURA", hash, salt, "PUR", "", ""]);
  Logger.log("Akun admin PURA berhasil dibuat. Segera ganti password default!");
}

/* =========================================================
 * Auth (publik, sebelum login)
 * ========================================================= */

function sendOTP(email) {
  try {
    if (!isValidEmail_(email)) {
      return { success: false, message: "Alamat email tidak valid!" };
    }
    const key = email.trim().toLowerCase();
    const cache = getCache_();

    if (cache.get("otp_cd_" + key)) {
      return { success: false, message: "Mohon tunggu sebentar sebelum meminta OTP lagi." };
    }

    const store = otpDailyStore_();
    if ((store.counts[key] || 0) >= OTP_MAX_PER_EMAIL_PER_DAY) {
      return { success: false, message: "Batas permintaan OTP harian untuk email ini sudah tercapai. Coba lagi besok." };
    }
    if (store.total >= OTP_MAX_TOTAL_PER_DAY) {
      return { success: false, message: "Sistem sedang sibuk (kuota email harian tercapai). Coba lagi nanti." };
    }

    const lock = LockService.getScriptLock();
    if (!lock.tryLock(10000)) {
      return { success: false, message: "Server sibuk, silakan coba lagi." };
    }

    try {
      const ss = getSS();
      if (!ss) {
        return { success: false, message: "Gagal terhubung ke Google Spreadsheet! Periksa ID Spreadsheet." };
      }

      let sheet = ss.getSheetByName(SHEET_USERS);
      if (!sheet) {
        sheet = ss.insertSheet(SHEET_USERS);
        sheet.appendRow(["Email", "PasswordHash", "Salt", "Role", "OTP", "OTPExpiry"]);
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000).toISOString();
      const data = sheet.getDataRange().getValues();
      let found = false;

      for (let i = 1; i < data.length; i++) {
        if (data[i][0] && data[i][0].toString().trim().toLowerCase() === key) {
          // Catatan: mengirim OTP baru untuk email yang sudah terdaftar juga
          // berfungsi sebagai reset password (OTP baru harus dikonfirmasi
          // lewat registerUser untuk menimpa password lama), sama seperti
          // perilaku aplikasi semula.
          sheet.getRange(i + 1, 5).setValue(otp);
          sheet.getRange(i + 1, 6).setValue(expiry);
          found = true;
          break;
        }
      }

      if (!found) {
        sheet.appendRow([email.trim(), "", "", "UMI", otp, expiry]);
      }

      MailApp.sendEmail({
        to: email.trim(),
        subject: "Kode OTP PBT Tracker",
        htmlBody: `
          <div style="font-family:Arial,sans-serif;padding:20px;border:1px solid #e0e0e0;border-radius:8px;max-width:500px">
            <h3 style="color:#0d6efd;margin-top:0">PBT Tracker - Verifikasi OTP</h3>
            <p>Gunakan kode OTP berikut untuk melengkapi proses registrasi akun UMI Anda (berlaku ${OTP_EXPIRY_MINUTES} menit):</p>
            <div style="background:#f8f9fa;padding:15px;border-radius:6px;text-align:center;margin:20px 0">
              <span style="font-size:32px;font-weight:bold;letter-spacing:5px;color:#198754">${otp}</span>
            </div>
            <p style="color:#6c757d;font-size:12px;margin-bottom:0">Jika Anda tidak merasa meminta kode ini, abaikan email ini.</p>
          </div>
        `
      });

      cache.put("otp_cd_" + key, "1", OTP_COOLDOWN_SECONDS);
      store.counts[key] = (store.counts[key] || 0) + 1;
      store.total += 1;
      saveOtpDailyStore_(store);

      return { success: true, message: "Kode OTP telah berhasil dikirimkan ke email: " + email.trim() };
    } finally {
      lock.releaseLock();
    }
  } catch (err) {
    Logger.log("Error sendOTP: " + err.message);
    return { success: false, message: "Gagal Mengirim OTP." };
  }
}

function registerUser(email, password, otp) {
  try {
    if (!isValidEmail_(email) || !password || !otp) {
      return { success: false, message: "Email, password dan OTP wajib diisi." };
    }
    if (password.length < 8) {
      return { success: false, message: "Password minimal 8 karakter." };
    }

    const lock = LockService.getScriptLock();
    if (!lock.tryLock(10000)) {
      return { success: false, message: "Server sibuk, silakan coba lagi." };
    }

    try {
      const ss = getSS();
      if (!ss) return { success: false, message: "Spreadsheet tidak ditemukan." };

      const sheet = ss.getSheetByName(SHEET_USERS);
      if (!sheet) return { success: false, message: "Sheet Users belum ditemukan." };

      const data = sheet.getDataRange().getValues();
      const key = email.trim().toLowerCase();

      for (let i = 1; i < data.length; i++) {
        if (data[i][0] && data[i][0].toString().trim().toLowerCase() === key) {
          const storedOtp = data[i][4] ? data[i][4].toString() : "";
          const storedExpiry = data[i][5];

          if (!storedOtp || storedOtp !== otp.toString().trim()) {
            return { success: false, message: "Kode OTP yang Anda masukkan salah!" };
          }
          if (storedExpiry && new Date(storedExpiry).getTime() < Date.now()) {
            return { success: false, message: "Kode OTP sudah kedaluwarsa. Silakan kirim ulang OTP." };
          }

          const salt = generateSalt_();
          const hash = hashPassword_(password, salt);
          sheet.getRange(i + 1, 2).setValue(hash);
          sheet.getRange(i + 1, 3).setValue(salt);
          sheet.getRange(i + 1, 5).setValue("");
          sheet.getRange(i + 1, 6).setValue("");
          return { success: true, message: "Registrasi akun UMI berhasil! Silakan login." };
        }
      }

      return { success: false, message: "Email belum mendaftar OTP! Silakan klik 'Kirim OTP'." };
    } finally {
      lock.releaseLock();
    }
  } catch (err) {
    Logger.log("Error registerUser: " + err.message);
    return { success: false, message: "Error Registrasi." };
  }
}

function loginUser(username, password) {
  try {
    if (!username || !password) {
      return { success: false, message: "Username/Email dan Password wajib diisi." };
    }

    const uname = username.toString().trim();

    if (isLoginLocked_(uname)) {
      return { success: false, message: "Terlalu banyak percobaan login gagal. Coba lagi dalam 15 menit." };
    }

    const ss = getSS();
    if (!ss) return { success: false, message: "Spreadsheet tidak ditemukan." };

    const sheet = ss.getSheetByName(SHEET_USERS);
    if (!sheet) {
      return { success: false, message: "Database pengguna belum ada di Sheet Users." };
    }

    const data = sheet.getDataRange().getValues();

    for (let i = 1; i < data.length; i++) {
      if (data[i][0] && data[i][0].toString().trim().toLowerCase() === uname.toLowerCase()) {
        const hash = data[i][1] ? data[i][1].toString() : "";
        const salt = data[i][2] ? data[i][2].toString() : "";

        if (!hash || !verifyPassword_(password, salt, hash)) {
          recordLoginFailure_(uname);
          return { success: false, message: "Username/Email atau Password salah!" };
        }

        clearLoginFailures_(uname);
        const role = data[i][3];
        const token = createSession_(data[i][0].toString().trim(), role);
        return { success: true, token: token, role: role, user: data[i][0].toString().trim() };
      }
    }

    recordLoginFailure_(uname);
    return { success: false, message: "Username/Email atau Password salah!" };
  } catch (err) {
    Logger.log("Error loginUser: " + err.message);
    return { success: false, message: "Error Login." };
  }
}

/* =========================================================
 * Data PBT (memerlukan sesi login yang valid)
 * ========================================================= */

function submitPBT(token, payload) {
  const auth = requireAuth_(token, null);
  if (auth.error) return auth.error;

  try {
    if (!payload || typeof payload !== "object") {
      return { success: false, message: "Data tidak valid." };
    }
    if (!payload.penerimaPBT || payload.penerimaPBT.toString().trim() === "") {
      return { success: false, message: "Penerima PBT wajib diisi." };
    }
    if (!payload.keterangan || payload.keterangan.toString().trim() === "") {
      return { success: false, message: "Keterangan Maker wajib diisi." };
    }
    if (!payload.noPBT || !payload.namaPencetak || !payload.tanggalCetak || !payload.uraian) {
      return { success: false, message: "Harap lengkapi seluruh kolom yang wajib diisi." };
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.tanggalCetak)) {
      return { success: false, message: "Format Tanggal Cetak tidak valid." };
    }

    const lock = LockService.getScriptLock();
    if (!lock.tryLock(10000)) {
      return { success: false, message: "Server sibuk, silakan coba lagi." };
    }

    try {
      const ss = getSS();
      if (!ss) return { success: false, message: "Spreadsheet tidak ditemukan." };

      let sheet = ss.getSheetByName(SHEET_PBT);
      if (!sheet) {
        sheet = ss.insertSheet(SHEET_PBT);
        sheet.appendRow([
          "ID", "NoPBT", "UnitKerja", "Nama Pencetak", "Nominal PBT",
          "TanggalCetak", "WaktuInput", "Uraian", "Status", "Penerima PBT",
          "Keterangan Maker", "WaktuApprove", "Keterangan Approver",
          "Email Penginput"
        ]);
      }

      const id = "PBT-" + Date.now() + "-" + Math.floor(Math.random() * 1000);
      const waktuInput = Utilities.formatDate(new Date(), "Asia/Jakarta", "yyyy-MM-dd HH:mm:ss");

      let unit = sanitizeText_(payload.unitKerja, 30);
      if (unit === "Lainnya") {
        unit = "Lainnya (" + sanitizeText_(payload.unitLainnya, 150) + ")";
      }

      let rawNominal = payload.nominalPBT ? payload.nominalPBT.toString() : "0";
      let cleanNominal = rawNominal.replace(/Rp\s?|[^0-9,]/g, "").replace(",", ".");
      let numericNominal = parseFloat(cleanNominal) || 0;
      if (numericNominal <= 0 || numericNominal > 999999999999) {
        return { success: false, message: "Nominal PBT tidak valid." };
      }

      sheet.appendRow([
        id,
        sanitizeText_(payload.noPBT, 100),
        unit,
        sanitizeText_(payload.namaPencetak, 150),
        numericNominal,
        payload.tanggalCetak,
        waktuInput,
        sanitizeText_(payload.uraian, 2000),
        "In Progress",
        sanitizeText_(payload.penerimaPBT, 150),
        sanitizeText_(payload.keterangan, 1000),
        "",
        "",
        auth.session.email
      ]);

      return { success: true, message: "Data PBT Berhasil Disimpan!" };
    } finally {
      lock.releaseLock();
    }
  } catch (err) {
    Logger.log("Error submitPBT: " + err.message);
    return { success: false, message: "Gagal Simpan." };
  }
}

function getPBTData(token) {
  const auth = requireAuth_(token, null);
  if (auth.error) return auth.error;

  try {
    const ss = getSS();
    if (!ss) return [];

    const sheet = ss.getSheetByName(SHEET_PBT);
    if (!sheet) return [];

    const data = sheet.getDataRange().getValues();
    if (data.length <= 1) return [];

    const rows = data.slice(1);

    return rows.map(row => {
      let tglCetak = row[5];
      let tglFormatted = "";

      if (tglCetak) {
        try {
          tglFormatted = Utilities.formatDate(new Date(tglCetak), "Asia/Jakarta", "yyyy-MM-dd");
        } catch (e) {
          tglFormatted = tglCetak.toString();
        }
      }

      let waktuIn = row[6];
      let waktuInFormatted = "";

      if (waktuIn) {
        try {
          waktuInFormatted = Utilities.formatDate(new Date(waktuIn), "Asia/Jakarta", "yyyy-MM-dd HH:mm:ss");
        } catch (e) {
          waktuInFormatted = waktuIn.toString();
        }
      }

      let waktuApp = row[11];
      let waktuAppFormatted = "-";

      if (waktuApp) {
        try {
          waktuAppFormatted = Utilities.formatDate(new Date(waktuApp), "Asia/Jakarta", "yyyy-MM-dd HH:mm:ss");
        } catch (e) {
          waktuAppFormatted = waktuApp.toString();
        }
      }

      return {
        id: row[0],
        noPBT: displayText_(row[1]),
        unitKerja: displayText_(row[2]),
        namaPencetak: displayText_(row[3]) || "-",
        nominalPBT: row[4] || 0,
        tanggalCetak: tglFormatted,
        waktuInput: waktuInFormatted,
        uraian: displayText_(row[7]),
        status: row[8],
        penerimaPBT: displayText_(row[9]) || "-",
        keteranganMaker: displayText_(row[10]) || "-",
        waktuApprove: waktuAppFormatted,
        keteranganApprover: displayText_(row[12]) || "-",
        emailPenginput: row[13] || "-"
      };
    }).reverse();
  } catch (err) {
    Logger.log("Error getPBTData: " + err.message);
    return [];
  }
}

function updateStatusPBT(token, idList, status, ketRejectMap) {
  const auth = requireAuth_(token, ["PUR"]);
  if (auth.error) return auth.error;

  try {
    if (!Array.isArray(idList) || idList.length === 0) {
      return { success: false, message: "Tidak ada data yang dipilih." };
    }
    if (status !== "Approve" && status !== "Reject") {
      return { success: false, message: "Status tidak valid." };
    }

    const lock = LockService.getScriptLock();
    if (!lock.tryLock(15000)) {
      return { success: false, message: "Server sibuk, silakan coba lagi." };
    }

    try {
      const ss = getSS();
      if (!ss) return { success: false, message: "Spreadsheet tidak ditemukan." };

      const sheet = ss.getSheetByName(SHEET_PBT);
      if (!sheet) return { success: false, message: "Sheet PBTData belum ditemukan." };

      const data = sheet.getDataRange().getValues();
      const now = Utilities.formatDate(new Date(), "Asia/Jakarta", "yyyy-MM-dd HH:mm:ss");
      let updated = 0;

      for (let i = 1; i < data.length; i++) {
        const rowId = data[i][0];
        const currentStatus = data[i][8];

        if (idList.includes(rowId) && currentStatus === "In Progress") {
          sheet.getRange(i + 1, 9).setValue(status);
          sheet.getRange(i + 1, 12).setValue(now);

          if (status === "Reject" && ketRejectMap && ketRejectMap[rowId]) {
            sheet.getRange(i + 1, 13).setValue(sanitizeText_(ketRejectMap[rowId], 1000));
          }
          if (status === "Approve") {
            sheet.getRange(i + 1, 13).setValue("");
          }
          updated++;
        }
      }

      if (updated === 0) {
        return { success: false, message: "Tidak ada data yang diperbarui (mungkin sudah diproses sebelumnya)." };
      }

      return { success: true, message: updated + " data berhasil diperbarui!" };
    } finally {
      lock.releaseLock();
    }
  } catch (err) {
    Logger.log("Error updateStatusPBT: " + err.message);
    return { success: false, message: "Gagal Update." };
  }
}
