# DES Implementation Lengkap — Final Version
# Kelompok Anti-Error — Matkul Keamanan Informasi

# ============================================
# TABEL-TABEL DES
# ============================================

IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

IP_INV = [40,8,48,16,56,24,64,32,
          39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30,
          37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28,
          35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26,
          33,1,41,9,49,17,57,25]

E = [32,1,2,3,4,5,
     4,5,6,7,8,9,
     8,9,10,11,12,13,
     12,13,14,15,16,17,
     16,17,18,19,20,21,
     20,21,22,23,24,25,
     24,25,26,27,28,29,
     28,29,30,31,32,1]

P = [16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
     19,13,30,6,22,11,4,25]

PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,
       15,6,21,10,23,19,12,4,
       26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,
       34,53,46,42,50,36,29,32]

SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ============================================
# 8 S-BOX LENGKAP
# ============================================

SBOX = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# ============================================
# A. FUNGSI UTILITAS — bits_to_hex() DIPERBAIKI
# ============================================

def permute(block, table):
    """Permutasi bit sesuai tabel"""
    return [block[i-1] for i in table]

def xor(a, b):
    """XOR dua list bit"""
    return [x ^ y for x, y in zip(a, b)]

def bytes_to_bits(data: bytes) -> list:
    """
    Konversi bytes ke list bit.
    Digunakan untuk plaintext dan key (UTF-8 bytes).
    """
    bits = []
    for byte in data:
        bits.extend((byte >> (7 - i)) & 1 for i in range(8))
    return bits

def bits_to_bytes(bits: list) -> bytes:
    """
    Konversi list bit ke bytes.
    Digunakan setelah dekripsi sebelum decode ke string.
    """
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)

def bits_to_hex(bits: list) -> str:
    """
    A. PERBAIKAN: Konversi bit ke HEX dengan panjang tetap.
    Setiap blok 64 bit menghasilkan tepat 16 digit HEX.
    Ciphertext dua blok → 32 digit HEX (tidak ada digit yang hilang).

    Input kosong (list bit kosong) menghasilkan string kosong,
    bukan error — supaya pemanggil tidak perlu cek panjang dulu
    sebelum memanggil fungsi ini.
    """
    if not bits:
        return ""

    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("Data hanya boleh berisi bit 0 atau 1.")

    if len(bits) % 4 != 0:
        raise ValueError("Panjang bit harus kelipatan 4.")

    hex_digits = len(bits) // 4
    value = int(''.join(map(str, bits)), 2)

    return f"{value:0{hex_digits}X}"

# ============================================
# C. VALIDASI ASCII + PADDING BERBASIS BYTES
# ============================================

def validate_ascii(text: str, label: str = "Input") -> bytes:
    """
    C. Pilihan sederhana: batasi plaintext dan key pada ASCII.
    Validasi setiap karakter dalam rentang ASCII (0-127).
    Kembalikan bytes untuk diproses lebih lanjut.
    """
    try:
        encoded = text.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError(
            f"[!] {label} mengandung karakter non-ASCII. "
            f"Gunakan hanya karakter ASCII (huruf, angka, simbol standar)."
        )
    return encoded

def validate_and_pad_key(key: str) -> bytes:
    """
    Validasi key: hanya ASCII, panjang 1-8 byte.
    - Kurang dari 8 byte: padding null byte di kanan
    - Lebih dari 8 byte: truncate + warning
    Kembalikan bytes 8 byte siap pakai.
    """
    if not key:
        raise ValueError("[!] Key tidak boleh kosong!")

    key_bytes = validate_ascii(key, "Key")

    if len(key_bytes) > 8:
        print(f"[!] WARNING: Key terlalu panjang ({len(key_bytes)} byte), "
              f"dipotong ke 8 byte.")
        key_bytes = key_bytes[:8]
    elif len(key_bytes) < 8:
        pad_count = 8 - len(key_bytes)
        print(f"[!] WARNING: Key kurang dari 8 byte, "
              f"ditambahkan {pad_count} null byte.")
        key_bytes = key_bytes + b'\x00' * pad_count

    return key_bytes

def validate_and_pad_plaintext(text: str) -> bytes:
    """
    Validasi plaintext: hanya ASCII.
    Padding PKCS#7 berbasis bytes:
    - pad_len = 8 - (len_bytes % 8), minimal 1
    - Tambahkan pad_len byte bernilai pad_len
    - Jika panjang tepat kelipatan 8: tambah blok padding penuh (8 byte x \\x08)
    """
    if not text:
        raise ValueError("[!] Plaintext tidak boleh kosong!")

    text_bytes = validate_ascii(text, "Plaintext")

    pad_len = 8 - (len(text_bytes) % 8)
    padded = text_bytes + bytes([pad_len] * pad_len)

    print(f"[+] Plaintext asli    : '{text}' ({len(text_bytes)} byte)")
    print(f"[+] Padding PKCS#7    : {pad_len} byte (nilai: 0x{pad_len:02X})")
    print(f"[+] Plaintext padded  : {len(padded)} byte ({len(padded)//8} blok)")

    return padded

def remove_padding(data: bytes) -> bytes:
    """
    Validasi dan hapus padding PKCS#7.

    Sengaja dibuat strict: padding yang tidak valid memunculkan error,
    bukan diam-diam mengembalikan data apa adanya. Kalau dibiarkan
    permisif, ciphertext yang rusak atau key yang salah bisa terlihat
    "berhasil" didekripsi padahal hasilnya sampah.

    Catatan: ciphertext dengan key yang salah memang bisa menghasilkan
    error padding di sini — itu wajar untuk implementasi ini, tapi
    validasi padding BUKAN cara yang aman untuk mengautentikasi
    ciphertext (bukan pengganti MAC/HMAC pada penggunaan nyata).
    """
    if not data or len(data) % 8 != 0:
        raise ValueError("Data hasil dekripsi tidak valid.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > 8:
        raise ValueError("Padding PKCS#7 tidak valid.")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 tidak valid.")

    return data[:-pad_len]

# ============================================
# FUNGSI KRIPTOGRAFI DES
# ============================================

def generate_subkeys(key_bytes: bytes) -> list:
    """Generate 16 subkey dari key 8 byte"""
    key_bits = bytes_to_bits(key_bytes)

    key_56 = permute(key_bits, PC1)
    C = key_56[:28]
    D = key_56[28:]

    subkeys = []
    for i in range(16):
        shift = SHIFT[i]
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)

    return subkeys

def sbox_substitution(bits_48: list) -> list:
    """
    S-Box substitution: 48 bit → 32 bit
    - Bit pertama & terakhir (bit 0 & 5) → baris (0-3)
    - Bit tengah (bit 1,2,3,4) → kolom (0-15)
    """
    result = []
    for i in range(8):
        chunk = bits_48[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = SBOX[i][row][col]
        result.extend((val >> (3 - b)) & 1 for b in range(4))
    return result

def feistel(R: list, subkey: list) -> list:
    """Fungsi Feistel f(R, K)"""
    R_exp = permute(R, E)
    xored = xor(R_exp, subkey)
    substituted = sbox_substitution(xored)
    return permute(substituted, P)

def des_encrypt_block(block_64bit: list, subkeys: list) -> list:
    """
    Enkripsi satu blok 64 bit.
    Tes: input 0123456789ABCDEF → output 85E813540F0AB405
    """
    bits = permute(block_64bit, IP)
    L, R = bits[:32], bits[32:]

    for i in range(16):
        L, R = R, xor(L, feistel(R, subkeys[i]))

    return permute(R + L, IP_INV)

def des_decrypt_block(block_64bit: list, subkeys: list) -> list:
    """
    Dekripsi satu blok 64 bit (subkey dibalik).
    Tes: input 85E813540F0AB405 → output 0123456789ABCDEF
    """
    bits = permute(block_64bit, IP)
    L, R = bits[:32], bits[32:]

    for subkey in reversed(subkeys):
        L, R = R, xor(L, feistel(R, subkey))

    return permute(R + L, IP_INV)

# ============================================
# ENKRIPSI & DEKRIPSI MULTI-BLOK
# ============================================

def des_encrypt(plaintext: str, key: str) -> list:
    """
    Enkripsi DES multi-blok.
    Plaintext dan key divalidasi ASCII, padding PKCS#7 otomatis.
    """
    key_bytes       = validate_and_pad_key(key)
    padded_bytes    = validate_and_pad_plaintext(plaintext)
    subkeys         = generate_subkeys(key_bytes)

    all_cipher_bits = []
    for i in range(0, len(padded_bytes), 8):
        block_bits  = bytes_to_bits(padded_bytes[i:i+8])
        all_cipher_bits.extend(des_encrypt_block(block_bits, subkeys))

    return all_cipher_bits

def des_decrypt(cipher_bits: list, key: str) -> str:
    """
    Dekripsi DES multi-blok.
    Padding PKCS#7 otomatis dihapus, hasil di-decode sebagai ASCII.

    Memvalidasi sendiri bahwa jumlah bit kelipatan 64 (tidak kosong,
    tidak ada blok setengah) — tidak bergantung pada validasi di
    hex_to_cipher_bits(), karena des_decrypt() bisa dipanggil langsung
    dengan cipher_bits dari sumber lain (mis. pengujian otomatis).
    """
    if not cipher_bits:
        raise ValueError("Ciphertext kosong — tidak ada yang bisa didekripsi.")

    if len(cipher_bits) % 64 != 0:
        raise ValueError(
            f"Jumlah bit ciphertext harus kelipatan 64 "
            f"(sekarang {len(cipher_bits)} bit, blok tidak lengkap)."
        )

    if any(bit not in (0, 1) for bit in cipher_bits):
        raise ValueError("Ciphertext hanya boleh berisi bit 0 atau 1.")

    key_bytes    = validate_and_pad_key(key)
    subkeys      = generate_subkeys(key_bytes)

    all_plain_bits = []
    for i in range(0, len(cipher_bits), 64):
        all_plain_bits.extend(des_decrypt_block(cipher_bits[i:i+64], subkeys))

    plain_bytes = bits_to_bytes(all_plain_bits)
    plain_bytes = remove_padding(plain_bytes)
    return plain_bytes.decode('ascii')

# ============================================
# B. VALIDASI CIPHERTEXT HEX SAAT DEKRIPSI
# ============================================

def hex_to_cipher_bits(cipher_hex: str) -> list:
    """
    B. Konversi HEX string ke list bit dengan validasi lengkap.
    - Strip whitespace dan prefix 0x/0X
    - Pastikan tidak kosong
    - Pastikan panjang kelipatan 16 (satu blok DES = 16 digit HEX)
    - Pastikan karakter valid HEX
    - Konversi via bytes.fromhex() untuk akurasi
    """
    clean_hex = cipher_hex.strip()

    if clean_hex.lower().startswith("0x"):
        clean_hex = clean_hex[2:]

    if not clean_hex:
        raise ValueError("Ciphertext tidak boleh kosong.")

    if len(clean_hex) % 16 != 0:
        raise ValueError(
            f"Ciphertext harus terdiri dari blok 16 digit HEX "
            f"(sekarang {len(clean_hex)} digit)."
        )

    try:
        cipher_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        raise ValueError("Ciphertext mengandung karakter HEX tidak valid.")

    return [
        (byte >> shift) & 1
        for byte in cipher_bytes
        for shift in range(7, -1, -1)
    ]

# ============================================
# TES OTOMATIS — VEKTOR STANDAR DES
# ============================================

def run_self_test():
    """
    Tes otomatis dengan vektor standar DES:
    - Plaintext : 0123456789ABCDEF (sebagai bit, bukan ASCII)
    - Key       : 133457799BBCDFF1 (sebagai bit)
    - Expected  : 85E813540F0AB405
    """
    print("\n" + "="*55)
    print("  TES OTOMATIS — VEKTOR STANDAR DES")
    print("="*55)

    # Plaintext dan key sebagai hex → bytes → bits
    pt_hex  = "0123456789ABCDEF"
    key_hex = "133457799BBCDFF1"

    pt_bytes  = bytes.fromhex(pt_hex)
    key_bytes = bytes.fromhex(key_hex)

    pt_bits = bytes_to_bits(pt_bytes)

    subkeys = generate_subkeys(key_bytes)

    # Enkripsi
    cipher_bits = des_encrypt_block(pt_bits, subkeys)
    cipher_hex  = bits_to_hex(cipher_bits)

    expected = "85E813540F0AB405"
    enc_ok   = (cipher_hex == expected)

    print(f"  Plaintext  : {pt_hex}")
    print(f"  Key        : {key_hex}")
    print(f"  Ciphertext : {cipher_hex}")
    print(f"  Expected   : {expected}")
    print(f"  Enkripsi   : {'PASS' if enc_ok else 'FAIL'}")

    # Dekripsi
    cipher_bits2 = bytes_to_bits(bytes.fromhex(expected))
    plain_bits   = des_decrypt_block(cipher_bits2, subkeys)
    plain_hex    = bits_to_hex(plain_bits)

    dec_ok = (plain_hex == pt_hex)
    print(f"\n  Input decrypt  : {expected}")
    print(f"  Hasil decrypt  : {plain_hex}")
    print(f"  Expected       : {pt_hex}")
    print(f"  Dekripsi       : {'PASS' if dec_ok else 'FAIL'}")

    if enc_ok and dec_ok:
        print("\n  [OK] Semua tes lulus! Implementasi DES valid.")
    else:
        print("\n  [FAIL] Ada tes yang gagal — periksa implementasi.")

    print("="*55)

# ============================================
# TAMPILKAN DETAIL 16 ROUND
# ============================================

def show_round_detail(plaintext: str, key: str):
    """
    Tampilkan nilai L dan R setiap round.
    Menggunakan padding PKCS#7 yang sama dengan des_encrypt(),
    bukan ljust(8) dengan spasi — supaya blok pertama yang ditampilkan
    di sini identik dengan blok pertama yang benar-benar dienkripsi.
    """
    key_bytes    = validate_and_pad_key(key)
    padded_bytes = validate_and_pad_plaintext(plaintext)
    pt_bytes     = padded_bytes[:8]  # blok pertama saja untuk demo round

    subkeys = generate_subkeys(key_bytes)
    bits    = permute(bytes_to_bits(pt_bytes), IP)
    L, R    = bits[:32], bits[32:]

    print(f"\n{'='*55}")
    print(f"  DETAIL 16 ROUND DES")
    print(f"{'='*55}")
    print(f"  Setelah IP:")
    print(f"  L0 = {bits_to_hex(L)}")
    print(f"  R0 = {bits_to_hex(R)}")

    for i in range(16):
        L, R = R, xor(L, feistel(R, subkeys[i]))
        print(f"  Round {i+1:2d}: L={bits_to_hex(L)}  R={bits_to_hex(R)}")

# ============================================
# MENU UTAMA
# ============================================

if __name__ == "__main__":
    print("=" * 55)
    print("  DES ENCRYPTION — Kelompok Anti-Error")
    print("  Matkul Keamanan Informasi")
    print("=" * 55)

    # Jalankan tes otomatis saat startup
    run_self_test()

    while True:
        print("\n[1] Enkripsi")
        print("[2] Dekripsi")
        print("[3] Demo enkripsi + detail round")
        print("[4] Jalankan tes otomatis ulang")
        print("[0] Keluar")

        choice = input("\nPilihan: ").strip()

        if choice == "1":
            plaintext = input("\nMasukkan plaintext (ASCII): ")
            key       = input("Masukkan key (maks 8 karakter ASCII): ")

            print("\n" + "-"*55)
            try:
                cipher_bits = des_encrypt(plaintext, key)
                cipher_hex  = bits_to_hex(cipher_bits)
                print(f"\n[+] KEY            : '{key}'")
                print(f"[+] CIPHERTEXT HEX : {cipher_hex}")
                print(f"[+] CIPHERTEXT BITS: {len(cipher_bits)} bit")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == "2":
            cipher_hex = input("\nMasukkan ciphertext (HEX, tanpa spasi): ")
            key        = input("Masukkan key: ")

            print("\n" + "-"*55)
            try:
                cipher_bits = hex_to_cipher_bits(cipher_hex)
                decrypted   = des_decrypt(cipher_bits, key)
                print(f"\n[+] KEY       : '{key}'")
                print(f"[+] DECRYPTED : '{decrypted}'")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == "3":
            plaintext = input("\nMasukkan plaintext (maks 8 karakter ASCII): ")[:8]
            key       = input("Masukkan key (maks 8 karakter ASCII): ")

            print("\n" + "-"*55)
            try:
                cipher_bits = des_encrypt(plaintext, key)
                cipher_hex  = bits_to_hex(cipher_bits)

                print(f"\n[+] KEY            : '{key}'")
                print(f"[+] CIPHERTEXT HEX : {cipher_hex}")

                show_round_detail(plaintext, key)

                decrypted = des_decrypt(cipher_bits, key)
                print(f"\n[+] DECRYPTED      : '{decrypted}'")
                # Perbandingan exact — spasi di awal/akhir harus ikut cocok,
                # bukan diabaikan lewat strip(), supaya tes benar-benar
                # memastikan teks identik byte per byte.
                print(f"[+] MATCH          : {plaintext == decrypted}")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == "4":
            run_self_test()

        elif choice == "0":
            print("\n[+] Keluar. Terima kasih!")
            break

        else:
            print("[!] Pilihan tidak valid!")