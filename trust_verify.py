import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- PART 1: HASHING AND LOCAL INTEGRITY ---

def generate_file_hash(file_path):
    """Herhangi bir dosya için SHA-256 hash üretir[cite: 8]."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_manifest(directory_path):
    """Dizindeki dosyaları tarar ve metadata.json oluşturur[cite: 9]."""
    manifest = {}
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path) and filename != "metadata.json" and not filename.endswith(".pem") and not filename.endswith(".sig"):
            manifest[filename] = generate_file_hash(file_path)
    
    with open("metadata.json", "w") as f:
        json.dump(manifest, f, indent=4)
    print("-> Manifest (metadata.json) oluşturuldu.")

def check_integrity(directory_path):
    """Dosyaları metadata.json ile karşılaştırıp modifikasyonları tespit eder[cite: 10]."""
    if not os.path.exists("metadata.json"):
        print("Hata: metadata.json bulunamadı!")
        return
    with open("metadata.json", "r") as f:
        old_manifest = json.load(f)
    
    tampered = []
    for filename, old_hash in old_manifest.items():
        file_path = os.path.join(directory_path, filename)
        if os.path.exists(file_path):
            if generate_file_hash(file_path) != old_hash:
                tampered.append(filename)
    
    if tampered:
        print(f"!!! UYARI: Şu dosyalar kurcalanmış: {tampered}")
    else:
        print("✓ Bütünlük doğrulandı: Dosyalar orijinal.")

# --- PART 2: DIGITAL SIGNATURES (RSA) ---

def generate_keys():
    """Kullanıcı için RSA Kamu/Özel anahtar çifti üretir[cite: 12]."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("-> RSA Anahtarları üretildi (private_key.pem, public_key.pem).")

def sign_manifest():
    """metadata.json'ın hash'ini Özel Anahtar ile imzalar[cite: 13]."""
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    
    # metadata.json dosyasının içeriğini oku
    with open("metadata.json", "rb") as f:
        manifest_data = f.read()
    
    signature = private_key.sign(
        manifest_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("-> Manifest dijital olarak imzalandı (signature.sig).")

def verify_signature():
    """Manifestin göndericiden geldiğini Kamu Anahtarı ile doğrular[cite: 14]."""
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    with open("metadata.json", "rb") as f:
        manifest_data = f.read()
    with open("signature.sig", "rb") as f:
        signature = f.read()
    
    try:
        public_key.verify(
            signature,
            manifest_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("✓ İmza Doğrulandı: Manifest güvenilir göndericiden geliyor ve değiştirilmemiş.")
    except Exception:
        print("!!! İMZA DOĞRULAMASI BAŞARISIZ: Veri sahte veya bozulmuş olabilir!")

# --- TEST SENARYOSU ---
if __name__ == "__main__":
    folder = "test_folder"
    if not os.path.exists(folder): os.makedirs(folder)
    
    print("--- TrustVerify CLI Başlatılıyor ---")
    generate_keys() # Task 4
    create_manifest(folder) # Task 2
    sign_manifest() # Task 5
    
    print("\n--- İlk Kontrol ---")
    check_integrity(folder) # Task 3
    verify_signature() # Task 6