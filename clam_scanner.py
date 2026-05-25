import yara
import os


def load_rules():
    # Buraya indirdiğin klasörün yolunu yaz (Örn: C:/Aegis/kurallar)
    rules_dir = "C:/Users/User/Desktop/signature-base-master/yara"

    rule_files = {}
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                # Dosya ismi çakışmaması için tam yolu anahtar yapıyoruz
                label = file.replace(".", "_")
                rule_files[label] = os.path.join(root, file)

    # Hepsini tek bir 'beyin' haline getir
    return yara.compile(filepaths=rule_files)


# Program başlarken kuralları bir kez yükle
try:
    scanner_brain = load_rules()
    print("Sistem Hazır: Binlerce kural yüklendi!")
except Exception as e:
    print(f"Kural Hatası: {e}")
    scanner_brain = None


def scan_file(path):
    if not scanner_brain: return False, "Hata"

    matches = scanner_brain.match(path)
    if matches:
        return True, f"Tehdit: {matches[0].rule}"
    return False, None