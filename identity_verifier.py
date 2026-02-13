import subprocess

class IdentityVerifier:
    def __init__(self):
        self.high_trust_publishers = ["Microsoft Corporation", "GitHub, Inc."]

    def get_publisher(self, file_path):
        try:
            cmd = f'powershell.exe "(Get-AuthenticodeSignature \'{file_path}\').SignerCertificate.Subject"'
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            if "CN=" in result:
                return result.split("CN=")[1].split(",")[0]
            return "Unknown"
        except Exception:
            return "Unsigned"

    def is_trusted(self, file_path):
        publisher = self.get_publisher(file_path)
        return publisher in self.high_trust_publishers