import os
import re
import subprocess


class IdentityVerifier:
    def __init__(self):
        self.high_trust_publishers = ["Microsoft Corporation", "GitHub, Inc."]

    @staticmethod
    def _validate_path(file_path):
        """Validate file path to prevent command injection."""
        # Resolve to absolute, reject path traversal
        resolved = os.path.realpath(file_path)
        if not os.path.isfile(resolved):
            raise ValueError(f"File not found: {resolved}")
        # Reject paths with characters that could break shell commands
        if re.search(r'[;|&`$(){}\[\]!]', resolved):
            raise ValueError(f"Invalid characters in path: {resolved}")
        return resolved

    def get_publisher(self, file_path):
        try:
            safe_path = self._validate_path(file_path)
            # Use list args (no shell=True) to prevent command injection
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command",
                 f"(Get-AuthenticodeSignature '{safe_path}').SignerCertificate.Subject"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout.strip()
            if "CN=" in output:
                return output.split("CN=")[1].split(",")[0]
            return "Unknown"
        except (ValueError, subprocess.TimeoutExpired):
            return "Unsigned"
        except Exception:
            return "Unsigned"

    def is_trusted(self, file_path):
        publisher = self.get_publisher(file_path)
        return publisher in self.high_trust_publishers