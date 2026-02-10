from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os


class CryptoManager:
    """
    Handles all cryptographic operations:
    ✅ Hybrid Encryption: RSA for key exchange + AES for data encryption
    ✅ Digital Signatures: RSA-based signing of hashed data
    ✅ Hashing: SHA-256 for data integrity

    FIXED:
    ✅ Prevents RSA key format error by checking if key files are empty/invalid.
    """

    def __init__(self):
        self.key_size = 2048
        self.aes_key_size = 32  # AES-256 = 32 bytes

        # Load or generate RSA key pair
        self.private_key, self.public_key = self._load_or_generate_keys()

        # Load or generate AES key
        self.aes_key = self._get_aes_key()

    def _load_or_generate_keys(self):
        """
        Load or generate RSA key pair for digital signatures.
        SECURITY: RSA key generation and management.
        FIX: Handles empty/invalid PEM files safely.
        """
        key_dir = "crypto"
        os.makedirs(key_dir, exist_ok=True)

        private_key_path = os.path.join(key_dir, "private_key.pem")
        public_key_path = os.path.join(key_dir, "public_key.pem")

        # ✅ Load only if file exists AND NOT empty
        if (
            os.path.exists(private_key_path)
            and os.path.exists(public_key_path)
            and os.path.getsize(private_key_path) > 0
            and os.path.getsize(public_key_path) > 0
        ):
            try:
                with open(private_key_path, "rb") as f:
                    private_key = RSA.import_key(f.read())

                with open(public_key_path, "rb") as f:
                    public_key = RSA.import_key(f.read())

                return private_key, public_key

            except ValueError:
                print("⚠️ Invalid RSA key files detected. Regenerating keys...")

        # ✅ Generate new RSA keys
        key = RSA.generate(self.key_size)
        private_key = key
        public_key = key.publickey()

        # ✅ Save keys
        with open(private_key_path, "wb") as f:
            f.write(private_key.export_key())

        with open(public_key_path, "wb") as f:
            f.write(public_key.export_key())

        print("✅ New RSA keys generated successfully!")

        return private_key, public_key

    def _get_aes_key(self):
        """
        Get or generate AES-256 key for symmetric encryption.
        SECURITY: AES key management.
        FIX: Validates key length before loading.
        """
        key_dir = "crypto"
        os.makedirs(key_dir, exist_ok=True)

        key_path = os.path.join(key_dir, "aes_key.bin")

        # ✅ Load AES key only if it exists and length matches expected
        if os.path.exists(key_path) and os.path.getsize(key_path) == self.aes_key_size:
            with open(key_path, "rb") as f:
                return f.read()

        # ✅ Generate new AES key
        aes_key = get_random_bytes(self.aes_key_size)

        with open(key_path, "wb") as f:
            f.write(aes_key)

        print("✅ New AES key generated successfully!")

        return aes_key

    def encrypt_data(self, plaintext):
        """
        Encrypt data using AES-256 (CBC mode).
        SECURITY: Symmetric encryption of sensitive data.
        Returns: Base64 ciphertext with IV prepended.
        """
        if plaintext is None:
            return None

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # Random IV for each encryption
        iv = get_random_bytes(16)

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        return base64.b64encode(iv + ciphertext).decode("utf-8")

    def decrypt_data(self, encrypted_data):
        """
        Decrypt AES-256 encrypted data.
        SECURITY: Symmetric decryption.
        """
        if encrypted_data is None:
            return None

        encrypted_bytes = base64.b64decode(encrypted_data)

        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext.decode("utf-8")

    def hash_data(self, data):
        """
        Create SHA-256 hash of data.
        SECURITY: Cryptographic hashing for integrity.
        """
        if data is None:
            return None

        if isinstance(data, str):
            data = data.encode("utf-8")

        return hashlib.sha256(data).hexdigest()

    def sign_data(self, data_hash):
        """
        Create digital signature using RSA private key.
        SECURITY: RSA-based digital signature for integrity + authenticity.
        """
        if data_hash is None:
            return None

        h = SHA256.new(data_hash.encode("utf-8"))
        signature = pkcs1_15.new(self.private_key).sign(h)

        return base64.b64encode(signature).decode("utf-8")

    def verify_signature(self, data_hash, signature):
        """
        Verify digital signature using RSA public key.
        SECURITY: Signature verification for authenticity + integrity.
        """
        if data_hash is None or signature is None:
            return False

        try:
            signature_bytes = base64.b64decode(signature)
            h = SHA256.new(data_hash.encode("utf-8"))
            pkcs1_15.new(self.public_key).verify(h, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt_with_rsa(self, data):
        """
        Encrypt small data with RSA public key (for key exchange demo).
        SECURITY: RSA encryption (OAEP).
        """
        from Crypto.Cipher import PKCS1_OAEP

        if data is None:
            return None

        if isinstance(data, str):
            data = data.encode("utf-8")

        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted = cipher.encrypt(data)

        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_with_rsa(self, encrypted_data):
        """
        Decrypt RSA encrypted data using private key.
        SECURITY: RSA decryption (OAEP).
        """
        from Crypto.Cipher import PKCS1_OAEP

        if encrypted_data is None:
            return None

        cipher = PKCS1_OAEP.new(self.private_key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted = cipher.decrypt(encrypted_bytes)

        return decrypted.decode("utf-8")

    def demonstrate_key_exchange(self):
        """
        Demonstrate Hybrid Encryption Model:
        1) Generate session AES key
        2) Encrypt session key with RSA public key
        3) Use AES for data encryption

        SECURITY: Key exchange + encryption demo.
        """
        session_key = get_random_bytes(32)
        encrypted_session_key = self.encrypt_with_rsa(session_key)

        return {
            "session_key": base64.b64encode(session_key).decode("utf-8"),
            "encrypted_session_key": encrypted_session_key,
            "method": "RSA-2048 for key exchange, AES-256-CBC for data encryption",
        }
