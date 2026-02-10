import base64
import qrcode
from io import BytesIO

class EncodingManager:
    """
    Handles encoding and decoding operations
    
    SECURITY: Implements Base64 encoding for QR tokens
    - Base64 encoding/decoding
    - Optional: QR code generation
    """
    
    def __init__(self):
        pass
    
    def encode_base64(self, data):
        """
        Encode data to Base64
        
        Args:
            data: String or bytes to encode
        
        Returns:
            str: Base64 encoded string
        
        SECURITY: Base64 encoding for token transmission
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encoded = base64.b64encode(data)
        return encoded.decode('utf-8')
    
    def decode_base64(self, encoded_data):
        """
        Decode Base64 encoded data
        
        Args:
            encoded_data: Base64 encoded string
        
        Returns:
            str: Decoded string
        
        SECURITY: Base64 decoding for token verification
        """
        if isinstance(encoded_data, str):
            encoded_data = encoded_data.encode('utf-8')
        
        decoded = base64.b64decode(encoded_data)
        return decoded.decode('utf-8')
    
    def generate_qr_code(self, data):
        """
        Generate QR code image from data
        
        Args:
            data: String data to encode in QR code
        
        Returns:
            BytesIO: QR code image as BytesIO object
        
        BONUS FEATURE: QR code generation
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to BytesIO
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        return img_io
    
    def qr_to_base64(self, data):
        """
        Generate QR code and return as Base64 string
        
        Args:
            data: String data to encode
        
        Returns:
            str: Base64 encoded QR code image
        """
        img_io = self.generate_qr_code(data)
        img_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{img_base64}"
    
    def encode_url_safe(self, data):
        """
        URL-safe Base64 encoding
        
        Args:
            data: String or bytes to encode
        
        Returns:
            str: URL-safe Base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encoded = base64.urlsafe_b64encode(data)
        return encoded.decode('utf-8')
    
    def decode_url_safe(self, encoded_data):
        """
        Decode URL-safe Base64 data
        
        Args:
            encoded_data: URL-safe Base64 encoded string
        
        Returns:
            str: Decoded string
        """
        if isinstance(encoded_data, str):
            encoded_data = encoded_data.encode('utf-8')
        
        decoded = base64.urlsafe_b64decode(encoded_data)
        return decoded.decode('utf-8')
    
    def demonstrate_encoding(self, sample_text="Secure Hostel Visitor Pass"):
        """
        Demonstrate encoding techniques
        
        Returns:
            dict: Examples of different encoding methods
        """
        return {
            'original': sample_text,
            'base64': self.encode_base64(sample_text),
            'url_safe_base64': self.encode_url_safe(sample_text),
            'description': 'Base64 encoding used for secure token transmission'
        }