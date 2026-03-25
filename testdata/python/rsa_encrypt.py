from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Generate RSA key - QUANTUM VULNERABLE
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

message = b"secret data"

# Encrypt with RSA - vulnerable to Shor's algorithm
ciphertext = private_key.public_key().encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
