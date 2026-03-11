# encrypted_message_proper.py
import sys
import secrets
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\frontend_mls\mls_stuff")

from mls_stuff.MLS import (
    FramedContent, FramedContentAuthData, AuthenticatedContent,
    PrivateMessage, MLSMessage, Sender
)
from mls_stuff.Enums import ContentType, SenderType, WireFormat, CipherSuite
from mls_stuff.Misc import VLBytes
from mls_stuff.Crypto._derive_secrets import DeriveSecret

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

def get_message_encryption_key(group, epoch_secret: bytes):
    """
    Derive the message encryption key for the current epoch
    """
    print(f"\n🔑 Deriving message encryption key for epoch {group['epoch']}")
    
    # Derive the message key from epoch secret
    # In MLS, this would be more complex with ratchets
    message_key = DeriveSecret(
        cs,
        epoch_secret,
        b"MLS 1.0 message key"
    )
    
    print(f"   Message key (first 16): {message_key[:16].hex()}...")
    return message_key

def encrypt_message_content(content_bytes: bytes, key: bytes):
    """
    Encrypt content using AES-GCM
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Generate random nonce (12 bytes for AES-GCM)
    nonce = secrets.token_bytes(12)
    
    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, content_bytes, b"")
    
    return ciphertext, nonce

def decrypt_message_content(ciphertext: bytes, nonce: bytes, key: bytes):
    """
    Decrypt content using AES-GCM
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, b"")
    return plaintext

def send_encrypted_message(group, sender_leaf_index: int, message_text: str, epoch_secret: bytes):
    """
    Send an ENCRYPTED message using PrivateMessage
    """
    print(f"\n=== Sending ENCRYPTED message from leaf {sender_leaf_index} ===")
    
    # 1. Convert message to bytes
    message_bytes = message_text.encode('utf-8')
    print(f"   Plaintext: '{message_text}' ({len(message_bytes)} bytes)")
    
    # 2. Create FramedContent (this will be encrypted)
    sender = Sender(sender_type=SenderType.member, leaf_index=sender_leaf_index)
    
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message_bytes)
    )
    
    # Serialize the content to be encrypted
    content_bytes = framed_content.serialize()
    print(f"   Content to encrypt: {len(content_bytes)} bytes")
    
    # 3. Get encryption key
    msg_key = get_message_encryption_key(group, epoch_secret)
    
    # 4. Encrypt the content
    ciphertext, nonce = encrypt_message_content(content_bytes, msg_key)
    print(f"   Encrypted: {len(ciphertext)} bytes")
    print(f"   Nonce: {nonce.hex()}")
    
    # 5. Create PrivateMessage using the signature we found
    private_message = PrivateMessage(
        group_id=group["group_id"],
        epoch=group["epoch"],
        content_type=ContentType.application,
        authenticated_data=VLBytes(b""),  # Empty AAD
        encrypted_sender_data=VLBytes(b""),  # No sender data encryption for now
        ciphertext=VLBytes(ciphertext)  # The encrypted content
    )
    
    # 6. Wrap in MLSMessage
    mls_message = MLSMessage(
        wire_format=WireFormat.MLS_PRIVATE_MESSAGE,
        msg_content=private_message
    )
    
    print(f"✅ PrivateMessage created")
    print(f"   Total size: {len(mls_message.serialize())} bytes")
    
    # Return both the message and the nonce (needed for decryption)
    # In real MLS, nonce would be derived, not sent separately
    return mls_message, nonce

def receive_encrypted_message(group, message: MLSMessage, nonce: bytes, 
                             expected_sender_index: int, epoch_secret: bytes):
    """
    Receive and decrypt an encrypted PrivateMessage
    """
    print("\n=== Receiving ENCRYPTED message ===")
    
    # 1. Verify it's a private message
    if message.wire_format != WireFormat.MLS_PRIVATE_MESSAGE:
        print("❌ Not a private message")
        return None
    
    # 2. Extract PrivateMessage
    private_msg = message.msg_content
    if not isinstance(private_msg, PrivateMessage):
        print("❌ Not a PrivateMessage")
        return None
    
    print(f"   PrivateMessage details:")
    print(f"     - Group ID: {private_msg.group_id.data.hex()[:16]}...")
    print(f"     - Epoch: {private_msg.epoch}")
    print(f"     - Content type: {private_msg.content_type}")
    print(f"     - Ciphertext size: {len(private_msg.ciphertext.data)} bytes")
    
    # 3. Verify epoch
    if private_msg.epoch != group["epoch"]:
        print(f"❌ Epoch mismatch: expected {group['epoch']}, got {private_msg.epoch}")
        return None
    
    # 4. Get decryption key
    msg_key = get_message_encryption_key(group, epoch_secret)
    
    # 5. Decrypt the ciphertext
    try:
        plaintext = decrypt_message_content(
            private_msg.ciphertext.data, 
            nonce, 
            msg_key
        )
        print(f"   Decrypted: {len(plaintext)} bytes")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return None
    
    # 6. Parse the FramedContent
    try:
        framed_content = FramedContent.deserialize(bytearray(plaintext))
        print(f"   Successfully parsed FramedContent")
    except Exception as e:
        print(f"❌ Failed to parse FramedContent: {e}")
        return None
    
    # 7. Verify sender
    if framed_content.sender.leaf_index != expected_sender_index:
        print(f"❌ Sender mismatch: expected {expected_sender_index}, got {framed_content.sender.leaf_index}")
        return None
    
    # 8. Extract message text
    if hasattr(framed_content, 'application_data'):
        message_text = framed_content.application_data.data.decode('utf-8')
        print(f"✅ Message received: '{message_text}'")
        return message_text
    else:
        print(f"✅ Decrypted but no application data found")
        return None

# Simple test function
def test_encrypted_message(group, alice_index, bob_index, epoch_secret):
    """
    Test encrypted message exchange between Alice and Bob
    """
    print("\n" + "="*60)
    print("TESTING ENCRYPTED MESSAGE EXCHANGE")
    print("="*60)
    
    # Bob sends encrypted message to Alice
    print("\n📤 Bob sending encrypted message...")
    bob_msg, nonce = send_encrypted_message(
        group, 
        bob_index, 
        "Hello Alice! This is an ENCRYPTED message!", 
        epoch_secret
    )
    
    # Alice receives and decrypts
    print("\n📥 Alice receiving encrypted message...")
    received = receive_encrypted_message(
        group, 
        bob_msg, 
        nonce, 
        bob_index, 
        epoch_secret
    )
    
    # Alice replies
    print("\n📤 Alice sending encrypted reply...")
    alice_msg, nonce2 = send_encrypted_message(
        group, 
        alice_index, 
        "Hi Bob! I can read your secret message!", 
        epoch_secret
    )
    
    # Bob receives
    print("\n📥 Bob receiving encrypted reply...")
    received2 = receive_encrypted_message(
        group, 
        alice_msg, 
        nonce2, 
        alice_index, 
        epoch_secret
    )
    
    print("\n✅ Encrypted message exchange complete!")