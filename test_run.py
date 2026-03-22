import cryp_hpke

def test_hpke_pair():
    """Test that seal and open work together"""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    
    # Generate a key pair
    skR = X25519PrivateKey.generate()
    pkR = skR.public_key()
    
    # Test data
    info = b"MLS 1.0 external init secret"
    plaintext = b"Hello, this is a test secret"
    
    # Seal
    kem_output, ciphertext = cryp_hpke.simple_hpke_seal(pkR, info, plaintext)
    print(f"Seal successful: kem_output={len(kem_output)}, ciphertext={len(ciphertext)}")
    
    # Open
    try:
        decrypted = cryp_hpke.simple_hpke_open(skR, info, kem_output, ciphertext)
        print(f"Open successful: {decrypted}")
        assert decrypted == plaintext
        print("✅ HPKE pair works correctly!")
        return True
    except Exception as e:
        print(f"❌ Open failed: {e}")
        return False
if __name__ == "__main__":    
    test_hpke_pair()