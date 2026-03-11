import base64

# Your group ID from the error
group_id_b64 = "7ULRxjp1EZuKWBNvcm422g=="

# Decode and check length
group_id_bytes = base64.b64decode(group_id_b64)
print(f"Length: {len(group_id_bytes)} bytes")  # Should be 16
print(f"Hex: {group_id_bytes.hex()}")          # Should be 32 chars
print(f"Base64: {group_id_b64}")

# This should output:
# Length: 16 bytes
# Hex: ed42d1c63a75119b8a58136f726e36da
# Base64: 7ULRxjp1EZuKWBNvcm422g==