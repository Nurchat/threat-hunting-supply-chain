import hashlib

def calculate_sha256(data: bytes) -> str:
    """Calculates the SHA-256 hash of a data block."""
    return hashlib.sha256(data).hexdigest()

def verify_artifact_blocks(expected_manifest: dict, received_blocks: dict):
    """
    Verifies received artifact chunks against the authoritative manifest.
    Simulates detection of poisoned/tampered supply chain components.
    """
    print("[*] Initiating Software Artifact Integrity Verification...\n")
    compromised_blocks = []

    for block_id, expected_hash in expected_manifest.items():
        received_data = received_blocks.get(block_id)
        if not received_data:
            print(f"[!] Alert: Missing artifact chunk: {block_id}")
            continue

        computed_hash = calculate_sha256(received_data)
        if computed_hash == expected_hash:
            print(f"[+] {block_id}: PASSED (Hash: {computed_hash[:16]}...)")
        else:
            print(f"[-] {block_id}: COMPROMISED!")
            print(f"    Expected: {expected_hash}")
            print(f"    Computed: {computed_hash}")
            compromised_blocks.append((block_id, computed_hash))

    print("\n" + "="*50)
    if compromised_blocks:
        print(f"[ALERT] Supply Chain Tampering Detected in {len(compromised_blocks)} block(s)!")
        for b_id, b_hash in compromised_blocks:
            print(f"  -> Flagged IOC (Poisoned Hash): {b_hash} ({b_id})")
    else:
        print("[SUCCESS] All artifact blocks verified successfully. No tampering detected.")

if __name__ == "__main__":
    # Simulated legitimate build manifest
    sample_manifest = {
        "block_01": calculate_sha256(b"library_core_binary_v1.0.0"),
        "block_02": calculate_sha256(b"library_dependencies_manifest"),
        "block_03": calculate_sha256(b"library_installer_script"),
    }

    # Simulated incoming data with block_03 poisoned by an adversary
    sample_download = {
        "block_01": b"library_core_binary_v1.0.0",
        "block_02": b"library_dependencies_manifest",
        "block_03": b"library_installer_script_WITH_INJECTED_BACKDOOR",
    }

    verify_artifact_blocks(sample_manifest, sample_download)
