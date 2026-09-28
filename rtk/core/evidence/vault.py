"""Evidence Vault: AES-GCM encryption with scrypt KDF."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_SECRET = os.getenv("RTK_MASTER_SECRET", "default-insecure-secret-change-me-in-prod")


class EvidenceVault:
    def __init__(self, base_path: Path = Path("./rtk_vault")):
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._keys: dict[str, bytes] = {}

    def _derive_key(self, mission_id: str) -> bytes:
        if mission_id not in self._keys:
            salt = mission_id.encode("utf-8")
            key = hashlib.scrypt(
                MASTER_SECRET.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=0, dklen=32
            )
            self._keys[mission_id] = key
        return self._keys[mission_id]

    def store(self, mission_id: str, data: bytes) -> str:
        evidence_ref = str(uuid.uuid4())
        key = self._derive_key(mission_id)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        file_path = self.base_path / f"{mission_id}_{evidence_ref}.enc"
        file_path.write_bytes(nonce + ciphertext)
        return evidence_ref

    def retrieve(self, mission_id: str, evidence_ref: str, key: bytes | None = None) -> bytes:
        if key is None:
            key = self._derive_key(mission_id)

        file_path = self.base_path / f"{mission_id}_{evidence_ref}.enc"
        if not file_path.exists():
            raise FileNotFoundError(f"Evidence {evidence_ref} not found for mission {mission_id}")

        payload = file_path.read_bytes()
        nonce, ciphertext = payload[:12], payload[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def purge(self, mission_id: str) -> None:
        """Supprime la clé de la mémoire, rendant les blobs irrécupérables."""
        if mission_id in self._keys:
            del self._keys[mission_id]
