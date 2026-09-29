"""Abstraction Azure pour le RTK."""
from __future__ import annotations

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource import ResourceManagementClient

from rtk.core.logging import get_logger

log = get_logger("cloud.azure")


def get_azure_blob_client(account_name: str, account_key: str | None = None) -> BlobServiceClient:
    """Retourne un client BlobServiceClient Azure."""
    if account_key:
        conn_str = f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
        return BlobServiceClient.from_connection_string(conn_str)
    else:
        credential = DefaultAzureCredential()
        return BlobServiceClient(
            account_url=f"https://{account_name}.blob.core.windows.net",
            credential=credential
        )


def list_azure_containers(account_name: str, account_key: str | None = None) -> list[str]:
    """Liste les containers Azure Blob Storage."""
    try:
        client = get_azure_blob_client(account_name, account_key)
        return [container.name for container in client.list_containers()]
    except Exception as e:
        log.error("azure_list_containers_failed", extra={"error": str(e)})
        return []


def check_azure_container_public_access(container_url: str) -> bool:
    """Vérifie si un container Azure est accessible anonymement."""
    try:
        client = BlobServiceClient(account_url=container_url)
        # Tenter de lister les blobs sans auth
        list(client.list_blobs())
        return True
    except Exception:
        return False
