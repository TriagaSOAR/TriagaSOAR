# soc-agent/velociraptor.py
# Velociraptor integration — dispatch hunts and collect endpoint telemetry
import os
import json
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

VELO_API_CONFIG = os.getenv("VELOCIRAPTOR_API_CONFIG", "/app/velociraptor/api.config.yaml")
VELO_ENABLED = os.getenv("VELOCIRAPTOR_ENABLED", "false").lower() == "true"

# Artifacts to collect per investigation type
HUNT_ARTIFACTS = {
    "brute_force": [
        "Linux.Sys.Users",
        "Linux.Sys.LastUserLogin",
        "Linux.Sys.BashHistory",
    ],
    "credential_stuffing": [
        "Linux.Sys.Users",
        "Linux.Sys.LastUserLogin",
    ],
    "lateral_movement": [
        "Linux.Network.NetstatEnriched",
        "Linux.Sys.BashHistory",
        "Linux.Sys.Pslist",
        "Linux.Sys.Crontab",
    ],
    "privilege_escalation": [
        "Linux.Sys.Pslist",
        "Linux.Sys.BashHistory",
        "Linux.Sys.Crontab",
    ],
    "default": [
        "Linux.Sys.Pslist",
        "Linux.Network.Netstat",
    ],
}


def velo_available() -> bool:
    if not VELO_ENABLED:
        return False
    if not os.path.exists(VELO_API_CONFIG):
        logger.warning("Velociraptor API config not found at %s", VELO_API_CONFIG)
        return False
    try:
        import pyvelociraptor
        return True
    except ImportError:
        logger.warning("pyvelociraptor not installed")
        return False


def _get_stub():
    """Get a gRPC stub for the Velociraptor API."""
    import grpc
    import pyvelociraptor.api_pb2_grpc as api_pb2_grpc

    config = pyvelociraptor.LoadConfigFile(VELO_API_CONFIG)

    # Build SSL credentials from the config certs
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )

    channel = grpc.secure_channel(
        config["api_connection_string"],
        creds,
        options=[("grpc.ssl_target_name_override", "localhost")],
    )
    return api_pb2_grpc.APIStub(channel), config


def _run_vql(stub, vql: str) -> list[dict]:
    """Run a VQL query and return results."""
    import pyvelociraptor.api_pb2 as api_pb2
    results = []
    request = api_pb2.VQLCollectorArgs(
        max_wait=30,
        Query=[api_pb2.VQLRequest(VQL=vql)],
    )
    for response in stub.Query(request):
        if response.Response:
            rows = json.loads(response.Response)
            results.extend(rows)
    return results


async def find_client(hostname_or_ip: str) -> Optional[str]:
    """Find a Velociraptor client ID by hostname or IP."""
    if not velo_available():
        return None
    try:
        stub, _ = _get_stub()
        # Search by hostname
        vql = f"SELECT client_id FROM clients() WHERE os_info.hostname =~ '{hostname_or_ip}' OR last_ip =~ '{hostname_or_ip}' LIMIT 1"
        results = await asyncio.to_thread(_run_vql, stub, vql)
        if results:
            return results[0].get("client_id")
    except Exception as e:
        logger.error("Velociraptor find_client error: %s", e)
    return None


async def collect_artifact(
    client_id: str,
    artifact: str,
    parameters: dict = None,
    timeout: int = 120,
) -> list[dict]:
    """Dispatch a collection on a specific client and wait for results."""
    if not velo_available():
        return []
    try:
        stub, _ = _get_stub()

        # Schedule collection
        params_vql = ""
        if parameters:
            params_str = ", ".join(f'{k}="{v}"' for k, v in parameters.items())
            params_vql = f", env=dict({params_str})"

        schedule_vql = f"SELECT collect_client(client_id='{client_id}', artifacts=['{artifact}']{params_vql}).flow_id AS flow_id FROM scope()"
        results = await asyncio.to_thread(_run_vql, stub, schedule_vql)
        if not results:
            return []

        flow_id = results[0].get("flow_id")
        if not flow_id:
            return []

        logger.info("Velociraptor flow %s started on %s for %s", flow_id, client_id, artifact)

        # Poll for completion
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            status_vql = f"SELECT state FROM flows(client_id='{client_id}', flow_id='{flow_id}') LIMIT 1"
            status = await asyncio.to_thread(_run_vql, stub, status_vql)
            if status and status[0].get("state") in ("FINISHED", "ERROR"):
                break
            await asyncio.sleep(5)

        # Pull results
        results_vql = f"SELECT * FROM source(client_id='{client_id}', flow_id='{flow_id}', artifact='{artifact}')"
        return await asyncio.to_thread(_run_vql, stub, results_vql)

    except Exception as e:
        logger.error("Velociraptor collect_artifact error: %s", e)
        return []


async def hunt_host(
    hostname_or_ip: str,
    alert_type: str = "default",
) -> dict:
    """
    High-level: find a host, dispatch relevant artifact collections,
    return structured results for inclusion in an investigation report.
    """
    if not velo_available():
        return {"available": False}

    client_id = await find_client(hostname_or_ip)
    if not client_id:
        logger.info("No Velociraptor client found for %s", hostname_or_ip)
        return {"available": True, "client_found": False, "host": hostname_or_ip}

    artifacts = HUNT_ARTIFACTS.get(alert_type, HUNT_ARTIFACTS["default"])
    collected = {}

    for artifact in artifacts:
        logger.info("Collecting %s from %s (%s)", artifact, hostname_or_ip, client_id)
        results = await collect_artifact(client_id, artifact)
        if results:
            # Truncate to first 20 rows per artifact to keep report size manageable
            collected[artifact] = results[:20]

    return {
        "available": True,
        "client_found": True,
        "client_id": client_id,
        "host": hostname_or_ip,
        "artifacts_collected": list(collected.keys()),
        "results": collected,
    }


async def create_hunt(
    artifact: str,
    description: str = "",
    parameters: dict = None,
) -> Optional[str]:
    """Create a fleet-wide hunt and return the hunt ID."""
    if not velo_available():
        return None
    try:
        stub, _ = _get_stub()
        params_vql = ""
        if parameters:
            params_str = ", ".join(f'{k}="{v}"' for k, v in parameters.items())
            params_vql = f", env=dict({params_str})"

        vql = f"SELECT hunt(description='{description}', artifacts=['{artifact}']{params_vql}).hunt_id AS hunt_id FROM scope()"
        results = await asyncio.to_thread(_run_vql, stub, vql)
        if results:
            hunt_id = results[0].get("hunt_id")
            logger.info("Velociraptor hunt %s created for %s", hunt_id, artifact)
            return hunt_id
    except Exception as e:
        logger.error("Velociraptor create_hunt error: %s", e)
    return None


async def get_clients() -> list[dict]:
    """List all known Velociraptor clients."""
    if not velo_available():
        return []
    try:
        stub, _ = _get_stub()
        vql = "SELECT client_id, os_info.hostname AS hostname, last_ip, os_info.system AS os FROM clients() LIMIT 100"
        return await asyncio.to_thread(_run_vql, stub, vql)
    except Exception as e:
        logger.error("Velociraptor get_clients error: %s", e)
        return []