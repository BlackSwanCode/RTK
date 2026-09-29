# rtk/modules/audit/mttd_closed_loop.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import boto3
from botocore.exceptions import ClientError

from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.audit.mttd_closed_loop")

def run(
    target: "Target", # Type hint string to avoid circular import if needed, or import Target
    scope: "ScopeDefinition",
    store: FindingsStore,
    mission_id: UUID,
    region: str = "us-east-1",
) -> int:
    from rtk.core.findings.schema import Target, ScopeDefinition # Local import for clarity
    assert_in_scope(target, scope, module="rtk.modules.audit.mttd_closed_loop")
    
    # Récupérer tous les findings simulés de la mission
    findings = store.list(mission_id, filters={"module": None}) # Get all, we filter in python
    simulated_findings = [f for f in findings if f.simulated_attack and f.target.cloud == "aws"]
    
    updated_count = 0
    client = boto3.client("cloudtrail", region_name=region)

    for finding in simulated_findings:
        if finding.mttd is not None:
            continue # Déjà évalué

        # Fenêtre de recherche : de 1h avant le finding à 1h après
        start_time = finding.timestamp_utc - timedelta(hours=1)
        end_time = finding.timestamp_utc + timedelta(hours=1)

        try:
            # Recherche d'événements CloudTrail correspondant au compte et à la fenêtre
            # Dans un cas réel, on utiliserait les correlation_id ou resource_arn du finding
            response = client.lookup_events(
                LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            )
            
            detected = False
            detection_time = None
            
            for event in response.get("Events", []):
                # Heuristique simple : si un événement Write correspond temporellement, on le considère comme détecté
                # Une implémentation V5 utiliserait le correlation.cloudtrail_event_id exact
                event_time = event["EventTime"].replace(tzinfo=timezone.utc)
                if abs((event_time - finding.timestamp_utc).total_seconds()) < 300: # ± 5 min
                    detected = True
                    detection_time = event_time
                    break

            if detected and detection_time:
                mttd = detection_time - finding.timestamp_utc
                store.update_finding_mttd(mission_id, finding.id, mttd)
                updated_count += 1
                log.info("mttd_recorded", extra={"finding_id": str(finding.id), "mttd_seconds": mttd.total_seconds()})
            else:
                store.update_finding_mttd(mission_id, finding.id, None) # None = non détecté
                log.warning("mttd_not_detected", extra={"finding_id": str(finding.id)})

        except ClientError as e:
            log.error("cloudtrail_lookup_failed", extra={"error": str(e)})

    log.info("mttd_evaluation_complete", extra={"updated_count": updated_count})
    return updated_count
