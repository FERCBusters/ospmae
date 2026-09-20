from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.db.models import Framework, FrameworkNode


@dataclass(frozen=True)
class CapabilitySpec:
    key: str
    display_name: str
    children: tuple["CapabilitySpec", ...] = ()


def c(
    key: str, display_name: str, children: tuple[CapabilitySpec, ...] = ()
) -> CapabilitySpec:
    return CapabilitySpec(key=key, display_name=display_name, children=children)


CAPABILITY_TAXONOMY: tuple[CapabilitySpec, ...] = (
    c(
        "channel_tier",
        "Channel Tier",
        (
            c(
                "admin_ui",
                "Admin UI",
                (
                    c(
                        "enrollment",
                        "Enrollment",
                        (
                            c("user_registration", "User Registration"),
                            c("identity_verification", "Identity Verification"),
                            c("kyc_aml_compliance", "KYC / AML Compliance"),
                            c("credential_management", "Credential Management"),
                        ),
                    ),
                    c(
                        "login",
                        "Login",
                        (
                            c("authentication_methods", "Authentication Methods"),
                            c(
                                "device_recognition_and_trust",
                                "Device Recognition and Trust",
                            ),
                            c("session_management", "Session Management"),
                            c("account_recovery", "Account Recovery"),
                        ),
                    ),
                    c(
                        "presentation_overlays",
                        "Presentation / Overlays",
                        (
                            c("capture", "Capture"),
                            c("validation", "Validation"),
                            c("transformation", "Transformation"),
                            c("presentation", "Presentation"),
                        ),
                    ),
                    c(
                        "management_ui",
                        "Management UI",
                        (
                            c("crud_operations", "CRUD Operations"),
                            c(
                                "object_specific_operations",
                                "Object-specific Operations",
                            ),
                        ),
                    ),
                ),
            ),
            c("transactional_ui", "Transactional UI"),
            c(
                "sdk_and_api",
                "SDK and API",
                (
                    c(
                        "consents",
                        "Consents",
                        (
                            c("query_consents", "Query Consents"),
                            c("grant_consents", "Grant Consents"),
                            c("revoke_consents", "Revoke Consents"),
                        ),
                    ),
                    c(
                        "profiles",
                        "Profiles",
                        (
                            c("query_profiles", "Query Profiles"),
                            c("add_profile", "Add Profile"),
                            c("update_profile", "Update Profile"),
                            c("delete_profile", "Delete Profile"),
                            c("select_profile", "Select Profile"),
                        ),
                    ),
                    c(
                        "inventory",
                        "Inventory",
                        (
                            c("query_inventory", "Query Inventory"),
                            c("add_inventory_item", "Add Inventory Item"),
                            c("update_inventory_item", "Update Inventory Item"),
                            c("delete_inventory_item", "Delete Inventory Item"),
                            c("refresh_inventory_item", "Refresh Inventory Item"),
                        ),
                    ),
                    c(
                        "connections",
                        "Connections",
                        (
                            c("query_connections", "Query Connections"),
                            c("add_connection", "Add Connection"),
                            c("update_connection", "Update Connection"),
                            c("delete_connection", "Delete Connection"),
                        ),
                    ),
                    c(
                        "wallet_transfer_and_recovery",
                        "Wallet Transfer and Recovery",
                        (
                            c("backup", "Backup"),
                            c("recover", "Recover"),
                            c("import", "Import"),
                            c("export", "Export"),
                        ),
                    ),
                    c(
                        "keys",
                        "Keys",
                        (
                            c("query_keys", "Query Keys"),
                            c("add_key", "Add Key"),
                            c("delete_key", "Delete Key"),
                            c("get_public_key", "Get Public Key"),
                            c("encrypt", "Encrypt"),
                            c("decrypt", "Decrypt"),
                            c("sign", "Sign"),
                        ),
                    ),
                    c(
                        "notifications",
                        "Notifications",
                        (
                            c("query_notifications", "Query Notifications"),
                            c("add_notification", "Add Notification"),
                            c("update_notification", "Update Notification"),
                            c("delete_notification", "Delete Notification"),
                        ),
                    ),
                    c(
                        "audit_log",
                        "Audit Log",
                        (
                            c("query_audit_log", "Query Audit Log"),
                            c("add_audit_log_entry", "Add Audit Log Entry"),
                        ),
                    ),
                    c(
                        "transactions",
                        "Transactions",
                        (
                            c("query_transactions", "Query Transactions"),
                            c("conduct_transaction", "Conduct Transaction"),
                            c("cancel_transaction", "Cancel Transaction"),
                            c(
                                "events_pubsub_query_status",
                                "Events (Pub/Sub/Query Status)",
                            ),
                        ),
                    ),
                    c(
                        "messaging",
                        "Messaging",
                        (
                            c("send_message", "Send Message"),
                            c("receive_message", "Receive Message"),
                            c("update_message", "Update Message"),
                            c("delete_message", "Delete Message"),
                            c("attachments", "Attachments"),
                        ),
                    ),
                ),
            ),
            c(
                "agents",
                "Agents",
                (
                    c(
                        "issuance",
                        "Issuance",
                        (
                            c("receive", "Receive"),
                            c(
                                "request_issue_reissue_revoke",
                                "Request (issue / re-issue / revoke)",
                            ),
                        ),
                    ),
                    c(
                        "agent_presentation",
                        "Presentation",
                        (
                            c("present", "Present"),
                            c("request", "Request"),
                            c("verify", "Verify"),
                            c("zero_knowledge", "Zero Knowledge"),
                        ),
                    ),
                    c(
                        "agent_p2p",
                        "P2P",
                        (
                            c("direct_message", "Direct Message"),
                            c("error_resilience", "Error Resilience"),
                        ),
                    ),
                    c(
                        "privacy_preserving_edge",
                        "Privacy Preserving Edge",
                        (
                            c("update_logic", "Update Logic"),
                            c("generate_recommendations", "Generate Recommendations"),
                            c("confidential_compute", "Confidential Compute"),
                        ),
                    ),
                    c(
                        "orchestration",
                        "Orchestration",
                        (
                            c("agent_message_relay", "Agent Message Relay"),
                            c("agent_index", "Agent Index"),
                            c("cross_agent_utility", "Cross Agent Utility"),
                        ),
                    ),
                    c(
                        "administration",
                        "Administration",
                        (
                            c("delegation", "Delegation"),
                            c("guardianship", "Guardianship"),
                            c("issue", "Issue"),
                        ),
                    ),
                    c(
                        "policy_engine",
                        "Policy Engine",
                        (
                            c("wallet_owner_rules", "Wallet Owner Rules"),
                            c("relying_party_rules", "Relying Party Rules"),
                            c("credential_rules", "Credential Rules"),
                            c("trust_framework_rules", "Trust Framework Rules"),
                        ),
                    ),
                ),
            ),
            c(
                "wallet_services",
                "Wallet Services",
                (
                    c(
                        "consents_management",
                        "Consents Management",
                        (
                            c("store_consent", "Store Consent"),
                            c("query_consent", "Query Consent"),
                            c("update_consent", "Update Consent"),
                            c("delete_consent", "Delete Consent"),
                        ),
                    ),
                    c(
                        "profiles_management",
                        "Profiles Management",
                        (
                            c("access_control_management", "Access Control Management"),
                            c(
                                "coordination_of_data_storage_and_retrieval",
                                "Coordination of Data Storage and Retrieval",
                            ),
                        ),
                    ),
                    c(
                        "inventory_management",
                        "Inventory Management",
                        (
                            c("calculate_value", "Calculate Value"),
                            c("query", "Query"),
                            c("add", "Add"),
                            c("update", "Update"),
                            c("delete", "Delete"),
                        ),
                    ),
                    c(
                        "connections_management",
                        "Connections Management",
                        (
                            c("peer_did_generation", "Peer DID Generation"),
                            c("did_management", "DID Management"),
                            c("session_key_management", "Session Key Management"),
                        ),
                    ),
                    c(
                        "wallet_services_transfer_and_recovery",
                        "Wallet Transfer and Recovery",
                        (
                            c("ws_backup", "Backup"),
                            c("ws_recover", "Recover"),
                            c("ws_import", "Import"),
                            c("ws_export", "Export"),
                        ),
                    ),
                    c(
                        "keys_management",
                        "Keys Management",
                        (
                            c("key_lifecycle_management", "Key Lifecycle Management"),
                            c("encryption_and_decryption", "Encryption and Decryption"),
                            c("digital_signatures", "Digital Signatures"),
                        ),
                    ),
                    c(
                        "wallet_notifications",
                        "Notifications",
                        (
                            c("multi_platform_support", "Multi-platform Support"),
                            c(
                                "push_notifications_integration",
                                "Push Notifications Integration",
                            ),
                            c("webhook_support", "Webhook Support"),
                        ),
                    ),
                    c(
                        "wallet_audit_log",
                        "Audit Log",
                        (
                            c("collection", "Collection"),
                            c("search", "Search"),
                            c("export_log", "Export"),
                            c("monitor", "Monitor"),
                        ),
                    ),
                    c(
                        "transactions_processing",
                        "Transactions Processing",
                        (
                            c("construct", "Construct"),
                            c("submit", "Submit"),
                            c("confirm", "Confirm"),
                            c("batching_and_sequencing", "Batching and Sequencing"),
                            c("roll_up", "Roll Up"),
                        ),
                    ),
                ),
            ),
            c(
                "secure_storage",
                "Secure Storage",
                (
                    c(
                        "key_storage",
                        "Key Storage",
                        (
                            c(
                                "hardware_security_modules",
                                "Hardware Security Modules (HSMs)",
                            ),
                            c("secure_enclaves", "Secure Enclaves"),
                            c(
                                "key_management_systems",
                                "Key Management Systems (KMSs)",
                            ),
                            c("key_encryption", "Key Encryption"),
                        ),
                    ),
                    c(
                        "credential_storage",
                        "Credential Storage",
                        (
                            c("status_management", "Status Management"),
                            c(
                                "schema_and_definition_retrieval",
                                "Schema and Definition Retrieval",
                            ),
                            c("encrypted_data_storage", "Encrypted Data Storage"),
                        ),
                    ),
                    c(
                        "data_storage",
                        "Data Storage",
                        (
                            c("local_storage", "Local Storage"),
                            c("remote_storage", "Remote Storage"),
                            c(
                                "folders_and_categorization",
                                "Folders and Categorization",
                            ),
                            c("indexing_and_search", "Indexing and Search"),
                            c("authorization", "Authorization"),
                            c("cryptography", "Cryptography"),
                        ),
                    ),
                    c(
                        "custodial_key_storage",
                        "Custodial Key Storage",
                        (
                            c("custodial_key_management", "Key Management"),
                            c("recovery_mechanisms", "Recovery Mechanisms"),
                            c("multi_party_control", "Multi-Party Control"),
                        ),
                    ),
                ),
            ),
            c(
                "network_services",
                "Network Services",
                (
                    c(
                        "indexers",
                        "Indexers",
                        (
                            c("data_extraction", "Data Extraction"),
                            c("parsing_and_normalization", "Parsing and Normalization"),
                            c("indexing", "Indexing"),
                        ),
                    ),
                    c(
                        "connectors",
                        "Connectors",
                        (
                            c("protocol_support", "Protocol Support"),
                            c("transaction_broadcasting", "Transaction Broadcasting"),
                            c("network_configuration", "Network Configuration"),
                        ),
                    ),
                    c(
                        "offline_synchronizers",
                        "Offline Synchronizers",
                        (
                            c("sync_changes", "Sync Changes"),
                            c("conflict_resolution", "Conflict Resolution"),
                        ),
                    ),
                    c(
                        "trust_registry",
                        "Trust Registry",
                        (
                            c(
                                "organizational_identity_maintenance",
                                "Organizational Identity Maintenance",
                            ),
                            c(
                                "credential_and_token_definitions_and_maintenance",
                                "Credential and Token Definitions and Maintenance",
                            ),
                            c(
                                "revocation_lists_maintenance",
                                "Revocation Lists Maintenance",
                            ),
                            c(
                                "trusted_secure_storage_maintenance",
                                "Trusted Secure Storage Maintenance",
                            ),
                            c(
                                "trusted_agents_maintenance",
                                "Trusted Agents Maintenance",
                            ),
                        ),
                    ),
                ),
            ),
            c(
                "p2p_services",
                "P2P Services",
                (
                    c(
                        "offline_processing",
                        "Offline Processing",
                        (
                            c("offline_storage", "Offline Storage"),
                            c("change_tracking", "Change Tracking"),
                        ),
                    ),
                    c(
                        "p2p_communication",
                        "P2P Communication",
                        (
                            c("wallet_addressing", "Wallet Addressing"),
                            c("peer_discovery", "Peer Discovery"),
                            c(
                                "secure_communication_protocols",
                                "Secure Communication Protocols",
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ),
    c(
        "security_services",
        "Security Services",
        (
            c("security_encryption", "Encryption"),
            c("security_authentication", "Authentication"),
            c("security_authorization", "Authorization"),
            c("fraud_detection", "Fraud Detection"),
            c("threat_vulnerability_management", "Threat / Vulnerability Management"),
            c("managed_detection_and_response", "Managed Detection and Response"),
            c("application_security", "Application Security"),
            c("device_security", "Device Security"),
            c("platform_security", "Platform Security"),
            c("network_security", "Network Security"),
        ),
    ),
    c(
        "devops_services",
        "DevOps Services",
        (
            c("build_and_integration_enablement", "Build and Integration Enablement"),
            c("test_execution_and_automation", "Test Execution and Automation"),
            c("change_control", "Change Control"),
            c("delivery_management", "Delivery Management"),
            c("ecosystem_management", "Ecosystem Management"),
            c("it_operations", "IT Operations"),
            c("metrics_and_monitoring", "Metrics and Monitoring"),
            c("disaster_recovery", "Disaster Recovery"),
        ),
    ),
    c("external_integration_services", "External Integration Services"),
    c("platform_infrastructure_services", "Platform/Infrastructure Services"),
)


def walk_taxonomy(
    specs: Iterable[CapabilitySpec], parent_key: str | None = None, level: int = 0
):
    for order, node in enumerate(specs, start=1):
        yield {
            "key": node.key,
            "display_name": node.display_name,
            "parent_key": parent_key,
            "sort_order": order,
            "level": level,
        }
        if node.children:
            yield from walk_taxonomy(
                node.children, parent_key=node.key, level=level + 1
            )


def taxonomy_rows() -> list[dict]:
    return list(walk_taxonomy(CAPABILITY_TAXONOMY))


UWRA_MACHINE_NAME = "uwra"
UWRA_DISPLAY_NAME = "Open Wallet Foundation UWRA"
UWRA_DESCRIPTION = "Universal Wallet Reference Architecture taxonomy (seeded as the default framework)."


def ensure_uwra_framework(db: Session) -> Framework:
    """Idempotently seed/update the UWRA framework + node hierarchy.

    Nodes not present in the canonical taxonomy are removed (strict sync).
    """

    framework = (
        db.query(Framework)
        .filter(Framework.machine_name == UWRA_MACHINE_NAME)
        .one_or_none()
    )
    if not framework:
        framework = Framework(
            machine_name=UWRA_MACHINE_NAME,
            display_name=UWRA_DISPLAY_NAME,
            description=UWRA_DESCRIPTION,
            created_by_user_id=None,
        )
        db.add(framework)
        db.flush()

    rows = taxonomy_rows()
    desired_keys = {row["key"] for row in rows}

    existing_nodes = (
        db.query(FrameworkNode).filter(FrameworkNode.framework_id == framework.id).all()
    )
    by_key = {node.key: node for node in existing_nodes}

    changed = False

    # Remove stale nodes first (deepest first).
    stale_nodes = [node for node in existing_nodes if node.key not in desired_keys]
    for node in sorted(stale_nodes, key=lambda n: (n.level or 0, n.id), reverse=True):
        db.delete(node)
        by_key.pop(node.key, None)
        changed = True

    if stale_nodes:
        db.flush()

    # Create / update canonical nodes.
    for row in rows:
        existing = by_key.get(row["key"])
        if not existing:
            existing = FrameworkNode(
                framework_id=framework.id,
                key=row["key"],
                display_name=row["display_name"],
                sort_order=int(row["sort_order"] or 0),
                level=int(row["level"] or 0),
            )
            db.add(existing)
            db.flush()
            by_key[row["key"]] = existing
            changed = True
        else:
            updated = False
            if existing.display_name != row["display_name"]:
                existing.display_name = row["display_name"]
                updated = True
            if int(existing.sort_order or 0) != int(row["sort_order"]):
                existing.sort_order = int(row["sort_order"])
                updated = True
            if int(existing.level or 0) != int(row["level"]):
                existing.level = int(row["level"])
                updated = True
            if updated:
                db.add(existing)
                changed = True

    # Set parents in second pass to ensure all nodes exist.
    for row in rows:
        node = by_key[row["key"]]
        parent = by_key.get(row["parent_key"]) if row["parent_key"] else None
        parent_id = parent.id if parent else None
        if node.parent_id != parent_id:
            node.parent_id = parent_id
            db.add(node)
            changed = True

    if changed:
        db.commit()

    return framework


def ensure_default_frameworks(db: Session) -> None:
    """Seed default frameworks used by the app."""

    ensure_uwra_framework(db)


# Backward-compatible alias (not relied upon by the UI after the refactor).
ensure_capability_taxonomy = ensure_default_frameworks
