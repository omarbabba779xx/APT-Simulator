"""TTP plugin library. Each TTP is mapped to a MITRE ATT&CK technique ID."""
from .base import TTP, TTPResult, registry

# Auto-import individual TTP modules so they self-register.
from .command_and_control import t1071_001_http_c2  # noqa: F401
from .command_and_control import t1105_ingress_tool_transfer  # noqa: F401
from .credential_access import t1003_credential_target_enum  # noqa: F401
from .defense_evasion import (  # noqa: F401
    t1027_obfuscation,
    t1070_004_file_deletion,
    t1112_modify_registry,
)
from .collection import t1005_data_from_local_system  # noqa: F401
from .discovery import (  # noqa: F401
    t1016_network_config,
    t1033_user_discovery,
    t1049_network_connections,
    t1057_process_discovery,
    t1069_001_local_groups,
    t1082_system_info,
    t1083_file_discovery,
    t1580_cloud_infra_discovery,
)
from .execution import t1059_command_sim  # noqa: F401
from .exfiltration import t1041_exfil_over_c2  # noqa: F401
from .exfiltration import t1048_exfil_alt_protocol  # noqa: F401
from .impact import t1486_data_encrypted_sim  # noqa: F401
from .initial_access import t1078_004_cloud_account_abuse  # noqa: F401
from .persistence import (  # noqa: F401
    t1053_005_scheduled_task,
    t1098_004_ssh_authorized_keys,
    t1543_002_systemd_service,
    t1547_registry_runkey,
)
from .lateral_movement import t1021_001_rdp  # noqa: F401
from .lateral_movement import t1021_002_smb_admin_shares  # noqa: F401
from .credential_access import t1110_brute_force_sim  # noqa: F401
from .collection import t1530_data_from_cloud_storage  # noqa: F401
from .collection import t1560_archive_collected  # noqa: F401
from .defense_evasion import t1055_process_injection_sim  # noqa: F401
from .catalog import register_catalog_ttps

register_catalog_ttps()

__all__ = ["TTP", "TTPResult", "registry"]
