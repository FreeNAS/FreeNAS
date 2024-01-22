from collections import defaultdict
from dataclasses import dataclass, field


@dataclass()
class Role:
    """
    An authenticated user role.

    :ivar includes: a list of other roles that this role includes. When user is granted this role, they will also
        receive permissions granted by all the included roles.
    :ivar full_admin: if `True` then this role will allow calling all methods.
    """
    includes: [str] = field(default_factory=list)
    full_admin: bool = False
    builtin: bool = True


ROLES = {
    'ACCOUNT_READ': Role(),
    'ACCOUNT_WRITE': Role(includes=['ACCOUNT_READ']),

    'FAILOVER_READ': Role(),
    'FAILOVER_WRITE': Role(includes=['FAILOVER_READ']),

    'AUTH_SESSIONS_READ': Role(),
    'AUTH_SESSIONS_WRITE': Role(includes=['AUTH_SESSIONS_READ']),

    'KMIP_READ': Role(),
    'KMIP_WRITE': Role(includes=['KMIP_READ']),

    'IPMI_READ': Role(),
    'IPMI_WRITE': Role(includes=['IPMI_READ']),

    'FILESYSTEM_ATTRS_READ': Role(),
    'FILESYSTEM_ATTRS_WRITE': Role(includes=['FILESYSTEM_ATTRS_READ']),
    'FILESYSTEM_DATA_READ': Role(),
    'FILESYSTEM_DATA_WRITE': Role(includes=['FILESYSTEM_DATA_READ']),
    'FILESYSTEM_FULL_CONTROL': Role(includes=['FILESYSTEM_ATTRS_WRITE',
                                              'FILESYSTEM_DATA_WRITE']),
    'REPORTING_READ': Role(),
    'REPORTING_WRITE': Role(includes=['REPORTING_READ']),

    'SUPPORT_READ': Role(),
    'SUPPORT_WRITE': Role(includes=['SUPPORT_READ']),

    'SYSTEM_AUDIT_READ': Role(),
    'SYSTEM_AUDIT_WRITE': Role(),

    'FULL_ADMIN': Role(full_admin=True, builtin=False),


    # Alert roles
    'ALERT_LIST_READ': Role(),

    'CLOUD_SYNC_READ': Role(),
    'CLOUD_SYNC_WRITE': Role(includes=['CLOUD_SYNC_READ']),

    'SERVICE_READ': Role(),
    'SERVICE_WRITE': Role(),

    # for webui.enclosure.** namespace
    'ENCLOSURE_READ': Role(),
    'ENCLOSURE_WRITE': Role(includes=['ENCLOSURE_READ']),

    # Network roles
    'NETWORK_GENERAL_READ': Role(),
    'NETWORK_INTERFACE_READ': Role(),
    'NETWORK_INTERFACE_WRITE': Role(includes=['NETWORK_INTERFACE_READ']),

    # VM roles
    'VM_READ': Role(),
    'VM_WRITE': Role(includes=['VM_READ']),
    'VM_DEVICE_READ': Role(includes=['VM_READ']),
    'VM_DEVICE_WRITE': Role(includes=['VM_WRITE', 'VM_DEVICE_READ']),

    # JBOF roles
    'JBOF_READ': Role(),
    'JBOF_WRITE': Role(includes=['JBOF_READ']),

    # Crypto roles
    'CERTIFICATE_READ': Role(),
    'CERTIFICATE_WRITE': Role(includes=['CERTIFICATE_READ']),
    'CERTIFICATE_AUTHORITY_READ': Role(),
    'CERTIFICATE_AUTHORITY_WRITE': Role(includes=['CERTIFICATE_AUTHORITY_READ']),

    # iSCSI roles
    'SHARING_ISCSI_AUTH_READ': Role(),
    'SHARING_ISCSI_AUTH_WRITE': Role(includes=['SHARING_ISCSI_AUTH_READ']),
    'SHARING_ISCSI_EXTENT_READ': Role(),
    'SHARING_ISCSI_EXTENT_WRITE': Role(includes=['SHARING_ISCSI_EXTENT_READ']),
    'SHARING_ISCSI_GLOBAL_READ': Role(),
    'SHARING_ISCSI_GLOBAL_WRITE': Role(includes=['SHARING_ISCSI_GLOBAL_READ']),
    'SHARING_ISCSI_HOST_READ': Role(),
    'SHARING_ISCSI_HOST_WRITE': Role(includes=['SHARING_ISCSI_HOST_READ']),
    'SHARING_ISCSI_INITIATOR_READ': Role(),
    'SHARING_ISCSI_INITIATOR_WRITE': Role(includes=['SHARING_ISCSI_INITIATOR_READ']),
    'SHARING_ISCSI_PORTAL_READ': Role(),
    'SHARING_ISCSI_PORTAL_WRITE': Role(includes=['SHARING_ISCSI_PORTAL_READ']),
    'SHARING_ISCSI_TARGET_READ': Role(),
    'SHARING_ISCSI_TARGET_WRITE': Role(includes=['SHARING_ISCSI_TARGET_READ']),
    'SHARING_ISCSI_TARGETEXTENT_READ': Role(),
    'SHARING_ISCSI_TARGETEXTENT_WRITE': Role(includes=['SHARING_ISCSI_TARGETEXTENT_READ']),
    'SHARING_ISCSI_READ': Role(includes=['SHARING_ISCSI_AUTH_READ',
                                         'SHARING_ISCSI_EXTENT_READ',
                                         'SHARING_ISCSI_GLOBAL_READ',
                                         'SHARING_ISCSI_HOST_READ',
                                         'SHARING_ISCSI_INITIATOR_READ',
                                         'SHARING_ISCSI_PORTAL_READ',
                                         'SHARING_ISCSI_TARGET_READ',
                                         'SHARING_ISCSI_TARGETEXTENT_READ']),
    'SHARING_ISCSI_WRITE': Role(includes=['SHARING_ISCSI_AUTH_WRITE',
                                          'SHARING_ISCSI_EXTENT_WRITE',
                                          'SHARING_ISCSI_GLOBAL_WRITE',
                                          'SHARING_ISCSI_HOST_WRITE',
                                          'SHARING_ISCSI_INITIATOR_WRITE',
                                          'SHARING_ISCSI_PORTAL_WRITE',
                                          'SHARING_ISCSI_TARGET_WRITE',
                                          'SHARING_ISCSI_TARGETEXTENT_WRITE']),

    'SHARING_NFS_READ': Role(),
    'SHARING_NFS_WRITE': Role(includes=['SHARING_NFS_READ']),
    'SHARING_SMB_READ': Role(),
    'SHARING_SMB_WRITE': Role(includes=['SHARING_SMB_READ']),
    'SHARING_READ': Role(includes=['SHARING_ISCSI_READ',
                                   'SHARING_NFS_READ',
                                   'SHARING_SMB_READ']),
    'SHARING_WRITE': Role(includes=['SHARING_ISCSI_WRITE',
                                    'SHARING_NFS_WRITE',
                                    'SHARING_SMB_WRITE']),

    'KEYCHAIN_CREDENTIAL_READ': Role(),
    'KEYCHAIN_CREDENTIAL_WRITE': Role(includes=['KEYCHAIN_CREDENTIAL_READ']),
    'REPLICATION_TASK_CONFIG_READ': Role(),
    'REPLICATION_TASK_CONFIG_WRITE': Role(includes=['REPLICATION_TASK_CONFIG_READ']),
    'REPLICATION_TASK_READ': Role(),
    'REPLICATION_TASK_WRITE': Role(includes=['REPLICATION_TASK_READ']),
    'REPLICATION_TASK_WRITE_PULL': Role(includes=['REPLICATION_TASK_WRITE']),
    'SNAPSHOT_TASK_READ': Role(),
    'SNAPSHOT_TASK_WRITE': Role(includes=['SNAPSHOT_TASK_READ']),

    'POOL_SCRUB_READ': Role(),
    'POOL_SCRUB_WRITE': Role(includes=['POOL_SCRUB_READ']),
    'DATASET_READ': Role(),
    'DATASET_WRITE': Role(includes=['DATASET_READ']),
    'DATASET_DELETE': Role(),
    'SNAPSHOT_READ': Role(),
    'SNAPSHOT_WRITE': Role(includes=['SNAPSHOT_READ']),
    'SNAPSHOT_DELETE': Role(),

    'REPLICATION_ADMIN': Role(includes=['KEYCHAIN_CREDENTIAL_WRITE',
                                        'REPLICATION_TASK_CONFIG_WRITE',
                                        'REPLICATION_TASK_WRITE',
                                        'SNAPSHOT_TASK_WRITE',
                                        'SNAPSHOT_WRITE'],
                              builtin=False),

    'SHARING_ADMIN': Role(includes=['READONLY_ADMIN',
                                    'DATASET_WRITE',
                                    'SHARING_WRITE',
                                    'FILESYSTEM_ATTRS_WRITE',
                                    'SERVICE_READ'],
                          builtin=False),
    # Apps roles
    'CONTAINER_READ': Role(),
    'CONTAINER_WRITE': Role(includes=['CONTAINER_READ']),
    'CATALOG_READ': Role(),
    'CATALOG_WRITE': Role(includes=['CATALOG_READ']),
    'KUBERNETES_READ': Role(includes=['CONTAINER_READ']),
    'KUBERNETES_WRITE': Role(includes=['CONTAINER_WRITE', 'KUBERNETES_READ']),
    'APPS_READ': Role(includes=['CATALOG_READ', 'CONTAINER_READ']),
    'APPS_WRITE': Role(includes=['CATALOG_WRITE', 'APPS_READ', 'CONTAINER_WRITE']),
}
ROLES['READONLY_ADMIN'] = Role(includes=[role for role in ROLES if role.endswith('_READ')], builtin=False)


class ResourceManager:
    def __init__(self, resource_title, resource_method, roles):
        self.resource_title = resource_title
        self.resource_method = resource_method
        self.roles = roles
        self.resources = {}
        self.allowlists_for_roles = defaultdict(list)

    def register_resource(self, resource_name, roles, exist_ok):
        if resource_name in self.resources:
            if not exist_ok:
                raise ValueError(f"{self.resource_title} {resource_name!r} is already registered in this role manager")
        else:
            self.resources[resource_name] = []

        self.add_roles_to_resource(resource_name, roles)

    def add_roles_to_resource(self, resource_name, roles):
        if resource_name not in self.resources:
            raise ValueError(f"{self.resource_title} {resource_name!r} is not registered in this role manager")

        for role in roles:
            if role not in self.roles:
                raise ValueError(f"Invalid role {role!r}")

        self.resources[resource_name] += roles

        for role in roles:
            self.allowlists_for_roles[role].append({"method": self.resource_method, "resource": resource_name})

    def roles_for_resource(self, resource_name):
        roles = set(self.resources.get(resource_name, []))

        changed = True
        while changed:
            changed = False
            for role_name, role in self.roles.items():
                if role_name not in roles:
                    for child_role_name in role.includes:
                        if child_role_name in roles:
                            roles.add(role_name)
                            changed = True

        return sorted(roles)


class RoleManager:
    def __init__(self, roles):
        self.roles = roles
        self.methods = ResourceManager("Method", "CALL", self.roles)
        self.events = ResourceManager("Event", "SUBSCRIBE", self.roles)

    def register_method(self, method_name, roles, *, exist_ok=False):
        self.methods.register_resource(method_name, roles, exist_ok)

    def add_roles_to_method(self, method_name, roles):
        self.methods.add_roles_to_resource(method_name, roles)

    def register_event(self, event_name, roles, *, exist_ok=False):
        self.events.register_resource(event_name, roles, exist_ok)

    def roles_for_role(self, role):
        if role not in self.roles:
            return set()

        return set.union({role}, *[self.roles_for_role(included_role) for included_role in self.roles[role].includes])

    def allowlist_for_role(self, role):
        if role in self.roles and self.roles[role].full_admin:
            return [{"method": "CALL", "resource": "*"}, {"method": "SUBSCRIBE", "resource": "*"}]

        return sum([
            self.methods.allowlists_for_roles[role] + self.events.allowlists_for_roles[role]
            for role in self.roles_for_role(role)
        ], [])

    def roles_for_method(self, method_name):
        return self.methods.roles_for_resource(method_name)

    def roles_for_event(self, event_name):
        return self.events.roles_for_resource(event_name)
