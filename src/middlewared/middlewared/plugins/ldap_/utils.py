from . import constants


def search_base_data_to_params(data):
    """
    This method converts the data from our schema key `search_bases` into
    nslcd configuration information
    """
    search_params = []
    for base in constants.LDAP_SEARCH_BASE_KEYS:
        if not (value := data.get(base)):
            continue

        match base:
            case constants.SEARCH_BASE_USER:
                search_params.append(f'base passwd {value}')
            case constants.SEARCH_BASE_GROUP:
                search_params.append(f'base group {value}')
            case constants.SEARCH_BASE_NETGROUP:
                search_params.append(f'base netgroup {value}')
            case _:
                raise ValueError(f'{base}: unexpected LDAP search base type')

    return search_params


def attribute_maps_data_to_params(data):
    """
    This method converts the data from our schema key `attribute_maps` into
    nslcd configuration information
    """
    map_params = []
    for nss_type, keys in constants.LDAP_ATTRIBUTE_MAPS.items():
        for key in keys:
            if not (value := data.get(nss_type, {}).get(key)):
                continue

            match key:
                # passwd
                case constants.ATTR_USER_OBJ:
                    map_params.append(f'filter passwd (objectClass={value})')
                case constants.ATTR_USER_NAME:
                    map_params.append(f'map passwd uid {value}')
                case constants.ATTR_USER_UID:
                    map_params.append(f'map passwd uidNumber {value}')
                case constants.ATTR_USER_GID:
                    map_params.append(f'map passwd gidNumber {value}')
                case constants.ATTR_USER_GECOS:
                    map_params.append(f'map passwd gecos {value}')
                case constants.ATTR_USER_HOMEDIR:
                    map_params.append(f'map passwd homeDirectory {value}')
                case constants.ATTR_USER_SHELL:
                    map_params.append(f'map passwd loginShell {value}')

                # shadow
                case constants.ATTR_SHADOW_OBJ:
                    map_params.append(f'filter shadow (objectClass={value})')
                case constants.ATTR_SHADOW_LAST_CHANGE:
                    map_params.append(f'map shadow shadowLastChange {value}')
                case constants.ATTR_SHADOW_MIN:
                    map_params.append(f'map shadow shadowMin {value}')
                case constants.ATTR_SHADOW_MAX:
                    map_params.append(f'map shadow shadowMax {value}')
                case constants.ATTR_SHADOW_WARNING:
                    map_params.append(f'map shadow shadowWarning {value}')
                case constants.ATTR_SHADOW_INACTIVE:
                    map_params.append(f'map shadow shadowInactive {value}')
                case constants.ATTR_SHADOW_EXPIRE:
                    map_params.append(f'map shadow shadowExpire {value}')

                # group
                case constants.ATTR_GROUP_OBJ:
                    map_params.append(f'filter group (objectClass={value})')
                case constants.ATTR_GROUP_GID:
                    map_params.append(f'map group gidNumber {value}')
                case constants.ATTR_GROUP_MEMBER:
                    map_params.append(f'map group member {value}')

                # netgroup
                case constants.ATTR_NETGROUP_OBJ:
                    map_params.append(f'filter netgroup (objectClass={value})')
                case constants.ATTR_NETGROUP_MEMBER:
                    map_params.append(f'map netgroup memberNisNetgroup {value}')
                case constants.ATTR_NETGROUP_TRIPLE:
                    map_params.append(f'map netgroup nisNetgroupTriple {value}')
                case _:
                    raise ValueError(f'{key}: unexpected attribute map parameter for {map}')

    return map_params
