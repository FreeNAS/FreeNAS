<%
    import ipaddress
    base_name = middleware.call_sync('iscsi.global.config')['basename']
    targets = middleware.call_sync('iscsi.target.query', [['auth_networks', '!=', []]])

    def parse_auths(auths):
        result = []
        for auth in auths:
            try:
                ipobj = ipaddress.ip_interface(auth)
            except ValueError:
                middleware.logger.warning("Invalid IP address: %s", auth, exc_info=True)
            else:
                if ipobj.network.prefixlen in (32, 128):
                    result.append(str(ipobj.ip))
                else:
                    result.append(str(ipobj.network))
        return ', '.join(result)
%>\
% for target in targets:
${base_name}:${target['name']} ${parse_auths(target['auth_networks'])}
% endfor
