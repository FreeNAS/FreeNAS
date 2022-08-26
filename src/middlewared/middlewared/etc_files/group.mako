<%
    from middlewared.utils import filter_list

    users_map = {
        i['id']: i
        for i in render_ctx['user.query']
    }

    def get_usernames(group):
        return ','.join([
            users_map[i]['username']
            for i in group['users']
            if i in users_map and users_map[i]['group']['id'] != group['id']
        ])

%>\
% for group in filter_list(render_ctx['group.query'], [], {'order_by': ['-builtin', 'gid', 'group']}):
${group['group']}:x:${group['gid']}:${get_usernames(group)}
% endfor
