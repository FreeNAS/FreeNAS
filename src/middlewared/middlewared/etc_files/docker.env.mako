<%
    config = middleware.call_sync('network.configuration.config')
%>\
# Docker Environment file

% if config['httpproxy']:
HTTP_PROXY="${config['httpproxy']}"
HTTPS_PROXY="${config['httpproxy']}"
% endif
