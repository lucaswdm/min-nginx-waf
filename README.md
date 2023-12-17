nginx.conf - LOG


log_format main escape=json '{"time": $msec, "resp_body_size": $body_bytes_sent, "host": "$http_host", "address": "$remote_addr", "request_length": $request_length, "method": "$request_method", "uri": "$request_uri", "status": $status,  "user_agent": "$http_user_agent", "resp_time": $request_time, "upstream_addr": "$upstream_addr", "upstream_cache_status": "$upstream_cache_status", "ip2": "$http_x_forwarded_for"}';

access_log /data/logs/access.log main buffer=1k;

