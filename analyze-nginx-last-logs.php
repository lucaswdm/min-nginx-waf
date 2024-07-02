<?php

    define('IPDATADIR', '/cacheip/');

    $WHITELISTED_IPS = [
        '142.93.197.28' => 1,
        '104.238.205.105' => 1,
        '192.99.37.32' => 1,
        '5.9.100.27' => 1,
        '69.46.15.22' => 1,
    ];

    if(!is_dir(IPDATADIR)) mkdir(IPDATADIR, 0777, true);

    error_reporting(0); ini_set('display_errors', true);

    $LAST_LINES = (shell_exec("tail -n 5000 /data/logs/access.log"));
    #print_r($LAST_LINES);
    $LINES = explode(PHP_EOL, $LAST_LINES);

    $STATS = [];

    $REMOTE_USERS = [];

    $IPS_URIS = [];

    $TIMELIMIT = time() - (60 * 3);

    #$WHITE

    foreach($LINES as $k => $Line) {



        $Line = trim($Line);
        if(empty($Line)) continue;
        $JSON = json_decode($Line, true);

        if(isset($WHITELISTED_IPS[$JSON['ip2']])) {
            continue;
        }

        #print_r($JSON);
        $STATS[$JSON['host']]++;

        $DIFF = $JSON['time'] - $TIMELIMIT;

        if($DIFF < 0) continue;

        #if($k % 10 == 0)
        {
            #echo date('H:i:s', $JSON['time']) . " " . $DIFF . PHP_EOL;
        }

        #continue;

        #echo time() . PHP_EOL . $TIMELIMIT . PHP_EOL . $DIFF . PHP_EOL . $JSON['time'] . PHP_EOL;

        #break;

        $URI_COMPLEX = $JSON['uri'];

        if($k = strpos($URI_COMPLEX, '?')) {
            $URI_COMPLEX = substr($URI_COMPLEX, 0, $k);
        }

        $EXTENSAO = @array_pop(explode(".", $URI_COMPLEX));

        if(in_array($EXTENSAO, ['png', 'gif', 'jpg', 'jpeg', 'woff', 'ico', 'svg', 'webp', 'js', 'css', 'html'])) continue;

        if(strpos($JSON['uri'], '/wp-admin/') !== false) continue;
        if(stripos($JSON['uri'], 'data2') !== false) continue;
        if(strpos($JSON['uri'], 'uptime.dog') !== false) continue;
        if(stripos($JSON['uri'], 'dataraw.net') !== false) continue;
        if(strpos($JSON['uri'], 'wp-cron.php') !== false) continue;

        if(stripos($JSON['user_agent'], 'bingbot') !== false) continue;
        if(stripos($JSON['user_agent'], 'googlebot') !== false) continue;

        if(isset($JSON['ip2']) && !empty($JSON['ip2']))
        {
            $REMOTE_USERS[$JSON['ip2']]++;
            $IPS_URIS[$JSON['ip2']][] = $JSON['uri'];
        }
        #break;
    }

    arsort($REMOTE_USERS);

    #print_r($STATS); print_r($REMOTE_USERS);

    foreach($REMOTE_USERS as $ip => $qtde)
    {
        if($qtde < 30) break;

        $GEOIP = geoip($ip);

        $PRINT_GEOIP = print_r($GEOIP, true);

        if( stripos($PRINT_GEOIP, 'Google') !== false ) continue;

        echo $qtde . "\t" . $ip . " - ". $GEOIP['as'] . PHP_EOL;
        print_r(array_slice($IPS_URIS[$ip],0,30));
        echo PHP_EOL;
        #print_r(geoip($ip));

        file_put_contents('/dev/shm/BLOCK_IP_' . $ip, $ip);
        touch('/dev/shm/BLOCK_IP_' . $ip, time() + (count($IPS_URIS[$ip])*3) );
    }


    $ARRAY_BLOCKED = [];

    $DEYN_NGINX = [];

    foreach(glob('/dev/shm/BLOCK_IP_*') as $FILE)
    {
        $DIFF = time() - filemtime($FILE);
        if($DIFF < 180)
        {
            $IP = file_get_contents($FILE);
            $ARRAY_BLOCKED[] = "'" . $IP . "'";
            $DEYN_NGINX[] = "deny " . $IP . ";";
        }
        else
        {
            unlink($FILE);
        }
    }

    if(!$ARRAY_BLOCKED) {
        $ARRAY_BLOCKED[] = "'0.0.0.0'";
    }

    file_put_contents('/etc/nginx/data2Deny', implode(PHP_EOL, $DEYN_NGINX));

    system("/usr/sbin/service nginx reload");

    $PHP_CONTENT_BLOCK = file_get_contents(__DIR__ . '/__prepend.inc.php.txt');

    print_r($ARRAY_BLOCKED);

    $PHP_CONTENT_BLOCK = str_Replace('{IPS}', implode(',', $ARRAY_BLOCKED), $PHP_CONTENT_BLOCK);

    echo $PHP_CONTENT_BLOCK . PHP_EOL;

    file_put_contents('/dev/shm/__prepend.inc.php', $PHP_CONTENT_BLOCK);



    function geoip($ip) {
        $FILE_EXISTS = IPDATADIR . $ip . '';
        if(is_file($FILE_EXISTS)) return json_decode(file_get_contents($FILE_EXISTS), true);
        $JSON = file_get_contents("https://pro.ip-api.com/json/".$ip."?key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        if(!empty($JSON))
        {
            file_put_contents($FILE_EXISTS, $JSON);
        }

        return json_decode( trim($JSON), true);
    }
