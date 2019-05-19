---
layout: post
category: Web
title: Harekaze CTF 2019 - SQLite Voting
tags: 
    - lukas2511
---

The challenge consisted of a webpage with four different animal emojis,
clicking on one sent a vote for that animal. It was promised that results
will be published at the end of the CTF.

We are provided with the database schema which consists of two tables,
one for all the votes and one containing the precious flag.

Looking at the provided code we can easily spot an attack vector:
```php
...
$id = $_POST['id'];
...
$res = $pdo->query("UPDATE vote SET count = count + 1 WHERE id = ${id}");
...
```

The only issue being that `$id` is filtered using a custom function:
```php
function is_valid($str) {
  $banword = [
    // dangerous chars
    // " % ' * + / < = > \ _ ` ~ -
    "[\"%'*+\\/<=>\\\\_`~-]",
    // whitespace chars
    '\s',
    // dangerous functions
    'blob', 'load_extension', 'char', 'unicode',
    '(in|sub)str', '[lr]trim', 'like', 'glob', 'match', 'regexp',
    'in', 'limit', 'order', 'union', 'join'
  ];
  $regexp = '/' . implode('|', $banword) . '/i';
  if (preg_match($regexp, $str)) {
    return false;
  }
  return true;
}
```

So we are not allowed to use whitespace, no functions like char, like or substr
that could help us compare strings and they even limited how we can query other tables
by blocking union and join.

After playing around with an sqlite shell for a few minutes it became clear that subqueries
using something like `SELECT(flag)FROM(flag)` seemed to be working fine, now we need two things:

- A way of actually getting a result back (no query results are returned)
- A way of comparing the flag in the database with given values (since we are attacking it completely blind)

Getting a result back was actually quite easy, we can just let sqlite try to interpret the flag as json.
Since it has brackets and (hopefully) doesn't follow correct json syntax that will result in an error which
we can't see but at least are told that something went wrong.

Trying this out we crafted two queries:

- `(SELECT(JSON(flag))FROM(flag)WHERE(flag)IS(0))` This one succeeded as json(flag) is never executed
- `(SELECT(JSON(flag))FROM(flag)WHERE(flag)IS(flag))` This one fails as the flag is no valid json string

Now we needed a way to actually get any information about the content... this is where most of the time got
spent.

Playing around with the shell a bit more we found that we can convert the flag into hex presentation and that
sqlite is using weak typing. Trying out something like `SELECT REPLACE("1234", 12, "");` results in `34`.

Taking the redacted flag from the given schema (`HarekazeCTF{<redacted>}`) and converting it into hex results
in `486172656b617a654354467b3c72656461637465643e7d`.
We noticed that there are lot of parts with just digits and no letters `486172656 b 617 a 654354467 b 3 c 72656461637465643 e 7 d`,
and since we could replace numbers with anything we wanted to we would be able to basically reduce the length of
the given hex-string by the number of matches of our replacement.

First we tried to find the length of the flag, that was actually quite easy to do, just probing around with a simple query:

- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(flag))IS(36))` Thank you for your vote!
- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(flag))IS(37))` Thank you for your vote!
- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(flag))IS(38))` An error occured...

So we know the flag is 38 characters long, or 76 hex characters.

Next we probed around for the count of each digit in the hex-flag, here an example for the digit `4` (which was in there 7 times):

- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(REPLACE(HEX(flag),4,hex(null))))IS(76))` Thank you for your vote!
- ...
- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(REPLACE(HEX(flag),4,hex(null))))IS(70))` Thank you for your vote!
- `(SELECT(JSON(flag))FROM(flag)WHERE(LENGTH(REPLACE(HEX(flag),4,hex(null))))IS(69))` An error occured

Using that information we now were able to piece together parts of the flag by trying number sequences instead of single digits,
each time decreasing the length accordingly and adding a digit, if it was correct we'd get an error otherwise we were thanked for our
patience.

After getting into the flow this was actually done quite quickly in a few minutes by hand, resulting in the following sequence of numbers
and 12 characters (`[a-f]`) left unknown:

- 345
- 34316
- 34353733727
- 3137335
- 35716
- 37305
- 62335
- 486172656
- 617
- 654354467
- 5
- 6

We knew that the flag would start with `HarekazeCTF{` so we quickly determined that `486172656 b 617 a 654354467 b` is the
start, already giving us the order for 3 of the numbers in the list. Since the flag ends with `}` (0x7d) we know that we'd
need a number with a 7 at the end, which after sorting out the start could only be `34353733727`.

After that we had the following numbers left:

- 345
- 34316
- 3137335
- 35716
- 37305
- 62335
- 5
- 6

Noticing that most of those numbers (excluding the last digit) resultet in valid ascii and most of them ended with a `5`
and 0x5f being an underscore which is often used as a flag separator we quickly filled that in, leaving us only with 3
hex characters and all being prefixed with a `6`. Since the flag seemed to be written in l33t-speak and `m` (0x6d) is
one of the characters which is really hard to represent that way, so we picked that sequence to fill in the last gaps.

At that point we had the following list:

- 486172656B617A654354467B `HarekazeCTF{`
- 345F `4_`
- 34316D 5F `41m_` (we moved the 5F from the end here since it fits the pattern of other parts)
- 3137335F `173_`
- 35716D `5qm`
- 37305F `70_`
- 62335F `b3_`
- 5F `_`
- 6D `m`
- 34353733727 `4573r}`

Sorting that around we got something like `HarekazeCTF{41m_70_b3_4_5qm173_m4573r}`, and fixing one of our guesses replacing
the `m` with an `l` resulted in the flag: `HarekazeCTF{41m_70_b3_4_5ql173_m4573r}`.
