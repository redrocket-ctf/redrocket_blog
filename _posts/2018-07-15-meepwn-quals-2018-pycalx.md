---
layout: post
category: Web
title: MeePwnCTF quals 2018 PyCalX
tags: 
    - lukas2511
---

PyCalX was part of the MeePwnCTF Quals 2018 and consists of a webpage with 3 inputs,
a value, an operator and a second value.

The code for the challenge is visible on the page when `source` is in the GET-arguments.
There is a link for that directly on the page.

The values and operation are used inside an `eval` statement, which very clearly is
the target of our attack.

## Filtered input

Having a look around we'll see that values and the operator are filtered in a few ways.

If a value contains only digits it's casted as integer, if it's a string there is a blacklist
for things like brackets and quotes. Furthermore instead of the string directly a `repr` of
it (containing single-quotes which we can't easily break) is used.

The operator is limited to 2 characters and the first has to be one of `+-/*=!`.

## Exploit

We can freely control the second character of the operator, so let's make it `+'`, that way
the second value will be evaluated as code and an empty string will be appended to the first
value.

Using a second value like `+source+FLAG < value1+source+source#` (using the comment-character
to ignore the last `'` in the eval) gives us an evaluated command that effectively
is equivilant to  `'whatever'+''+'Mee'+'MeePwnCTF{...}' < 'whatever'+'Mee'+'Mee'` (for `source=Mee`).

Python considers a string "bigger" than another if there is a difference between them and the first
mismatching character is bigger (in ascii) than in the comparison.

With the example `Mee` would be False, but `Mef` is True.

That made it very easy to use a binary search, making this process really quick.

In the end we get the (annoyingly confusing) flag: `MeePwnCTF{python3.66666666666666_([_((you_passed_this?]]]]]])}`
