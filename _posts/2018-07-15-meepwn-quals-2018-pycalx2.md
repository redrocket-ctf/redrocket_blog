---
layout: post
category: Web
title: MeePwnCTF quals 2018 PyCalX2
tags: 
    - lukas2511
---

PyCalX2 was part of the MeePwnCTF Quals 2018 and consists of a webpage with 3 inputs,
a value, an operator and a second value.

You should have a look PyCalX before reading this writeup.

## Filtered input

The code differs from PyCalX by the fact that our operation is filtered now too, this
breaks our quote injection and we have to find a new way in.

```diff
-    op = get_op(arguments['op'].value)
+    op = get_op(get_value(arguments['op'].value))
```

## Fun with flags

Well, seeing the flag of PyCalcX we get a hint for python3.6, reading the changelog we
found that python3.6 intruduced a new type of format-strings, often called f-strings
or Literal String Interpolation.

With that information our new operator now is: `+f`

## Exploit

These new format strings allow some eval-like behaviour, using `{FLAG<source}` we
appearantly have an even easier comparison, but there is a catch, this returns
True or False, which would be appended to value1 (which can't be empty), but the
script only allows outputs with digits, the word True or the word False, no combinations,
nothing else.

As a workaround we can use nesting inside the format-string, something like
`{"e":{FLAG<source:1}.1}` would return `e` if `FLAG<source`, otherwise it would
throw an exception.
Setting value1 to `Tru` this would end up as `True` in one case and `Invalid`
(because of the exception) in the other.

Now we still can't use quotes so we have to find a string starting with `e`, but that's
quite easy and our full payload for value2 now looks like this: `{sys.exit.__name__:{FLAG<source:1}.1}`.

With everything in place we can now do the binary search again.

This time we knew what was coming: `MeePwnCTF{python3.6[_strikes_backkkkkkkkkkkk)}`
