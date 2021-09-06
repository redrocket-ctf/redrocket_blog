---
layout: post
title: ALLES! CTF 2021 EntrAPI
category: Misc
tags: 
    - lukas2511
---

EntrAPI was a task of the ALLES! CTF 2021:

```
A very simple stegano tool that estimates the entropy of sections of a file by counting unique bytes in a range. Here's a snippet of the Dockerfile to get you started:

COPY main.js index.html flag /
RUN deno cache main.js
EXPOSE 1024
CMD deno run -A main.js
```

It provided an http based API taking a path to a file, a start position and an end position, and gave the number of different characters in the giving range as result.

So e.g. with a flag in the format `ALLES!{....}` giving path /flag with start 0 and end 5 would result in 4, as the `L` is used twice.

For ease of use a helper function has been defined first:

```python
url = "https://[...]/query"
path = '/whatever/i/want'
def getent(start, stop):
    data = {'path': path, 'start': start, 'end': stop}
    ent = requests.post(url, json=data).json()['range-entropy']
    return ent
```

The length of the file can be acquired by setting end to start+1 and simply count up the start character until the result is 0.

Using something like the code below allowed searching for positions where new characters (that have not been used before) are appearing:

```python
newchars = []
lastent = 0
for i in tqdm.tqdm(range(FILE_LEN)):
    ent = getent(0, i)
    if ent != lastent:
        lastent = ent
        newchars.append(i-1)
print(newchars)
```

Using that knowledge allows searching for repititions of those known characters (takes a while):

```python
flag = list([0] * FILE_LEN)
mychars = list(range(1, len(newchars)+1))

for nc, ncp in enumerate(newchars):
    dummyc = mychars[nc]
    flag[ncp] = dummyc

# for every possible position in file
for i in tqdm.tqdm(range(len(flag))):
    # if position is known to be a character that has not occured before or character is already known skip to next position
    if i in newchars or flag[i] != 0:
        continue
    # for each already known character
    for c in set([x for x in flag[:i] if x != 0]):
        # get index of last known position in file/flag
        lastidx = i-(flag[:i][::-1].index(c))-1

        # get number of different characters from known character to tested character
        A = getent(lastidx, i+1)
        # get number of different characters behind known character to tested character
        B = getent(lastidx+1, i+1)

        # if those numbers match the tested character is equal to the already known character
        # mark character in flag, print current state, go back to outer loop
        if A == B:
            flag[i] = c
            print(flag)
            break
```

Trying this out on the flag just results in a weird mess that's not really decodable, but thanks to the given snippet of the Dockerfile we know the main script is called `main.js`.

We also know that it's using deno.

Reading a few deno examples they all start with something like `import * from "https://deno.land/[...]/mod.ts";\n`, `import { [...] } from "https://deno.land/[...]/mod.ts";\n` or `import { [...], [...] } from "https://deno.land/[...]/mod.ts";\n` (and some more very similar lines), so they probably all start with `import` followed by a space, followed by some character, and another space.

The start of the acquired map looks something like this: `[1, 2, 3, 4, 5, 6, 7, 8, 7, 9, 3, 3, 10,`, which perfectly matches the `import ` at the start, including the space.

Applying a simple replacement on those characters easily reveals where the `"https` is since `ttp` is already visible. End of line can easily be found as well since the `.ts"` becomes obvious.
From here on it's basically just filling in all obvious replacements.

Finally we get to some code that looks like this:

```javascript
router.get("/flag", async (ctx) => {
  const auth = ctx.request.headers.get('authorization') ?? '';
  const hasher = createHash("md5");
  hasher.update(auth);
  // NOTE: this is stupid and annoying. remove?
  // FIXME? crackstation.net knows this hash
  if (hasher.toString("hex") === "eX{40}55X{63}dX{64}bX{40}cX{64}a01fad1c3X{40}e45X{63}af4acX{64}5") {
    ctx.response.body = await Deno.readTextFile("flag");
  } else {
    ctx.response.status = 403;
    ctx.response.body = 'go away';
  }
});
```

The `X{num}` placeholders are bytes which have not yet been determined. They where obvisouly digits since it's a hex string and a-f where already known.
Some digits were already known e.g. from the `403` or the `md5`. A few more limitations could be done by looking up the version numbers of the import
statements at the top of the file, which reduced digits to a few lesser possibilities.

I then simply created all possible combinations of replacements, which resulted in ~360 hashes, and tried 20 at a time on crackstation.net.
After a few tries I found `e7552d9b7c9a01fad1c37e452af4ac95` = `gibflag`.

The flag can now be optained using a simple `curl https://[...]/flag -H 'Authorization: gibflag'`:

`ALLES!{is_it_encryption_if_there's_no_key?also_a_bit_too_lossy_for_high_entropy_secrets:MRPPASQHX3b0QrMWH0WF}`

The last few replacements can be made and the full `main.js` can be extracted:

```javascript
import { Application, Router } from "https://deno.land/x/oak@v6.5.0/mod.ts";
import { bold, yellow } from "https://deno.land/std@0.87.0/fmt/colors.ts";
import { createHash } from "https://deno.land/std@0.81.0/hash/mod.ts";

const app = new Application();
const router = new Router();

router.get("/", async (ctx) => {
  ctx.response.body = await Deno.readTextFile("index.html");
});

router.get("/flag", async (ctx) => {
  const auth = ctx.request.headers.get('authorization') ?? '';
  const hasher = createHash("md5");
  hasher.update(auth);
  // NOTE: this is stupid and annoying. remove?
  // FIXME? crackstation.net knows this hash
  if (hasher.toString("hex") === "e7552d9b7c9a01fad1c37e452af4ac95") {
    ctx.response.body = await Deno.readTextFile("flag");
  } else {
    ctx.response.status = 403;
    ctx.response.body = 'go away';
  }
});

router.post("/query", async (ctx) => {
  if (!ctx.request.hasBody) {
    ctx.response.status = 400;
    return;
  }
  const body = ctx.request.body();
  if (body.type !== "json") {
    ctx.response.status = 400;
    ctx.response.body = "expected json body";
    return;
  }
  const { path, start, end } = await body.value;
  const text = await Deno.readTextFile(path);
  const charset = new Set(text.slice(start, end));
  ctx.response.type = "application/json";
  ctx.response.body = JSON.stringify({
    "range-entropy": charset.size,
  });
});

app.use(router.routes());
app.use(router.allowedMethods());

app.addEventListener("listen", ({ hostname, port }) => {
  console.log(
    bold("Start listening on ") + yellow(`${hostname}:${port}`),
  );
});

await app.listen({ hostname: "0.0.0.0", port: 1024 });
```

Overall an interesting challenge, showing how little information is actually required to get the contents of a file with a few known plain-text elements.












