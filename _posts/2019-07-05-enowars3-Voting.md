---
layout: post
category: web
title: Enowars3 - Voting
tags: 
    - kauzu
---


"Voting" was a web service at the Enowars3 attack/defense CTF.

```
tl;dr 
Flagbot username was public. Cookies were sha512() of flagbot username
``` 

The service was written in Python with an sqlite db and flask. You could register an account and then vote yes/no to some default votes and also create your own votes. When creating your own votes you could place a secret message there, which was only printet when the creator of a vote was visiting the vote page.


```html
{% raw %}
{% if session[2] == pollCreator and pollCreatorsNotes|length > 0 %}
	<h3>Your private notes</h3>
	<p>{{ pollCreatorsNotes }}</p>
{% endraw %}
```

The login function was really simple

```python
def login(userName, password):
	if auth(userName, password):
		return createSessionAuthenticated(userName)
	return None
```
here it was already obvious that the cookie only depends on the username.

```python
def createSessionAuthenticated(userName):
	h = hashlib.sha512()
	h.update(str.encode(userName))
	sid = h.hexdigest()

	db = sqlite3.connect("data.sqlite3")
	c = db.cursor()
	c.execute("INSERT OR REPLACE INTO sessions VALUES (:sid, (SELECT datetime('now','+1 hour')), :userName);", {"sid": sid, "userName": userName})
	db.commit()
	db.close()

	return (sid, 3600)
```
Looking at createSessionAuthenticated() confirmed this. My "fix" :D was really simple then.


```python
#h.update(str.encode(userName))
h.update(str.encode(userName+"dsjkflsjdflskjdfsklfjskljflsjfjsfljredrocket"))
```

No exploit script here. The code is kind of messy and really boring. Just read the vote id's from /index.html -> read the vote creators usernames -> sha512(username) -> read the flag



 



