# RedRocket blog

To create a new post, create a .md file in the \_post folder like this:

```
cp post_template.md _posts/[ISO-DATE]-[TITLE].md
```

Theme is based on whiteglass.

# Build

You can build it with docker.

Build containter (will take a while, you have to do this only once):

`docker run --name red_blog -v "$PWD":/usr/src/app -w /usr/src/app ruby:2.5-buster bash -c gem install bundler jekyll && bundle install && bundle exec jekyll build`

Build the blog (should be fast):

`docker start -a red_blog`

The blog is now saved in the \_site directory.

Copy it to the website with: `scp _site/* redrocket.club:/var/www/blog.redrocket.club/`
