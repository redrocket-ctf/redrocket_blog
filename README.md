# RedRocket blog

To create a new post, create a .md file in the \_post folder like this:

```
cp post_template.md _posts/[ISO-DATE]-[TITLE].md
```

Theme is based on whiteglass.

# Build

You can build it with docker.

Build the containter inside the blog directory, or change $PWD accordingly (will take a while, you have to do this only once):

`docker run --name red_blog -v "$PWD":/usr/src/app -w /usr/src/app ruby:2.5-buster bash -c "gem install bundler jekyll && bundle install && bundle exec jekyll build"`

Build the blog (should be fast):

`docker start -a red_blog`

The blog is now saved in the \_site directory.

Copy it to the website with: `scp -r _site/* root@redrocket.club:/var/www/blog.redrocket.club/`

Or: `rsync -ru _site/* root@redrocket.club:/var/www/blog.redrocket.club/`

# View Live
IF you want to see live changes locally to review your writeup, you can do a (once):

`docker run --name red_blog_live -p 4000:4000 -v "$PWD":/usr/src/app -w /usr/src/app ruby:2.5-buster bash -c "gem install bundler jekyll && bundle install && bundle exec jekyll serve --host 0.0.0.0"`

then start the container with `docker start -a red_blog_live`.

You can now watch the blog at `http://localhost:4000`. Changes on files will be tracked and updated live.
