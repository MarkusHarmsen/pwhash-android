PwHash (android)
=============

PwHash is a simple password generator which uses well-known algorithms
to generate a strong unique password for any service based on a given (master) password.

You simply enter the current service tag as well as your (master) password to generate a strong hash
which is copied to clipboard and can now be used as login password.

There also exists an [HTML](https://github.com/MarkusHarmsen/pwhash-html),  [GTK](https://github.com/MarkusHarmsen/pwhash-gtk) and [Bash](https://github.com/MarkusHarmsen/pwhash-bash) version of pwhash.


Example
------------
Tag: facebook
Password: myDefaultPassword

Resulting hash: wb9dnpOCUIas5xGJ


How does it work?
------------
PwHash uses HMAC (SHA1) + Base64 to generate the hash.
It is compatible to other services like [hashapass](http://hashapass.com/).


Note
------------
This program has a crappy UI ;)
