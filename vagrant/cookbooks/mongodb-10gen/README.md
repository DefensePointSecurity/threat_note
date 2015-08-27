Description
===========

[![Build Status](https://secure.travis-ci.org/higanworks-cookbooks/mongodb-10gen.png)](http://travis-ci.org/higanworks-cookbooks/mongodb-10gen)

Add apt repository and install mongodb-10gen. 

## Platform

* ubuntu
* debian

### Tested on

* ubuntu 12.04(precise)

Requirements
============

- OpscodeCookbook[apt]


Attributes
==========

### group ['mongodb']

update your mongodb.conf values

### group ['mongodb']['config']

update your mongodb_config.conf values

### group ['mongodb']['router']

update your mongos.conf values

Usage
=====

### Available recipes

#### default

- Add 10gen official repository and install newer stable mongodb.
- **disable** autostart when install or serverboot.

#### single

- setup mongodb single node.

#### config

- setup mongodb config node.

#### router

- setup mongodb router(mongos) node.

Additions
=====

### mongorc.js

Print information to prompt.  

Usage: `cp {mongo_dir}misc/mongorc.js ~/.mongorc.js`

<pre><code># mongo
MongoDB shell version: 2.0.4
connecting to: test
s01:PRIMARY:[2.0.4] > </code></pre>


Author
====


Author:: HiganWorks LLC (<sawanoboriyu@higanworks.com>)
