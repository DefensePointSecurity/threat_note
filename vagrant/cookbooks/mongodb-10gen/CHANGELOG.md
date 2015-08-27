# CHANGELOG for mongodb-10gen

This file is used to list changes made in each version of mongodb-10gen.

## 0.2.1

* remove self depends.

## 0.2.0

* apt cookbook v2.5.0 doesn not provide apt-get update every run.
* apt cookbook v2.5.0 does an immediate apt-get update after adding a repository

## 0.1.10

* fix: #6 Error when using a base_dir different of /data/mongodb/ @mgrenonville

## 0.1.9

* fix etc dir in init_mongodb.erb template HT: @alovak

## 0.1.8

* add dummy file due to remote_directory compatibility. HT: @Soulou , @teyrow

## 0.1.7

* apt update immediately when add repository.
* add Kitchenfile for test-kitchen

## 0.1.6

*  #1 replSet is blank in the mongo.conf file. HT: @rbrcurtis

## 0.1.5

*  #2 support debian. HT: @cjblomqvist

- - -
Check the [Markdown Syntax Guide](http://daringfireball.net/projects/markdown/syntax) for help with Markdown.

The [Github Flavored Markdown page](http://github.github.com/github-flavored-markdown/) describes the differences between markdown on github and standard markdown.
