#
## Cookbook Name:: monit_bin
## Recipe:: default
##
## Copyright (C) 2012 HiganWorks LLC
## 
## Permission is hereby granted, free of charge, to any person obtaining
## a copy of this software and associated documentation files (the
## "Software"), to deal in the Software without restriction, including
## without limitation the rights to use, copy, modify, merge, publish,
## distribute, sublicense, and/or sell copies of the Software, and to
## permit persons to whom the Software is furnished to do so, subject to
## the following conditions:
## 
## The above copyright notice and this permission notice shall be
## included in all copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
## MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
## NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
## LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
## OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
## WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

include_recipe "apt"

apt_repository "mongodb-10gen" do
  case node["platform"]
  when "ubuntu"
    uri "http://downloads-distro.mongodb.org/repo/ubuntu-upstart"
  when "debian"
    uri "http://downloads-distro.mongodb.org/repo/debian-sysvinit"
  end
  distribution "dist"
  components ["10gen"]
  keyserver "keyserver.ubuntu.com"
  key "7F0CEB10"
  action :add
end


file "/etc/default/mongodb" do
  action :create_if_missing
  owner "root"
  content "ENABLE_MONGODB=no"
end

# cookbook apt has bug ?
# apt-get update notifies does not work.
# here is work around.
if node['chef_packages']['chef']['version'] < "10"
  execute "apt-get update" do
    command "apt-get update"
    ignore_failure true
    action :run
  end

  file "/etc/apt/sources.list.d/mongodb-10gen.update-once.list" do
    action :create_if_missing
    notifies :run, "execute[apt-get update]", :immediately
  end
end

package node['mongodb']['package'] do
  action :install
end

directory "/data" do
  group "root"
  owner "root"
  mode 00755
end

remote_directory node['mongodb']['base_dir'] do
  source "mongodb"
  files_group "mongodb"
  files_owner "mongodb"
  files_mode 00644
  owner "mongodb"
  group "mongodb"
  mode 00755
  recursive true
end

log "created mongodb base_dir #{node['mongodb']['base_dir']}" if resources("remote_directory[#{node['mongodb']['base_dir']}]").updated?
