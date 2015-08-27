include_recipe "mongodb-10gen::default"

# node.set['mongodb']['node_type'] = "router"
# node.load_attribute_by_short_filename("default","mongodb-10gen")

directory File.join(node['mongodb']['data_dir'], node['mongodb']['router']['nodename']) do
  owner "mongodb"
  group "mongodb"
  mode 00700
end

directory File.join(node['mongodb']['log_dir']) do
  owner "mongodb"
  group "mongodb"
  mode 00755
end

template File.join("/etc/init", "#{node['mongodb']['router']['nodename']}.conf") do
  source "init_mongos.erb"
  owner "root"
  group "root"
  mode 00644
  variables({
    :nodename => node['mongodb']['router']['nodename'],
  })
end

template File.join("/etc/logrotate.d", node['mongodb']['router']['nodename']) do
  source "logrotate_mongodb.erb"
  owner "root"
  group "root"
  mode 00644
  variables({
    :nodename => node['mongodb']['router']['nodename'],
  })
end

template File.join(node['mongodb']['etc_dir'], "#{node['mongodb']['router']['nodename']}.conf") do
  source "mongos.conf.erb"
  owner "mongodb"
  group "mongodb"
  mode 00600
  variables({
    :nodename => node['mongodb']['router']['nodename'],
        :port => node['mongodb']['router']['port'],
  })
  notifies :restart, "service[#{node['mongodb']['router']['nodename']}]"
end


service node['mongodb']['router']['nodename'] do
  case node['platform']
  when "ubuntu"
    if node['platform_version'].to_f >= 9.10
      provider Chef::Provider::Service::Upstart
    end
  end
  action [:enable, :start]
end

