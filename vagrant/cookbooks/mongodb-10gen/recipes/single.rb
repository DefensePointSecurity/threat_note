include_recipe "mongodb-10gen::default"


directory File.join(node['mongodb']['data_dir'], node['mongodb']['nodename']) do
  owner "mongodb"
  group "mongodb"
  mode 00700
end

directory File.join(node['mongodb']['log_dir']) do
  owner "mongodb"
  group "mongodb"
  mode 00755
end

template File.join("/etc/init", "#{node['mongodb']['nodename']}.conf") do
  source "init_mongodb.erb"
  owner "root"
  group "root"
  mode 00644
  variables({
    :nodename => node['mongodb']['nodename']
  })
end

template File.join("/etc/logrotate.d", node['mongodb']['nodename']) do
  source "logrotate_mongodb.erb"
  owner "root"
  group "root"
  mode 00644
  variables({
    :nodename => node['mongodb']['nodename']
  })
end

template File.join(node['mongodb']['etc_dir'], "#{node['mongodb']['nodename']}.conf") do
  source "mongodb.conf.erb"
  owner "mongodb"
  group "mongodb"
  mode 00600
  variables({
    :nodename => node['mongodb']['nodename'],
        :port => node['mongodb']['port'],
        :replSet => node['mongodb']['replSet']
  })
  notifies :restart, "service[#{node['mongodb']['nodename']}]"
end


service node['mongodb']['nodename'] do
  case node['platform']
  when "ubuntu"
    if node['platform_version'].to_f >= 9.10
      provider Chef::Provider::Service::Upstart
    end
  end
  action [:enable, :start]
end

