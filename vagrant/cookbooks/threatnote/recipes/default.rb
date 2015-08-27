# Install pip (for python)
execute 'apt-get install python-pip -y' do
  command 'apt-get install python-pip -y'
end

# Configure working environment for Flask
execute 'pip install -r /threatnote/requirements.txt' do
    command 'pip install -r /threatnote/requirements.txt'
end

# Install supervisor service to run web interface
execute 'apt-get install supervisor -y' do
    command 'apt-get install supervisor -y'
end

# Copy the supervisor config file to the right location
cookbook_file "/etc/supervisor/conf.d/threatnote.conf" do
    source "threatnote.conf"
    mode "0644"
end

# Restart the supervisor service
service "supervisor" do
    action [:restart]
end