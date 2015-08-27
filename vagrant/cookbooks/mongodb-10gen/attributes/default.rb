## choose version as package name
# mongodb18-10gen, mongodb20-10gen,mongodb-10gen
default['mongodb']['nodename'] = "mongodb"
default['mongodb']['package'] = "mongodb-10gen"
default['mongodb']['port']   = 27017
default['mongodb']['log_verbose']   = false
default['mongodb']['log_cpu']   = true

default['mongodb']['enable_shardsvr'] = true
default['mongodb']['enable_configsvr'] = false
default['mongodb']['enable_rest'] = true
default['mongodb']['enable_jsonp'] = false
default['mongodb']['enable_nojournal'] = false
default['mongodb']['enable_directoryperdb'] = true
default['mongodb']['oplogSize'] = 5120

default['mongodb']['base_dir'] = '/data/mongodb'
default['mongodb']['etc_dir'] = File.join(node['mongodb']['base_dir'], "etc")
default['mongodb']['log_dir'] = File.join(node['mongodb']['base_dir'], "log")
default['mongodb']['data_dir'] = File.join(node['mongodb']['base_dir'], "db")
default['mongodb']['misc_dir'] = File.join(node['mongodb']['base_dir'], "misc")


## for replica sets

default['mongodb']['isreplica'] = false
default['mongodb']['replSet']   = "replica" ## dummy

### multi instance option

default['mongodb']['rep_prefix']   = "rep"
default['mongodb']['rep_fromid']   = 1   # rep01,rep02...
default['mongodb']['multi_prefix']   = "mongodb"
default['mongodb']['multi_num']     = 3
default['mongodb']['port_base']   = 27017
default['mongodb']['port_step']   = 2000

## for config node

default['mongodb']['config']['nodename'] = "mongodb_config"
default['mongodb']['config']['port'] = 27019
default['mongodb']['config']['log_verbose']   = false
default['mongodb']['config']['log_cpu']   = true

default['mongodb']['config']['enable_shardsvr'] = false
default['mongodb']['config']['enable_configsvr'] = true
default['mongodb']['config']['enable_rest'] = true
default['mongodb']['config']['enable_jsonp'] = false
default['mongodb']['config']['enable_nojournal'] = false
default['mongodb']['config']['enable_directoryperdb'] = true
default['mongodb']['config']['oplogSize'] = 5120


## for mongos
default['mongodb']['router']['nodename'] = "mongos"
default['mongodb']['router']['port'] = 27018
default['mongodb']['router']['configdb'] = ["localhost:27019"]
default['mongodb']['router']['log_verbose']   = false

