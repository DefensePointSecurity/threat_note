prompt = function() {
  // set version
  version = db.version();

  // case mongos
  if (rs.status().info == 'mongos') {
    return rs.status().info + ':[' + version + '] > ';
  }

  // config or replica
  if (rs.status().set) {
    role = rs.status().set;
  } else if (db.serverCmdLineOpts().parsed.configsvr) {
    role = 'config';
    return role + ':[' + version + '] > ';
  } else {
    role = 'single';
    return role + ':[' + version + '] > ';
  }
  
  // for replicasets
  switch (rs.status().myState) {
    case 1:
      stateStr = 'PRIMARY'
      break;
  
    case 2:
      stateStr = 'SECONDARY'
      break;
  
    case 7:
      stateStr = 'ARBITER'
      break;
    }
  return role + ':' + stateStr + ':[' + version + '] > ';
}

