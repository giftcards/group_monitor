#!/usr/bin/python
import ldap
import json
import sqlite3
import datetime
import ConfigParser
from time import sleep

# Timestamps
print "Running Checks : %s" % str(datetime.datetime.now())

# Read our config file
config = ConfigParser.RawConfigParser()
config.read('/etc/group_monitor.conf')

# Set our base variables
server = config.get('ldap', 'server') 
base = config.get('ldap', 'base')
binddn = config.get('ldap', 'binddn')
bindpw = config.get('ldap', 'bindpw')
cacert = config.get('ldap', 'cacert')
grouplist = config.items('grouplist')
# Set where the zabbix alert is put
zabbixfile = config.get('zabbix', 'file')
# Path to our database file
db = config.get('sqlite', 'db')
# Tablenames to use
group_table = config.get('sqlite', 'group_table') 
group_changes_table = config.get('sqlite', 'group_changes_table')
# Used to create our initial tables if need be
create_tables=["CREATE TABLE %s (_id INTEGER PRIMARY KEY AUTOINCREMENT, grp TEXT UNIQUE, json TEXT)" % group_table,
               "CREATE TABLE %s (_id INTEGER PRIMARY KEY AUTOINCREMENT, grp TEXT, log TEXT)" % group_changes_table]
# Used to query to grp/json table data
get_stored_groups = "SELECT grp,json FROM %s" % group_table
# Used to update grp/json table data
update_stored_group = "UPDATE %s SET json = ? WHERE grp == ?" % group_table
# Used to create grp/json table data
create_stored_group = "INSERT INTO %s (grp, json) VALUES (?, ?)" % group_table
# Used to log changes
log_group_changes = "INSERT INTO %s (grp, log) VALUES (?, ?)" % group_changes_table

# We have to setup ca options and the opt_referrals workaround for this to talk tls to ad correctly
# The ca.pem file is setup by puppet in authldap
#ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacert)
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
ldap.set_option(ldap.OPT_REFERRALS, 0)
ldap.protocol_version = 3

# Open the zabbix alert file
zabbix = open(zabbixfile, 'a')

# Setup our sqlite connection
sql_conn = sqlite3.connect(db)
sql_conn.text_factory = str
cur = sql_conn.cursor()

# Try to create our tables but if they're already there that's okay
try:
    for table_sql in create_tables :
        cur.execute(table_sql)
        #print "Ran Table Creation : %s : on db : %s" % (table_sql, db)
except sqlite3.OperationalError as e:
    #print "Found Database : %s" % db
    pass

# Now (assuming there's anything there) we need to get our old group memberships out of sqlite
cur.execute(get_stored_groups)
stored_group_data = cur.fetchall()

# Now that we have the raw data we need to convert to our dictionary object
# SQLAlchemy would have been a better choice but this will do
stored_group_members = dict()
# Don't name this json, will override the json library object
for group, member_json in stored_group_data :
    stored_group_members[group]=json.loads(member_json)

# Alright, let's setup our ldap connection
#print "Connecting to : %s" % server
# You can set trace_level=2 here for more debugging info
l = ldap.initialize(server)
#print "Complete!"
#print "Binding : %s" % binddn
l.simple_bind(binddn, bindpw)
# There's a bug in python-ldap where ad doesn't believe the bind is complete causing search to fail
sleep(1)
#print "Complete!"

# Okay, setup our results dict
found_group_members = dict()

for key, group in grouplist :
    # Look for items with a CommonName of our grouplist
    filter = "cn="+group

    # Run our actual search
    result_id = l.search(base, ldap.SCOPE_SUBTREE, filter)
    result_type, result_data = l.result(result_id, 0)

    # Make sure we actually found the group
    if (result_data == []) :
        print "!!! Group Not Found In LDAP !!! : %s" % filter
        found_group_members[group]=[]
        continue

    # python-ldap search returns a turducken of a dict inside a tuple inside a list to get attributes
    try:
        attributes = result_data[0][1]
        found_group_members[group]=attributes['member']
    except KeyError:
        found_group_members[group]=[]

# Do our comparison between lists
for group in found_group_members :
    sql_update = False

    print "Checking Group : %s" % group
    try:
        if found_group_members[group] != stored_group_members[group] :
            print "ALERT ZABBIX Group Change : %s" % group
            print "ALERT ZABBIX Old Members : %s" % str(stored_group_members[group])
            print "ALERT ZABBIX New Members : %s" % str(found_group_members[group])
            change_log = "%s : Group Change : \nOld Members : %s\nNew Members : %s\nALERT ZABBIX\n" % \
                         (str(datetime.datetime.now()), str(stored_group_members[group]), str(found_group_members[group]))
            # This is bad, tell zabbix
            zabbix.write(change_log)
            sql_update = True
    except KeyError:
        print "Group Not Found In Storage : %s" % group
        change_log = "%s : Group Added : %s\n" % (str(datetime.datetime.now()), group)
        sql_update = True

    if sql_update == False :
        # If there's no updates to be made we can skip our sql bits
        print "No Changes Found : %s" % group
        continue

    # Write our changelog to the db
    print "Logging : %s" % change_log
    cur.execute(log_group_changes, (group, change_log)) 

    # Write our updated data
    member_json = json.dumps(found_group_members[group])
    try:
        # Try to create the group, this has to be first as update will fail silently
        cur.execute(create_stored_group, (group, member_json))
        #print "Created Group : %s" % group
    except sqlite3.IntegrityError:
        # Catch if the row already exists, then update it
        #print "Updating Group : %s" % group
        cur.execute(update_stored_group, (member_json, group))

    # Commit our changes
    sql_conn.commit()

# Clean everything up
zabbix.close()
sql_conn.close()
print "Finished : %s" % str(datetime.datetime.now()) 
