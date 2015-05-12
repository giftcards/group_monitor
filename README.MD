## Synopsis  
  
This is a simple cronjob that alerts zabbix to changes in active directory groups.  
  
## Example  
  
This script should be run periodically on a cronjob. It will connect to the configured domain controller over LDAPS tcp port 636 and search for each of the group names configured. If it has no historical data it will add the groups to the sqlite database, otherwise it will compare what it finds against the database. Any changes are logged by default under /tmp/group_monitor.log. The included zabbix template will monitor this file and alert on changes. *** By default zabbix will not clear on it's own, you'll have to zero the log file to clear it. ***   
  
## Motivation  
  
This was created to satisfy a finding from a penetration test.  
  
## Installation  
  
Script runs in production on CentOS 6 under /local/group_monitor and is scheduled to run every 5 minutes through cron.  
Requires python > 2.6 and ldap, json, and sqlite3 pip modules.  
This script is written in python and requires sqlite support. It will create it's required database on first execution.  
group_monitor.conf should be copied to /etc/ and modified for your environment.  
The xml template should be imported into zabbix and assigned to the server that runs the cron job.   
As written this requires the signing cert be available for the certificate used by the LDAPS service on the domain controller. You can change this certificate on the domain controller through the service accounts option in the certificate mmc snapin. Typically it defaults to the first certificate assigned to the domain controller.  
  
## Contributors  
  
Ryan Munz for Giftcards.com - May 2015   
