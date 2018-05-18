#!/bin/bash
echo $(date +"%Y%m%d %T")",TN:"$1",TID:"$2 >> /opt/otrs/var/log/GenericAgent.log
/usr/bin/python3 otrs2thehive.py /opt/otrs/ $2 >> /opt/otrs/var/log/otrs2thehive.log
