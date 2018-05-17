import os, sys, configparser
from pyotrs import Client



# Collect args fom call and write them to log file
try:
	_OTRS = os.environ['HOME']
	log_filename = _OTRS + 'var/log/thehive.log' 
	with open(log_filename, 'a') as log_file:
		for arg in sys.argv:
			log_file.write(arg)
		log_file.write("\n")

	TID = sys.argv[2]
except:
	print('Cannot open ', log_filename)


try:
	# open thehive.conf
	config_filename = _OTRS + 'Kernel/GenericInterface/Operation/TheHive/thehive.conf'
	thehiveconf = configparser.ConfigParser()
	thehiveconf.sections()
	thehiveconf.read(config_filename)

	# Generate args
	otrs_args = {}
	#OTRS instance parameters        
	otrs_args['baseurl']  = thehiveconf.get('pyotrs','PYOTRS_BASEURL')
	otrs_args['username'] = thehiveconf.get('pyotrs','PYOTRS_USERNAME')
	otrs_args['password'] = thehiveconf.get('pyotrs','PYOTRS_PASSWORD')
except:
	print('Cannot open ', config_filename)

try:
	client = Client(otrs_args['baseurl'], otrs_args['username'], otrs_args['password'])
	client.session_create()
	client.ticket_get_by_id(TID, articles=True, attachments=True, dynamic_fields=True)
	my_ticket = client.result[0]
	print(my_ticket.articles)
	print(my_ticket.dynamic_fields)

except:
	print('Check PyOTRS')




