#!/usr/bin/python3
#
# otrs2thehive.py - Get OTRS ticket metadata and create new case in TheHive
#
# Author: Remi Seguy <remg427@gmail.com>
# Copyright: GPLv3 (http://gplv3.fsf.org)
# Fell free to use the code, but please share the changes you've made
#
# From imap2thehive.py authored by Xavier Mertens <xavier@rootshell.be>
# 

from __future__ import print_function
from __future__ import unicode_literals
import configparser
import os,sys
import io
import chardet
import time,datetime
import json
import requests
import uuid
import tempfile
import re

try:
	from pyotrs import Article, Client, Ticket, DynamicField

except:
	log_ts = datetime.datetime.now()
	print("%s [ERROR] Please install PyOTRS (REST version)." % log_ts)
	sys.exit(1)

try:
	from thehive4py.api import TheHiveApi
	from thehive4py.models import Case, CaseTask, CaseObservable, CustomFieldHelper
	from thehive4py.models import Alert, AlertArtifact
except:
	log_ts = datetime.datetime.now()
	print("%s [ERROR] Please install thehive4py." % log_ts)
	sys.exit(1)

__author__     = "Remi Seguy"
__license__    = "GPLv3"
__version__    = "1.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"
__name__       = "otrs2thehive"

# Default configuration 
args = ''
config = {
	'otrsURL'           : '',
	'otrsUser'          : '',
	'otrsPassword'      : '',
	'otrsTLSCheck'      : True,
	'otrsCert'          : '',

	'thehiveURL'        : '',
	'thehiveKey'        : '',
	'thehiveTLP'        : 'TLP:RED',
	'caseObservables'   : False,
	'thehiveTLSCheck'   : True, 
	'thehiveCaseTags'   : '', 
	'thehiveTemplate'   : '', 
	'thehiveObservable' : '', 
	'thehiveCustomTags' : '',
	'thehiveSeverity'   : ''
}

def slugify(s):
	'''
	Sanitize filenames
	Source: https://github.com/django/django/blob/master/django/utils/text.py
	'''
	s = str(s).strip().replace(' ', '_')
	return re.sub(r'(?u)[^-\w.]', '', s)

def searchObservables(buffer, observables):
	'''
	Search for observables in the buffer and build a list of found data
	'''
	# Observable types
	# Source: https://github.com/armbues/ioc_parser/blob/master/iocp/data/patterns.ini
	observableTypes = [
		 { 'type': 'filename', 'regex': r'\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b' },
		 { 'type': 'url',      'regex': r'\b([a-z]{3,}\:\/\/[a-z0-9.\-:/?=&;]{16,})\b' },
		 { 'type': 'ip',       'regex': r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b' },
		 { 'type': 'fqdn',     'regex': r'\b(([a-z0-9\-]{2,}\[?\.\]?){2,}(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw))\b' },
		 { 'type': 'domain',   'regex': r'\b(([a-z0-9\-]{2,}\[?\.\]?){1}(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw))\b' },
		 { 'type': 'mail',     'regex': r'\b([a-z][_a-z0-9-.+]+@[a-z0-9-.]+\.[a-z]+)\b' },
		 { 'type': 'hash',     'regex': r'\b([a-f0-9]{32}|[A-F0-9]{32})\b' },
		 { 'type': 'hash',     'regex': r'\b([a-f0-9]{40}|[A-F0-9]{40})\b' },
		 { 'type': 'hash',     'regex': r'\b([a-f0-9]{64}|[A-F0-9]{64})\b' }
		 ]

	for o in observableTypes:
		for match in re.findall(o['regex'], buffer, re.MULTILINE|re.IGNORECASE):
			# Bug: If match is a tuple (example for domain or fqdn), use the 1st element
			if type(match) is tuple:
				match = match[0]

			# Bug: Avoid duplicates!
			if not {'type': o['type'], 'value': match } in observables:
				observables.append({ 'type': o['type'], 'value': match })
				if log_level > 1:
					log_ts = datetime.datetime.now()
					print('%s [INFO] Found observable %s: %s' % (log_ts, o['type'], match))
			else:
				if log_level > 1:
					log_ts = datetime.datetime.now()
					print('%s [INFO] Ignoring duplicate observable: %s' % (log_ts, match))
	return observables

def excludeObservables(exclusion_list, observables):
	newObservables = []
	if log_level == 3:
		log_ts = datetime.datetime.now()
		print('%s [DEBUG] observable list contains %s before exclusion' % (log_ts, str(observables)))

	for o in observables:
		noMatch = True
		if log_level == 3:
			log_ts = datetime.datetime.now()
			print('%s [DEBUG] Found observable type: %s and value: %s' % (log_ts, o['type'], o['value']))

		for e in exclusion_list:
			if noMatch:
				if log_level == 3:
					log_ts = datetime.datetime.now()
					print('%s [DEBUG] testing regex  %s ' % (log_ts, e))
				if re.search(e, o['value']):
					if log_level > 1:
						log_ts = datetime.datetime.now()
						print('%s [INFO] Found match on %s for value: %s, removing from observables' % (log_ts, e, o['value']))
					noMatch = False

		if noMatch:
			newObservables.append(o)
#		#if log_level > 1:
#			log_ts = datetime.datetime.now()
#			print('%s [INFO] no match for value: %s, kept in observables' % (log_ts, o['value']))
	if log_level == 3:
		log_ts = datetime.datetime.now()
		print('%s [DEBUG] observable list contains %s after exclusion' % (log_ts, str(newObservables)))

	return newObservables

def submitTheHive(newCase):

	'''
	Create a new case in TheHive based on the OTRS ticket
	Return the case ID if successfully processed otherwise '-1'
	'''
	TLP = { 'TLP:WHITE': 0, 'TLP:GREEN': 1, 'TLP:AMBER': 2, 'TLP:RED': 3 }
	api = TheHiveApi(config['thehiveURL'], config['thehiveKey'], cert=config['thehiveTLSCheck'])

	#Prepare default values for the case
	caseTitle       = 'Case from OTRS'
	caseTLP         = TLP[config['thehiveTLP']]
	caseDescription = ''
	caseDelims      = ''
	caseTemplate    = config['thehiveTemplate']
	caseTags        = config['thehiveCaseTags']
	caseObservables = []
	# default values for custom fields
	caseSource      = 'OTRS'
	caseTimestamp   = 'not provided'

	#Modify default value with data from OTRS ticket
	caseTitle    = newCase['TicketNumber'] + ': ' + newCase['Title']
	caseSeverity = config['thehiveSeverity'][newCase['Priority']]
	caseTags.append('ticket:id='+newCase['TicketID'])
	caseTags.append('ticket:ref='+newCase['TicketNumber'])
	
	if 'Article' in newCase:
		for article in newCase['Article']:
			if article['SenderType'] != 'system' :
				caseDescription = caseDescription + caseDelims
				caseDelims = '\n\n____\n\n'
				if 'CreateTime' in article:   #OTRS 6.x
					caseDescription = caseDescription + article['CreateTime'] + ' - '
				elif 'Created' in article:    #OTRS 5.x
					caseDescription = caseDescription + article['Created'] + ' - '
				caseDescription = caseDescription + 'From: ' + article['From'] + '\n\n'
				caseDescription = caseDescription + article['Body']
				caseObservables = searchObservables(article['Body'], caseObservables)
		# if some observables have been found in articles, check if they have to be excluded
		if caseObservables:
			caseObservables = excludeObservables(exclusion, caseObservables)


	if 'DynamicField' in newCase:
		for DF in newCase['DynamicField']:
			if DF['Name'] == 'TLP':
				if DF['Value']:
					caseTLP = TLP[DF['Value']]
			elif DF['Name'] == 'TheHiveCaseTemplate':
				if DF['Value']:
					caseTemplate = DF['Value']
			elif DF['Name'] == config['thehiveObservable']:
				if DF['Value']:
					caseObservables = searchObservables(DF['Value'],caseObservables)
			elif DF['Name'] == config['thehiveCustomTags']:
				if DF['Value']:
					for v in DF['Value'].split(','):
						caseTags.append(v)

	# Prepare case structure
	case = Case(title        = caseTitle,
				tlp          = caseTLP,
				severity     = caseSeverity,
				flag         = False,
				tags         = caseTags,
				description  = caseDescription,
				template     = caseTemplate)

	# Create the case
	id = None
	response = api.create_case(case)
	if response.status_code == 201:
		newID = response.json()['id']
		caseId = response.json()['caseId']
		log_ts = datetime.datetime.now()
		print('%s [INFO] Created case %s' % (log_ts, caseId))
		#
		# Add observables provided in the DynamicField Observable if any
		#
		if len(caseObservables) > 0:
			for o in caseObservables:
				observable = CaseObservable(
					dataType = o['type'],
					data     = o['value'],
					tlp      = caseTLP,
					ioc      = False,
					tags     = caseTags,
					message  = 'Listed as Observable'
					)
				response = api.create_case_observable(newID, observable)
				if response.status_code == 201:
					if log_level > 1:
						log_ts = datetime.datetime.now()
						print('%s [INFO] Added observable %s: %s to case ID %s' % (log_ts, o['type'], o['value'], newID))
				else:
					if log_level > 0:
						log_ts = datetime.datetime.now()
						print('%s [WARNING] Cannot add observable %s: %s - %s (%s)' % (log_ts, o['type'], o['value'], response.status_code, response.text))
	else:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Cannot create case: %s (%s)' % (log_ts, response.status_code, response.text))
		return -1
	return int(caseId)

def main():
	global args
	global config
	global log_level
	global exclusion


	# Collect args fom call and open log file
	try:
		_OTRS = sys.argv[1]
		TID = sys.argv[2]
		log_level = 0

		# open thehive.conf
		config_filename = _OTRS + '/Kernel/GenericInterface/Invoker/TheHive/otrs2thehive.conf'
		if not os.path.isfile(config_filename):
			log_ts = datetime.datetime.now()
			print('%s [ERROR] Configuration file %s is not readable.' % (log_ts, config_filename))
			sys.exit(1);
		c = configparser.ConfigParser()
		c.read(config_filename)

	except OSError as e:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Cannot read config file %s: %s' % (log_ts, config_filename, e.errno))
		sys.exit(1)

	# Generate args
	config = {}
	# Global settings
	if c.has_option('global', 'LOG_LEVEL'):
		log_level = c.getint('global', 'LOG_LEVEL')
	else:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Configuration file has no option LOG_LEVEL.' % log_ts)


	#OTRS config
	if c.has_option('pyotrs','PYOTRS_BASEURL'):
		config['otrsURL']          = c.get('pyotrs','PYOTRS_BASEURL')
	else:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Configuration file has no option PYOTRS_BASEURL.' % log_ts)

	config['otrsUser']         = c.get('pyotrs','PYOTRS_USERNAME')
	config['otrsPassword']     = c.get('pyotrs','PYOTRS_PASSWORD')
	config['otrsTLSCheck']     = c.getboolean('pyotrs','PYOTRS_HTTPS_VERIFY')
	config['otrsCert']         = c.get('pyotrs','PYOTRS_CA_CERT_BUNDLE')

	# TheHive Config
	config['thehiveURL']       = c.get('thehive', 'THEHIVE_BASEURL')
	config['thehiveKey']       = c.get('thehive', 'THEHIVE_APIKEY')
	config['thehiveTLSCheck']  = c.getboolean('thehive', 'THEHIVE_TLS_CHECK')
	config['thehiveCaseTags']  = c.get('thehive', 'THEHIVE_CASETAGS').split(',')
	config['thehiveTemplate']  = c.get('thehive', 'THEHIVE_TEMPLATE')
	config['thehiveTLP']       = c.get('thehive', 'THEHIVE_TLP')
	config['thehiveObservable']= c.get('thehive', 'THEHIVE_OBSERVABLE_DF')
	config['thehiveCustomTags']= c.get('thehive', 'THEHIVE_CUSTOMTAGS_DF')
	config['thehiveSeverity']  = eval(c.get('thehive', 'THEHIVE_SEVERITY'))

	exclusion = []
	exclusion_filename = ''
	if c.has_option('thehive', 'THEHIVE_NOTOBS_REX'):
		exclusion_filename = c.get('thehive', 'THEHIVE_NOTOBS_REX')
	else:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Cannot find option NOTOBS_REX in section thehive' % log_ts)

	try:
		if not os.path.isfile(exclusion_filename) and log_level > 0:
			log_ts = datetime.datetime.now()
			print('%s [WARNING] file %s is not readable. no exclusion in observables based on regex' % (log_ts, exclusion_filename))
		else:
			# open exclusion_filename
			with open(exclusion_filename) as exclusion_file:
				# collect the list of regex to exclude observables from the extracted list
				exclusion = exclusion_file.read().splitlines() 
			if log_level == 3:
				log_ts = datetime.datetime.now()
				print('%s [DEBUG] read file %s and imported %s in exclusion list' % (log_ts, exclusion_filename, str(exclusion)))
			elif log_level == 2:
				log_ts = datetime.datetime.now()
				print('%s [INFO] read file %s and imported %s strings in exclusion list' % (log_ts, exclusion_filename, len(exclusion)))

	except OSError as e:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Cannot read config file section NOTOBS_REX: %s' % (log_ts, e.errno))
		sys.exit(1)





	try:
		#Get OTRS ticket 
		client = Client(config['otrsURL'], config['otrsUser'], config['otrsPassword'], https_verify=config['otrsTLSCheck'])
		client.session_create()
		t = client.ticket_get_by_id(TID, articles=True, attachments=True, dynamic_fields=True).to_dct()

	except:
		print('%s [ERROR] Cannot get OTRS ticket content for Ticket ID %s using URL %s and User: %s' % (log_ts, TID, config['otrsURL'], config['otrsUser']))
		sys.exit(1)

	#Build newCase dict
	otrsCase = {}
	otrsCase = t['Ticket']
	if log_level > 2:
		log_ts = datetime.datetime.now()
		print("%s [DEBUG] %s" % (log_ts, str(json.dumps(t, indent=4))))

	if 'DynamicField' in otrsCase:
		thehiveNoCase = False
		for df in otrsCase['DynamicField']:
			if df['Name'] == 'TheHiveAction':    #Get the command set in TheHiveAction dynamic field
				thehiveAction = df['Value']
			if df['Name'] == 'TheHiveCaseId':
				if not df['Value']:              #Verify that no TheHive case has been created yet
					thehiveNoCase = True

		if thehiveAction == 'A1':
			if thehiveNoCase:  # Valid request to create a case in TheHive
				TheHiveCaseId = submitTheHive(otrsCase)
				if TheHiveCaseId > 0:
					df = DynamicField("TheHiveCaseId", str(TheHiveCaseId))
					client.ticket_update(TID, dynamic_fields=[df])
				else:
					log_ts = datetime.datetime.now()
					print('%s [ERROR] The case could not be created in TheHive.' % log_ts)			
			df = DynamicField("TheHiveAction", "A0")  # change TheHiveAction dynamic field back to 'Do nothing'
			client.ticket_update(TID, dynamic_fields=[df])
	else:
		log_ts = datetime.datetime.now()
		print('%s [ERROR] Dynamic fields not collected - check they are activated for tickets.' % log_ts)
	return

if __name__ == 'otrs2thehive':
	main()
	sys.exit(0)


