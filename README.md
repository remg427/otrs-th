# OTRS-TH - WIP
Caution: this is Work in Progress - this version is released as the first one working to create a case in TheHive from OTRS

The objective of this project is to build a connector between OTRS and Thehive_projet

# OTRS to TheHive
## Installation
* install Python3
* install [PyOTRS](https://pypi.python.org/pypi/PyOTRS)
* install [thehive4py](https://github.com/TheHive-Project/TheHive4py)
* create dynamic fields
	- TheHiveAction: dropdown list with following keys
	    * Key: __A0__ Value: Do nothing
		* Key: __A1__ Value: Create case in TheHive 
	- TheHiveCaseTemplate: dropdown list with the cases you have created in TheHive
	- TheHiveCaseId: text field
	- TheHiveTags: text field to provide a list of tags (comma , separated)

* you also need 2 additional dynamic fields:
    - __TLP__: dropdown list with keys and values set to TLP levels i.e TLP:WHITE to TLP:RED
	- Observable: text area to store observables (one per line). you may select another existing dynamic field for this in configuration file(see below)

* copy files in /opt/otrs/Kernel/GenericInterface/Invoker/TheHive/
	- thehive.sh
	- otrs2thehive.conf
	- otrs2thehive.conf
* edit thehive.sh and adapt as required
* edit otrs2thehive.conf

	[pyotrs]

		PYOTRS_BASEURL=http://127.0.0.1
		PYOTRS_USERNAME=root@localhost    <=== needs to be admin
		PYOTRS_PASSWORD=changeme
		PYOTRS_HTTPS_VERIFY=True
		PYOTRS_CA_CERT_BUNDLE=

	[thehive]

		THEHIVE_BASEURL=http://172.22.0.3:9000
		THEHIVE_APIKEY=kV246jl05vzgXvamzsNZDnQcBHjRshh5
		THEHIVE_TLS_CHECK=False
		THEHIVE_CASETAGS=otrs   <= here you can list tags e.g. tag1,tag2,tag3; they will be added to all cases
		THEHIVE_TEMPLATE=OTRS   <= default case template to use
		THEHIVE_TLP=TLP:RED     <= default TLP level
		THEHIVE_OBSERVABLE_DF=Observable   <= or another dynamic fields where to store observables in OTRS
		THEHIVE_CUSTOMTAGS_DF=TheHiveTags  <= a custom list of tags can be passed for each ticket
		THEHIVE_SEVERITY={'1 very low': 1, '2 low': 1, '3 normal': 1, '4 high': 2, '5 very high': 3}
		For last one, you have to list the Priority levels in OTRS and decide to which level to map in TheHive (Low=1, Medium=2, High=3)

* Create a job in generic agent to launch the script /opt/otrs/Kernel/GenericInterface/Invoker/TheHive/thehive.sh
    - if successful, then a case is created in TheHive and the case ID is set in OTRS TheHiveCaseId field (and TheHiveAction set back to A0)
    - there are some logging (to be improved) in /opt/otrs/var/log/


## TheHive to OTRS
From TH, to be able to update an OTRS ticket (metadata, add article, list of observable, attachments).

# Technical aspects
Given that both products have a Python interface, develop the connector using this language.
## Prerequisite on OTRS
* install the [RESTful Generic interface in webservices ](https://github.com/OTRS/otrs/blob/master/development/webservices/GenericTicketConnectorREST.yml) for your OTRS version

## Workflow in OTRS
Using a Generic Agent that triggers on one event ("Send to TH" checkbox), launch a python script that push OTRS info into a TH Case and store the CaseID into OTRS

## Prerequiste for TH
* install thehive4py
* ?

## workflow in TH
using webhook? is it possible to connect directly to OTRS REST API? some documentation to be done here.

