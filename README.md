# OTRS-TH
Work in Progress

The objective of this project is to build a connector between OTRS and Thehive_projet

## OTRS to TheHive
From [OTRS](https://www.otrs.com), to create cases into [TH](https://thehive-project.org/) passing some data such as
* list of tasks
* observables
* attachments
As a result the CaseID is stored into a dynamic field in OTRS.

## TheHive to OTRS
From TH, to be able to update an OTRS ticket (metadata, add article, list of observable, attachments).

# Technical aspects
Given that both products have a Python interface, develop the connector using this language.
## Prerequisite on OTRS
* install the [RESTful Generic interface in webservices ](https://gitlab.com/rhab/PyOTRS/blob/master/webservices_templates/GenericTicketConnectorREST.yml)
* install [PyOTRS](https://pypi.python.org/pypi/PyOTRS)

## Workflow in OTRS
Using a Generic Agent that triggers on one event ("Send to TH" checkbox), launch a python script that push OTRS info into a TH Case and store the CaseID into OTRS

## Prerequiste for TH
* install thehive4py
* ?

## workflow in TH
using webhook? is it possible to connect directly to OTRS REST API? some documentation to be done here.

