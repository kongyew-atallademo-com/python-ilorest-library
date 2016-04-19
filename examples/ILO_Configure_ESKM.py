# Copyright 2016 Hewlett Packard Enterprise Development, LP.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""

Provides examples of using the HP RESTful API on iLO for common Key Management use cases.
This is for tutorial/example purposes only.

---------------------------------------------------------------------------------------------------------------------
IMPORTANT!!!
---------------------------------------------------------------------------------------------------------------------
When developing a client for the HP RESTful API, be sure to not code based upon assumptions that are not guaranteed.
Search for, and note any 'NOTE' comments in this code to read about ways to avoid incorrect assumptions.

The reason avoiding these assumptions is so important is that implementations may vary across systems and firmware
versions, and we want your code to work consistently.

---------------------------------------------------------------------------------------------------------------------
STARTING ASSUMPTIONS
---------------------------------------------------------------------------------------------------------------------

On URIs:

The HP RESTful API is a "hypermedia API" by design.  This is to avoid building in restrictive assumptions to the
data model that will make it difficult to adapt to future hardware implementations.  A hypermedia API avoids these
assumptions by making the data model discoverable via links between resources.

A URI should be treated by the client as opaque, and thus should not be attempted to be understood or deconstructed
by the client.  Only specific top level URIs (any URI in this sample code) may be assumed, and even these may be
absent based upon the implementation (e.g. there might be no /rest/v1/Systems collection on something that doesn't
have compute nodes.)

The other URIs must be discovered dynamically by following href links.  This is because the API will eventually be
implemented on a system that breaks any existing data model "shape" assumptions we may make now.  In particular,
clients should not make assumptions about the URIs for the resource members of a collection.  For instance, the URI of
a collection member will NOT always be /rest/v1/.../collection/1, or 2.  On Moonshot a System collection member might be
/rest/v1/Systems/C1N1.

This sounds very complicated, but in reality (as these examples demonstrate), if you are looking for specific items,
the traversal logic isn't too complicated.

On Resource Model Traversal:

Although the resources in the data model are linked together, because of cross link references between resources,
a client may not assume the resource model is a tree.  It is a graph instead, so any crawl of the data model should
keep track of visited resources to avoid an infinite traversal loop.

A reference to another resource is any property called "href" no matter where it occurs in a resource.

An external reference to a resource outside the data model is referred to by a property called "extref".  Any
resource referred to by extref should not be assumed to follow the conventions of the API.

On Resource Versions:

Each resource has a "Type" property with a value of the format Tyepname.x.y.z where
* x = major version - incrementing this is a breaking change to the schema
* y = minor version - incrementing this is a non-breaking additive change to the schema
* z = errata - non-breaking change

Because all resources are versioned and schema also have a version, it is possible to design rules for "nearest"
match (e.g. if you are interacting with multiple services using a common batch of schema files).  The mechanism
is not prescribed, but a client should be prepared to encounter both older and newer versions of resource types.

On HTTP POST to create:

WHen POSTing to create a resource (e.g. create an account or session) the guarantee is that a successful response
includes a "Location" HTTP header indicating the resource URI of the newly created resource.  The POST may also
include a representation of the newly created object in a JSON response body but may not.  Do not assume the response
body, but test it.  It may also be an ExtendedError object.

HTTP REDIRECT:

All clients must correctly handle HTTP redirect.  We (or Redfish) may eventually need to use redirection as a way
to alias portions of the data model.

FUTURE:  Asynchronous tasks

In the future some operations may start asynchonous tasks.  In this case, the client should recognized and handle
HTTP 202 if needed and the 'Location' header will point to a resource with task information and status.

JSON-SCHEMA:

The json-schema available at /rest/v1/Schemas governs the content of the resources, but keep in mind:
* not every property in the schema is implemented in every implementation.
* some properties are schemed to allow both null and anotehr type like string or integer.

Robust client code should check both the existence and type of interesting properties and fail gracefully if
expectations are not met.

GENERAL ADVICE:

Clients should always be prepared for:
* unimplemented properties (e.g. a property doesn't apply in a particular case)
* null values in some cases if the value of a property is not currently known due to system conditions
* HTTP status codes other than 200 OK.  Can your code handle an HTTP 500 Internal Server Error with no other info?
* URIs are case insensitive
* HTTP header names are case insensitive
* JSON Properties and Enum values are case sensitive
* A client should be tolerant of any set of HTTP headers the service returns

"""

import sys
import json
import logging
import urlparse
import jsonpatch

from ilorest import AuthMethod, ilorest_logger, rest_client

# Config logger used by HPE Restful library
LOGGERFILE = "ILO_Configure_ESKM.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGGER = ilorest_logger(LOGGERFILE, LOGGERFORMAT, logging.INFO)
LOGGER.info("HPE Restful API examples to configure ESKM")


def ex1_get_resource_directory(restobj):
    # sys.stdout.write("\nEXAMPLE 1: Find and store the resource directory " + "\n")
    response = restobj.rest_get("/rest/v1/resourcedirectory")
    resources = {}

    if response.status == 200:
        sys.stdout.write("\tFound resource directory at /rest/v1/resource" \
                         "directory" + "\n")
        resources["resources"] = response.dict["Instances"]
        return resources
    else:
        sys.stderr.write("\tResource directory missing at /rest/v1/resource" \
                         "directory" + "\n")


def ex2_get_base_registry(restobj):
    # sys.stdout.write("\nEXAMPLE 2: Find and return registry " + "\n")
    response = restobj.rest_get("/rest/v1/Registries")
    messages = {}

    for entry in response.dict["Items"]:
        if entry["Id"] not in ["Base", "iLO"]:
            continue

        for location in entry["Location"]:
            reg_resp = restobj.rest_get(location["Uri"]["extref"])

            if reg_resp.status == 200:
                sys.stdout.write("\tFound " + entry["Id"] + " at " + \
                                 location["Uri"]["extref"] + "\n")
                messages[entry["Id"]] = reg_resp.dict["Messages"]
            else:
                sys.stdout.write("\t" + entry["Id"] + " not found at " \
                                 + location["Uri"]["extref"] + "\n")

    return messages


def set_ESKM_PrimaryKeyServer(restobj, PrimaryKeyServerAddress, PrimaryKeyServerPort):
    sys.stdout.write("\nset_ESKM_PrimaryKeyServer\n")
    instances = restobj.search_for_type("ESKM.")

    for instance in instances:
        body = dict()

        body["PrimaryKeyServerAddress"] = PrimaryKeyServerAddress
        body["PrimaryKeyServerPort"] = int(PrimaryKeyServerPort)

        response = restobj.rest_patch(instance["href"], body)
        restobj.error_handler(response)


def set_ESKM_username_password(restobj, username, password, accountgroup):
    sys.stdout.write("\nSet ESKM username, password\n")
    instances = restobj.search_for_type("ESKM.")

    for instance in instances:
        body = dict()

        body["KeyManagerConfig"] = dict()
        body["KeyManagerConfig"]["LoginName"] = username
        body["KeyManagerConfig"]["Password"] = password
        body["KeyManagerConfig"]["AccountGroup"] = accountgroup
        body["KeyManagerConfig"]["ESKMLocalCACertificateName"] = ""

        response = restobj.rest_patch(instance["href"], body)
        restobj.error_handler(response)


def test_ESKM_connection(restobj):
    sys.stdout.write("\nTest ESKM connection\n")
    instances = restobj.search_for_type("ESKM.")

    for instance in instances:
        body = dict()
        body["Action"] = "TestESKMConnections"

        response = restobj.rest_post(instance["href"], body)
        restobj.error_handler(response)

        #  sys.stdout.write("\tResponse:" +         ": " +str(response) + "\n")


def reset_ESKM_eventlog(restobj):
    sys.stdout.write("\nReset ESKM event logs\n")
    instances = restobj.search_for_type("ESKM.")

    for instance in instances:
        body = dict()
        body["Action"] = "ClearESKMLog"

        response = restobj.rest_post(instance["href"], body)
        restobj.error_handler(response)


def dump_eskm_event_log(restobj):
    sys.stdout.write("\nDump ESKM Event Log\n")
    instances = restobj.search_for_type("SecurityService.")

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])
        response = restobj.rest_get(tmp.dict["links"]["ESKM"]["href"])

        for entry in tmp.dict["ESKMEvents"]:
            response = restobj.rest_get(entry["href"])

            for log_entry in response.dict["Items"]:
                sys.stdout.write(log_entry["Event"] + "\n")


def read_IP_file(filename):
    import re  # for regular expressions - to match ip's
    import sys  # for parsing command line opts

    # I need to probably make this more pythonic but am working on that...
    # if file is specified on command line, parse, else ask for file
    if filename:
        print "File: %s" % (filename)
        logfile = filename
    else:
        logfile = raw_input("Please enter a file to parse, e.g /var/log/secure: ")

    try:
        # open the file
        file = open(logfile, "r")
        # create an empty list
        ips = []
        # read through the file
        for text in file.readlines():
            # strip off the \n
            text = text.rstrip()
            # this is probably not the best way, but it works for now
            regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$', text)
            # if the regex is not empty and is not already in ips list append
            if regex is not None and regex not in ips:
                ips.append(regex)

        # loop through the list
        for ip in ips:
            # I know there is argument as to whether the string join method is pythonic
            addy = "".join(ip)
            if addy is not '':
                print "IP: %s" % (addy)
        # cleanup and close file
        file.close()
    # catch any standard error (we can add more later)
    except IOError, (errno, strerror):
        print "I/O Error(%s) : %s" % (errno, strerror)


def get_ESKM(restobj):
    sys.stdout.write("\n: Get ESKM configuration\n")
    instances = restobj.search_for_type("SecurityService.")

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])
        response = restobj.rest_get(tmp.dict["links"]["ESKM"]["href"])
        # sys.stdout.write("response\t" +         ": " +str(response) + "\n")

        sys.stdout.write("\tPrimaryKeyServerAddress:  " +
                         json.dumps(response.dict["PrimaryKeyServerAddress"]) + "\n")
        sys.stdout.write("\tPrimaryKeyServerPort:  " +
                         json.dumps(response.dict["PrimaryKeyServerPort"]) + "\n")
        sys.stdout.write("\tSecondaryKeyServerAddress:  " +
                         json.dumps(response.dict["SecondaryKeyServerAddress"]) + "\n")
        sys.stdout.write("\tSecondaryKeyServerPort:  " +
                         json.dumps(response.dict["SecondaryKeyServerPort"]) + "\n")
        sys.stdout.write("\tType:  " +
                         json.dumps(response.dict["Type"]) + "\n")
        sys.stdout.write("\tKeyServerRedundancyReq:  " +
                         json.dumps(response.dict["KeyServerRedundancyReq"]) + "\n")

        sys.stdout.write("\tAccountGroup:  " +
                         json.dumps(response.dict["KeyManagerConfig"]["AccountGroup"]) + "\n")
        sys.stdout.write("\tESKMLocalCACertificateName:  " +
                         json.dumps(response.dict["KeyManagerConfig"]["ESKMLocalCACertificateName"]) + "\n")
        sys.stdout.write("\tImportedCertificateIssuer:  " +
                         json.dumps(response.dict["KeyManagerConfig"]["ImportedCertificateIssuer"]) + "\n")

        sys.stdout.write("\tESKMEvents:  " +
                         json.dumps(response.dict["ESKMEvents"]) + "\n")

        tmp = response.dict["ESKMEvents"]
        for entry in tmp:
            sys.stdout.write("\tTimestamp : " + entry["Timestamp"] + "Event:  " +
                             json.dumps(entry["Event"]) + "\n")
            #  response = restobj.rest_get(entry["Event"])
            # import csv


def find_ilo_mac_address(restobj):
    sys.stdout.write("\nFind iLO's MAC Addresses\n")
    instances = restobj.search_for_type("Manager.")

    for instance in instances:
        tmp = restobj.rest_get(instance["href"])
        response = restobj.rest_get(tmp.dict["links"]["EthernetNICs"]["href"])

        for item in response.dict["Items"]:
            if "MacAddress" not in item:
                sys.stderr.write("\tNIC resource does not contain " \
                                 "'MacAddress' property\n")
            else:
                sys.stdout.write("\t" + item["Name"] + " = " + \
                                 item["MacAddress"] + "\t(" + \
                                 item["Status"]["State"] + ")\n")




def get_computer_details(restobj):
    sys.stdout.write("\nDump host computer details\n")
    instances = restobj.search_for_type("ComputerSystem.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])

        sys.stdout.write("\tManufacturer:  " + \
                                str(response.dict["Manufacturer"]) + "\n")
        sys.stdout.write("\tModel:  " + str(response.dict["Model"]) + "\n")
        sys.stdout.write("\tSerial Number:  " + \
                                str(response.dict["SerialNumber"]) + "\n")
        if "VirtualSerialNumber" in response.dict:
            sys.stdout.write("\tVirtual Serial Number:  " +
                   str(response.dict["VirtualSerialNumber"]) + "\n")
        else:
            sys.stderr.write("\tVirtual Serial Number information not " \
                                        "available on system resource\n")
        sys.stdout.write("\tUUID:  " + str(response.dict["UUID"]) + "\n")

        if "VirtualUUID" in response.dict["Oem"]["Hp"]:
            sys.stdout.write("\tVirtualUUID:  " + \
                     str(response.dict["Oem"]["Hp"]["VirtualUUID"]) + "\n")
        else:
            sys.stderr.write("\tVirtualUUID not available system " \
                                                            "resource\n")
        if "AssetTag" in response.dict:
            sys.stdout.write("\tAsset Tag:  " + response.dict["AssetTag"] \
                                                                    + "\n")
        else:
            sys.stderr.write("\tNo Asset Tag information on system " \
                                                            "resource\n")
        sys.stdout.write("\tBIOS Version: " + \
                 response.dict["Bios"]["Current"]["VersionString"] + "\n")

        sys.stdout.write("\tMemory:  " +
               str(response.dict["Memory"]["TotalSystemMemoryGB"]) +" GB\n")

        sys.stdout.write("\tProcessors:  " + \
                 str(response.dict["Processors"]["Count"]) + " x " + \
                 str(response.dict["Processors"]["ProcessorFamily"])+ "\n")

        if "Status" not in response.dict or "Health" not in \
                                                    response.dict["Status"]:
            sys.stdout.write("\tStatus/Health information not available in "
                                                        "system resource\n")
        else:
            sys.stdout.write("\tHealth:  " + \
                             str(response.dict["Status"]["Health"]) + "\n")

        if "HostCorrelation" in response.dict:
            if "HostFQDN" in response.dict["HostCorrelation"]:
                sys.stdout.write("\tHost FQDN:  " + \
                     response.dict["HostCorrelation"]["HostFQDN"] + "\n")

            if "HostMACAddress" in response.dict["HostCorrelation"]:
                for mac in response.dict["HostCorrelation"]["HostMACAddress"]:
                    sys.stdout.write("\tHost MAC Address:  " + str(mac) + "\n")

            if "HostName" in response.dict["HostCorrelation"]:
                sys.stdout.write("\tHost Name:  " + \
                     response.dict["HostCorrelation"]["HostName"] + "\n")

            if "IPAddress" in response.dict["HostCorrelation"]:
                for ip_address in response.dict["HostCorrelation"]\
                                                            ["IPAddress"]:
                    if ip_address:
                        sys.stdout.write("\tHost IP Address:  " + \
                                                    str(ip_address) + "\n")

        if "SmartStorage" in response.dict:
            sys.stdout.write("\tSmartStorage:  " +
                           str(response.dict["SmartStorage"]) + "\n")
        else:
            sys.stderr.write("\tSmartStorage not " \
                                                "available on system resource\n")

    sys.stdout.write("\nDump host storage details\n")
    instances = restobj.search_for_type("HpSmartStorageArrayController.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        if "AdapterType" in response.dict:
            sys.stdout.write("\tAdapterType:  " +
                           str(response.dict["AdapterType"]) + "\n")
        else:
            sys.stderr.write("\tAdapterType is not " \
                                                "available on HpSmartStorageArrayController resource\n")


        if "BackupPowerSourceStatus" in response.dict:
            sys.stdout.write("\tBackupPowerSourceStatus:  " +
                           str(response.dict["BackupPowerSourceStatus"]) + "\n")
        else:
            sys.stderr.write("\tBackupPowerSourceStatus is not " \
                                                "available on HpSmartStorageArrayController resource\n")

        if "BootVolumePrimary" in response.dict:
            sys.stdout.write("\tBootVolumePrimary:  " +
                           str(response.dict["BootVolumePrimary"]) + "\n")
        else:
            sys.stderr.write("\tBootVolumePrimary not " \
                                                "available on HpSmartStorageArrayController resource\n")


        if "EncryptionBootPasswordSet" in response.dict:
            sys.stdout.write("\tEncryptionBootPasswordSet:  " +
                           str(response.dict["EncryptionBootPasswordSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionBootPasswordSet is not " \
                                                "available on HpSmartStorageArrayController resource\n")

        if "EncryptionCryptoOfficerPasswordSet" in response.dict:
            sys.stdout.write("\tEncryptionCryptoOfficerPasswordSet:  " +
                           str(response.dict["EncryptionCryptoOfficerPasswordSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionCryptoOfficerPasswordSet is not " \
                                           "available on HpSmartStorageArrayController resource\n")
        if "EncryptionLocalKeyCacheEnabled" in response.dict:
            sys.stdout.write("\tEncryptionLocalKeyCacheEnabled:  " +
                           str(response.dict["EncryptionLocalKeyCacheEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionLocalKeyCacheEnabled is not " \
                                           "available on HpSmartStorageArrayController resource\n")

        if "EncryptionMixedVolumesEnabled" in response.dict:
            sys.stdout.write("\tEncryptionMixedVolumesEnabled:  " +
                           str(response.dict["EncryptionMixedVolumesEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionMixedVolumesEnabled is not " \
                                           "available on HpSmartStorageArrayController resource\n")


        print "\n################################################\n"



def get_EncryptionSettings(restobj):

    sys.stdout.write("\nDump EncryptionSettings\n")
    instances = restobj.search_for_type("HpSmartStorageArrayController.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])

        sys.stdout.write("\tID:  " +
                           str(response.dict["@odata.id"]) + "\n")

        if "Name" in response.dict:
            sys.stdout.write("\tName:  " +
                           str(response.dict["Name"]) + "\n")
        else:
            sys.stderr.write("\tName is not " \
                                                "available on HpSmartStorageArrayController resource\n")

        if "Model" in response.dict:
            sys.stdout.write("\tModel:  " +
                           str(response.dict["Model"]) + "\n")
        else:
            sys.stderr.write("\tModel is not " \
                                                "available on HpSmartStorageArrayController resource\n")
        if "SerialNumber" in response.dict:
            sys.stdout.write("\tSerialNumber:  " +
                           str(response.dict["SerialNumber"]) + "\n")
        else:
            sys.stderr.write("\tSerialNumber is not " \
                                                "available on HpSmartStorageArrayController resource\n")

        if "EncryptionBootPasswordSet" in response.dict:
            sys.stdout.write("\tEncryptionBootPasswordSet:  " +
                           str(response.dict["EncryptionBootPasswordSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionBootPasswordSet is not " \
                                                "available on HpSmartStorageArrayController resource\n")

        if "EncryptionCryptoOfficerPasswordSet" in response.dict:
            sys.stdout.write("\tEncryptionCryptoOfficerPasswordSet:  " +
                           str(response.dict["EncryptionCryptoOfficerPasswordSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionCryptoOfficerPasswordSet is not " \
                                           "available on HpSmartStorageArrayController resource\n")
        if "EncryptionLocalKeyCacheEnabled" in response.dict:
            sys.stdout.write("\tEncryptionLocalKeyCacheEnabled:  " +
                           str(response.dict["EncryptionLocalKeyCacheEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionLocalKeyCacheEnabled is not " \
                                           "available on HpSmartStorageArrayController resource\n")

        if "EncryptionMixedVolumesEnabled" in response.dict:
            sys.stdout.write("\tEncryptionMixedVolumesEnabled:  " +
                           str(response.dict["EncryptionMixedVolumesEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionMixedVolumesEnabled is not " \
                                           "available on HpSmartStorageArrayController resource\n")

        if "EncryptionLocalKeyCacheEnabled" in response.dict:
            sys.stdout.write("\tEncryptionLocalKeyCacheEnabled:  " +
                           str(response.dict["EncryptionLocalKeyCacheEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionLocalKeyCacheEnabled is not " \
                                           "available on HpSmartStorageArrayController resource\n")


        if "EncryptionPhysicalDriveCount" in response.dict:
            sys.stdout.write("\tEncryptionPhysicalDriveCount:  " +
                           str(response.dict["EncryptionPhysicalDriveCount"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionPhysicalDriveCount is not " \
                                           "available on HpSmartStorageArrayController resource\n")

        if "EncryptionRecoveryParamsSet" in response.dict:
            sys.stdout.write("\tEncryptionRecoveryParamsSet:  " +
                           str(response.dict["EncryptionRecoveryParamsSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionRecoveryParamsSet is not " \
                                         "available on HpSmartStorageArrayController resource\n")

        if "EncryptionStandaloneModeEnabled" in response.dict:
            sys.stdout.write("\tEncryptionStandaloneModeEnabled:  " +
                           str(response.dict["EncryptionStandaloneModeEnabled"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionStandaloneModeEnabled is not " \
                                         "available on HpSmartStorageArrayController resource\n")

        if "EncryptionUserPasswordSet" in response.dict:
            sys.stdout.write("\tEncryptionUserPasswordSet:  " +
                           str(response.dict["EncryptionUserPasswordSet"]) + "\n")
        else:
            sys.stderr.write("\tEncryptionUserPasswordSet is not " \
                                         "available on HpSmartStorageArrayController resource\n")


        print "\n################################################\n"


def get_LogicalDrives(restobj):

    sys.stdout.write("\nDump LogicalDrivese details\n")
    instances = restobj.search_for_type("HpSmartStorageArrayController.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        if "ArrayControllers" in response.dict:
            sys.stdout.write("\tArrayControllers:  " +
                           str(response.dict["ArrayControllers"]) + "\n")
        else:
            sys.stderr.write("\tArrayControllers is not " \
                                                "available on HpSmartStorageArrayController resource\n")


        print "\n################################################\n"


def get_license_key(restobj):
    sys.stdout.write("\nGet iLO License Key\n")
    instances = restobj.search_for_type("HpiLOLicense.")
    license_result = dict()
    for instance in instances:
        response = restobj.rest_get(instance["href"])
        license_result["License"] = response.dict["License"]
        if "License" in response.dict:
            sys.stdout.write("\tLicense:  " +
                           str(response.dict["License"]) + "\n")
        else:
            sys.stderr.write("\tLicense is not " \
                                           "available on HpiLOLicense resource\n")
        if "LicenseKey" in response.dict:
            sys.stdout.write("\tLicense:  " +
                           str(response.dict["LicenseKey"]) + "\n")
        else:
            sys.stderr.write("\tLicenseKey is not " \
                                           "available on HpiLOLicense resource\n")

        if "LicenseType" in response.dict:
            sys.stdout.write("\tLicense:  " +
                           str(response.dict["LicenseType"]) + "\n")
        else:
            sys.stderr.write("\tLicenseType is not " \
                                           "available on HpiLOLicense resource\n")

    return (license_result)


class RestObject(object):
    def __init__(self, host, login_account, login_password):
        self.rest_client = rest_client(base_url=host, \
                                       username=login_account, password=login_password, \
                                       default_prefix="/rest/v1")
        self.rest_client.login(auth=AuthMethod.SESSION)
        self.SYSTEMS_RESOURCES = ex1_get_resource_directory(self)
        self.MESSAGE_REGISTRIES = ex2_get_base_registry(self)

    def __del__(self):
        self.rest_client.logout()

    def search_for_type(self, type):
        instances = []

        for item in self.SYSTEMS_RESOURCES["resources"]:
            foundsettings = False

            if type.lower() in item["Type"].lower():
                for entry in self.SYSTEMS_RESOURCES["resources"]:
                    if (item["href"] + "/settings").lower() == \
                            (entry["href"]).lower():
                        foundsettings = True

                if not foundsettings:
                    instances.append(item)

        if not instances:
            sys.stderr.write("\t'%s' resource or feature is not " \
                             "supported on this system\n" % type)
        return instances

    def error_handler(self, response):
        if not self.MESSAGE_REGISTRIES:
            sys.stderr.write("ERROR: No message registries found.")

        try:
            message = json.loads(response.text)
            newmessage = message["Messages"][0]["MessageID"].split(".")
        except:
            sys.stdout.write("\tNo extended error information returned by " \
                             "iLO.\n")
            return

        for err_mesg in self.MESSAGE_REGISTRIES:
            if err_mesg != newmessage[0]:
                continue
            else:
                for err_entry in self.MESSAGE_REGISTRIES[err_mesg]:
                    if err_entry == newmessage[3]:
                        sys.stdout.write("\tiLO return code %s: %s\n" % ( \
                            message["Messages"][0]["MessageID"], \
                            self.MESSAGE_REGISTRIES[err_mesg][err_entry] \
                                ["Description"]))

    def rest_get(self, suburi):
        """REST GET"""
        return self.rest_client.get(path=suburi)

    def rest_patch(self, suburi, request_body, optionalpassword=None):
        """REST PATCH"""
        sys.stdout.write("PATCH " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.patch(path=suburi, body=request_body, \
                                          optionalpassword=optionalpassword)
        sys.stdout.write("PATCH response = " + str(response.status) + "\n")

        return response

    def rest_put(self, suburi, request_body, optionalpassword=None):
        """REST PUT"""
        sys.stdout.write("PUT " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.put(path=suburi, body=request_body, \
                                        optionalpassword=optionalpassword)
        sys.stdout.write("PUT response = " + str(response.status) + "\n")

        return response

    def rest_post(self, suburi, request_body):
        """REST POST"""
        sys.stdout.write("POST " + str(request_body) + " to " + suburi + "\n")
        response = self.rest_client.post(path=suburi, body=request_body)
        sys.stdout.write("POST response = " + str(response.status) + "\n")

        return response

    def rest_delete(self, suburi):
        """REST DELETE"""
        sys.stdout.write("DELETE " + suburi + "\n")
        response = self.rest_client.delete(path=suburi)
        sys.stdout.write("DELETE response = " + str(response.status) + "\n")

        return response


if __name__ == "__main__":
    debug = False
    import ConfigParser
    from ConfigParser import SafeConfigParser

    # Require values
    try:
        # read configuration file
        parser = SafeConfigParser()
        parser.read('ilo_config.ini')
        iLO_host =  parser.get('ilo', 'ilo_host')
        login_account =  parser.get('ilo', 'login_account')
        login_password =  parser.get('ilo', 'login_password')
        eskm_username =  parser.get('ilo', 'eskm_username')
        eskm_password =  parser.get('ilo', 'eskm_password')
        eskm_accountgroup =  parser.get('ilo', 'eskm_accountgroup')
        PrimaryKeyServerAddress =  parser.get('ilo', 'PrimaryKeyServerAddress')
        PrimaryKeyServerPort =  parser.get('ilo', 'PrimaryKeyServerPort')
        # if you want hard-coded these values,  use the following commented values
        # iLO_host = "blobstore://."
        # iLO_account = "None"
        # iLO_password = "None"

    except ConfigParser.ParsingError, err:
        print 'Could not parse:', err

    if debug:
        print " login_account: "  + login_account
        print " login_password: "  + login_password
        print " iLO_host: "  + iLO_host


    # Create a REST object
    REST_OBJ = RestObject(iLO_host, login_account, login_password)

    # # Change the user name and password, eskm account group
    set_ESKM_username_password(REST_OBJ, eskm_username, eskm_password, eskm_accountgroup)
    #
    set_ESKM_PrimaryKeyServer(REST_OBJ, PrimaryKeyServerAddress, PrimaryKeyServerPort)
    #
    # # retrieve ESKM information
    get_ESKM(REST_OBJ)
    #
    # # reset_ESKM_eventlog(REST_OBJ)
    test_ESKM_connection(REST_OBJ)
    #
    # find_ilo_mac_address(REST_OBJ)
    # get_computer_details(REST_OBJ)
    # get_LogicalDrives(REST_OBJ)
    # get_EncryptionSettings(REST_OBJ)

    get_license_key(REST_OBJ)



