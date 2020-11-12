from ruxit.api.base_plugin import BasePlugin
from ruxit.api.snapshot import pgi_name, parse_port_bindings
from ruxit.api.data import PluginProperty, MEAttribute
from ruxit.api.selectors import *
from  datetime import datetime, timezone, timedelta
import logging
import threading
import time
import idna
import ssl
import socket 
import asn1crypto
import asn1crypto.x509
import re
import pytz

class SSLCheckResult:
    def __init__(self, sni, certificate):
        self.sni = sni
        self.certificate = certificate
        self.discoverEvent = time.time()      

# Check thread
class SSLPortChecker(threading.Thread):
    def __init__(self, binding, plugin):
        threading.Thread.__init__(self)
        self.binding = binding
        self.plugin = plugin

    def run(self):
        certs = []
        self.plugin.logger.debug("SSLCheck - SSLPortCheckerThread - checking {b}".format(b=self.binding))
        try:
            connection = ssl.create_connection(self.binding)
            connection.settimeout(3)
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sock = context.wrap_socket(connection)
            remote_cert=asn1crypto.x509.Certificate.load(sock.getpeercert(True))        
            certs.append(SSLCheckResult(sni="", certificate=remote_cert['tbs_certificate']))
            serial=remote_cert['tbs_certificate']['serial_number'].native
            # try additional SNI
            for sni in self.plugin.additional_sni:
                self.plugin.logger.debug("SSLCheck - SSLPortCheckerThread - checking {b} SNI {s}".format(b=self.binding, s=sni))
                connection = ssl.create_connection(self.binding)
                connection.settimeout(3)
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sock = context.wrap_socket(connection, server_hostname=sni)
                remote_cert = asn1crypto.x509.Certificate.load(sock.getpeercert(True))
                # Only add certificate if differs from main certificate
                if (remote_cert['tbs_certificate']['serial_number'].native!=serial):
                    certs.append(SSLCheckResult(sni=sni, certificate=remote_cert['tbs_certificate']))        
        except:
            self.plugin.logger.debug("SSLCheck - SSLPortCheckerThread - checking {b} - error/timed out".format(b=self.binding))            
        self.plugin.logger.debug("SSLCheck - SSLPortCheckerThread - finished checking {b}".format(b=self.binding))            
        self.plugin.sslinfo[self.binding] = certs

# Main Plugin Class
class SSLCertCheck_Plugin(BasePlugin):
    checkBindings=[]
    sslinfo={}
    lastCheck=0

    firstRun = True

    LOCAL_TIMEZONE = datetime.now(timezone.utc).astimezone().tzinfo

    # Parse range string
    def parseRanges(self, rangeString: str):
        ranges = []
        for range in rangeString.split(";"):
            range_re = re.search("(\d+)\s*-\s*(\d+)", range)
            if (range_re):
                ranges.append([ int(range_re.group(1)), int(range_re.group(2))])
            else: 
                range_re = re.search("(\d+)", range)
                if (range_re):
                    ranges.append([ int(range_re.group(1)), int(range_re.group(1))])
        return ranges

    def portInCheckRanges(self, port: int):
        isInRange = False
        for in_range in self.inclusivePortRange:
            if (in_range[0] <= port <= in_range[1]):
                isInRange = True
        for in_range in self.exclusivePortRange:
            if (in_range[0] <= port <= in_range[1]):
                isInRange = False
        return isInRange

    # Discovers TCP listen ports to check
    def discoverPorts(self):
        discoveredBindings=[]
        # Iteration across all procss groups
        pgi_list = self.find_all_process_groups(  lambda entry: entry.group_name.startswith("") )            
        for pgi in pgi_list:
            pgi_id = pgi.group_instance_id
            # Iteration across all processes in the process group
            for proc in pgi.processes:        
                port_bindings = parse_port_bindings(pgi)
                # Check all bindings
                for binding in port_bindings:
                    if (self.portInCheckRanges(binding[1])):
                        # Skipping OneAgent ports itself for sanity
                        if (pgi.group_name!="OneAgent system monitoring"):
                            self.logger.debug("SSLCheck - Port binding {binding} for process group {pg}".format(binding=binding, pg=pgi.group_name))
                            discoveredBindings.append(binding)
        if (set(self.checkBindings) != set(discoveredBindings)):
            self.logger.debug("SSLCheck - Discovered ports do not match previously discovered ports, forcing recheck")
            self.lastCheck=0
        else:
            self.logger.debug("SSLCheckDiscovered ports match previously discovered ports.")
        self.checkBindings=discoveredBindings        

    # Trigger check threads
    def checkPorts(self):   
        self.lastCheck = time.time()    
        self.logger.info("SSLCheck - starting check for ports")
        for b in self.checkBindings:
            t = SSLPortChecker(b,self)
            t.start()

    def dtEventCertProperties(self, certificate:asn1crypto.x509.TbsCertificate, hostPort:str=None):
        properties={}
        for cert_prop in ["Subject","Issuer", "Validity"]:
            for k,v in certificate[cert_prop.lower()].native.items():
                if isinstance(v, datetime):
                    properties["{prop} {attr}".format(prop=cert_prop, attr=k)]=v.astimezone(self.LOCAL_TIMEZONE).isoformat()
                else:
                    properties["{prop} {attr}".format(prop=cert_prop, attr=k)]=v
        if hostPort:
            properties["Certificate found at"]=hostPort
        return properties

    def initialize(self, **kwargs):        
        self.logger.debug("SSLCheck - Initializing")
        self.inclusivePortRange=self.parseRanges(self.config["ports_include"])
        self.exclusivePortRange=self.parseRanges(self.config["ports_exclude"])
        if self.config["additional_sni"]:
            self.additional_sni = re.split('[ ;,]+',self.config["additional_sni"])
        else: 
            self.additional_sni = []
        self.discoverPorts()
        self.checkPorts()        

    def query(self, **kwargs):
        # Initializes DEBUG logging in first run or when debug setting is true
        if self.config['debug'] or self.firstRun:
            self.logger.setLevel(logging.DEBUG)
            self.firstRun = False
        else:
            self.logger.info("Setting log level to WARNING (Debug is %s)", self.config['debug'])
            self.logger.setLevel(logging.WARNING)

        self.logger.debug("SSLCheck - time {t} lastcheck {l}".format(t=time.time(), l=self.lastCheck))
        self.discoverPorts()
        if (time.time() > (self.lastCheck + self.config["check_interval"]*3600) ):
            self.logger.debug("SSLCheck - check interval due")
            self.checkPorts()

        # publish results
        certcount = 0
        for binding in self.sslinfo:
            for check_result in self.sslinfo[binding]:
                cert = check_result.certificate
                entity=ListenPortSelector(port_number=binding[1])
                host = binding[0]
                port = binding[1]
                sni = sni=check_result.sni
                if (sni==""):
                    hps="{h}:{p}".format(h=host, p=port)
                else:
                    hps="{h}:{p}/{sni}".format(h=host, p=port, sni=sni)
                self.logger.info("SSLCheck result {hps} subject CN {sub} notvalidbefore {nvb} novalidafter {nva}".format(hps=hps,
                    sub=cert['subject'].native['common_name'],
                    nvb=cert['validity']['not_before'].native,
                    nva=cert['validity']['not_after'].native))
                certcount=certcount+1                
                
                if (check_result.discoverEvent > self.lastCheck):
                    check_result.discoverEvent = 0
                    self.results_builder.report_custom_info_event(
                        description="Certificate with CN:{sub} published on {hps} discovered".format(sub=cert['subject'].native['common_name'], hps=hps), 
                        title="Certificate discovered", 
                        entity_selector=entity,
                        properties=self.dtEventCertProperties(cert, hps))
                if (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_error'])):
                    # sending error event
                    self.results_builder.report_error_event(
                        description="Certificate expiring in less than {expiring} days".format(expiring=self.config['days_event_info']), 
                        title="Certificate due to expire", 
                        entity_selector=entity,
                        properties=self.dtEventCertProperties(cert, hps))
                elif (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_info'])):
                    # sending info event
                    self.results_builder.report_custom_info_event(
                        description="Certificate expiring in less than {expiring} days".format(expiring=self.config['days_event_info']), 
                        title="Certificate expiration warning", 
                        entity_selector=entity,
                        properties=self.dtEventCertProperties(cert, hps))

                if (self.config["publish_metadata"]==True):
                    # Send certificate metadata to process 
                    self.logger.info("SSLCheck metadata sent for {hps} on subject CN {sub}".format(hps=hps,
                        sub=cert['subject'].native['common_name']))
                    self.results_builder.add_property(PluginProperty(me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                                                                     entity_selector=entity,
                                                                     key="Certificate [{hps}, {cn}]".format(
                                                                         hps=hps, cn=cert["subject"].native["common_name"]),
                                                                     value="Valid from:{nvb} to {nva} issued by {issuer}".format(
                                                                         nvb=cert['validity']['not_before'].native.isoformat(
                                                                         ),
                                                                         nva=cert['validity']['not_after'].native.isoformat(
                                                                         ),
                                                                         issuer=cert["issuer"].native["common_name"])))