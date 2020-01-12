from ruxit.api.base_plugin import BasePlugin
from ruxit.api.snapshot import pgi_name, parse_port_bindings
from ruxit.api.data import PluginProperty, MEAttribute
from ruxit.api.selectors import *
from  datetime import datetime, timezone, timedelta
import threading
import time
import idna
import ssl
import socket 
import asn1crypto
import asn1crypto.x509
import re
 
class SSLCheckResult:
    def __init__(self, sni, certificate):
        self.sni = sni
        self.certificate = certificate        

# Check thread
class SSLPortChecker(threading.Thread):
    def __init__(self, binding, plugin):
        threading.Thread.__init__(self)
        self.binding = binding
        self.plugin = plugin

    def run(self):
        certs = []
        self.plugin.logger.info("SSLCheck - SSLPortCheckerThread - checking {b}".format(b=self.binding))
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
                self.plugin.logger.info("SSLCheck - SSLPortCheckerThread - checking {b} SNI {s}".format(b=self.binding, s=sni))
                connection = ssl.create_connection(self.binding)
                connection.settimeout(3)
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sock = context.wrap_socket(connection, server_hostname=sni)
                remote_cert = asn1crypto.x509.Certificate.load(sock.getpeercert(True))
                # Only add certificate if differs from main certificate
                if (remote_cert['tbs_certificate']['serial_number'].native!=serial):
                    certs.append(SSLCheckResult(sni=sni, certificate=remote_cert['tbs_certificate']))        
        except:
            self.plugin.logger.info("SSLCheck - SSLPortCheckerThread - checking {b} - error/timed out".format(b=self.binding))            
        self.plugin.logger.info("SSLCheck - SSLPortCheckerThread - finished checking {b}".format(b=self.binding))            
        self.plugin.sslinfo[self.binding] = certs

# Main Plugin Class
class SSLCertCheck_Plugin(BasePlugin):
    checkBindings=[]
    sslinfo={}
    lastCheck=0

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
                            self.logger.info("Port binding {binding} for process group {pg}".format(binding=binding, pg=pgi.group_name))
                            discoveredBindings.append(binding)
        self.checkBindings=discoveredBindings        

    # Trigger check threads
    def checkPorts(self):   
        self.lastCheck = time.time()    
        self.logger.info("SSLCheck - starting check for ports")
        for b in self.checkBindings:
        #    self.checkPort(b)
            t = SSLPortChecker(b,self)
            t.start()

    def initialize(self, **kwargs):
        self.logger.info("SSLCheck - Initializing")
        self.inclusivePortRange=self.parseRanges(self.config["ports_include"])
        self.exclusivePortRange=self.parseRanges(self.config["ports_exclude"])
        if self.config["additional_sni"]:
            self.additional_sni = re.split('[ ;,]+',self.config["additional_sni"])
        else: 
            self.additional_sni = []
        self.discoverPorts()
        self.checkPorts()        

    def query(self, **kwargs):
        self.logger.info("SSLCheck - time {t} lastcheck {l}".format(t=time.time(), l=self.lastCheck))
        if (time.time() > (self.lastCheck + self.config["check_interval"]*3600) ):
            self.logger.info("SSLCheck - check interval due")
            self.discoverPorts()
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
                
                if (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_info'])):
                    # sending info event
                    self.results_builder.report_error_event(
                        description="Certificate for CN:{sub} published on {hps} is expiring at {nva}".format(sub=cert['subject'].native['common_name'], hps=hps, nva=cert['validity']['not_after'].native), 
                        title="Certificate due to expire", 
                        entity_selector=entity)
                if (cert['validity']['not_after'].native < datetime.now(timezone.utc) + timedelta(days=self.config['days_event_error'])):
                    # sending error event
                    self.results_builder.report_error_event(
                        description="Certificate for CN:{sub} published on {hps} is expiring at {nva}".format(sub=cert['subject'].native['common_name'], hps=hps, nva=cert['validity']['not_after'].native), 
                        title="Certificate due to expire", 
                        entity_selector=entity)
            
                if (self.config["publish_metadata"]==True):
                    # Send certificate metadata to process 
                    self.logger.info("SSLCheck metadata sent for {hps} on subject CN {sub}".format(hps=hps,
                        sub=cert['subject'].native['common_name']))
                    self.results_builder.add_property(PluginProperty(key="Certificate [{hps}] Subject".format(hps=hps), 
                        value=cert["subject"].native["common_name"], 
                        me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                        entity_selector=entity))
                    self.results_builder.add_property(PluginProperty(key="Certificate [{hps}] Issuer".format(hps=hps), 
                        value=cert["issuer"].native["common_name"], 
                        me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                        entity_selector=entity))
                    self.results_builder.add_property(PluginProperty(key="Certificate [{hps}] Valid from".format(hps=hps), 
                        value=cert['validity']['not_before'].native.isoformat(), 
                        me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                        entity_selector=entity))
                    self.results_builder.add_property(PluginProperty(key="Certificate [{hps}] Valid until".format(hps=hps), 
                        value=cert['validity']['not_after'].native.isoformat(), 
                        me_attribute=MEAttribute.CUSTOM_PG_METADATA,
                        entity_selector=entity))