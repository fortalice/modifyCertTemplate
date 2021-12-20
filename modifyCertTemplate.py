#!/usr/bin/env python3

from impacket.krb5.kerberosv5 import KerberosError
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.examples.utils import parse_credentials
from impacket.examples import logger
from impacket.ldap import ldap, ldaptypes
from binascii import unhexlify
from src.models import *
from src.constants import *
from src.crtd import *
import argparse
import logging
import sys
import ldap3
import ssl
import os


def get_dn(template, domain):
    components = domain.split('.')
    base = ''
    for comp in components:
        base += f',DC={comp}'
    
    return f'CN={template},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration{base}', base[1:]


def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()



def init_ldap_connection(target, tls_version, options, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if options.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, options.aesKey, kdcHost=options.dc_ip)
    elif options.hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(options, domain, username, password, lmhash, nthash):
    if options.k:
        target = get_machine_name(options, domain)
    else:
        if options.dc_ip is not None:
            target = options.dc_ip
        else:
            target = domain

    if options.ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, options, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, options, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, options, domain, username, password, lmhash, nthash)


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logging.debug('Domain retrieved from CCache: %s' % domain)

            logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


class CertificateModifier():
    def __init__(self, ldap_server, ldap_session, cert_dn, search_base, target_property=None, new_value=None, add_value=None, raw=False):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.cert_dn = cert_dn
        self.search_base = search_base
        self.target_property = target_property
        self.new_value = new_value
        self.add_value = add_value
        self.cached_sids = {}
        self.domain_sids = {}
        self.raw = raw
        # properties that will need new values to be formatted as a list as opposed to a single value
        self.list_properties = ['mspki-certificate-application-policy', 'pkiextendedkeyusage', 'mspki-certificate-application-policy']


    def query_cert(self, acl=False):
        filter = '(objectClass=*)'
        logging.debug('Performing LDAP query...')
        logging.debug(f'"{self.cert_dn}" "{filter}"')

        if acl:
            # if SD control is unspecified, a non-admin user will be unable to query nTSecurityDescriptor
            # https://stackoverflow.com/questions/40771503/selecting-the-ad-ntsecuritydescriptor-attribute-as-a-non-admin
            controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
            self.ldap_session.search(self.cert_dn, filter, attributes=['nTSecurityDescriptor'], controls=controls)
        else:
            self.ldap_session.search(self.cert_dn, filter, attributes='*')

        if len(self.ldap_session.entries) > 0:
            logging.info(f'Object found')
        else:
            logging.warning('Object not found')
            sys.exit(1)

    
    def query_property(self):
        self.query_cert()
        try:
            current_value = self.ldap_session.entries[0][self.target_property]
            logging.info(f'Current {self.target_property} value: {current_value}')
            if self.new_value is not None:
                self.modify_template()
        except ldap3.core.exceptions.LDAPKeyError: 
            logging.critical(f'Could not find proptery \'{self.target_property}\' on the object')


    def modify_template(self):
        if self.target_property.lower() in self.list_properties:
            new_value = {self.target_property: [ldap3.MODIFY_REPLACE, [i.strip() for i in self.new_value.replace("'","").split(',')]]}
        else:
            new_value = {self.target_property: [ldap3.MODIFY_REPLACE, [self.new_value]]}

        self.perform_ldap_modify(new_value)
        
    
    def add_to_attribute(self):
        # currently implemented for the add feature
        supported_attributes = [
            "msPKI-Certificate-Name-Flag", 
            "msPKI-Enrollment-Flag", 
            "pKIExtendedKeyUsage", 
            "msPKI-Certificate-Application-Policy"
        ]

        # sorry not implemented :(
        if self.target_property.upper() not in [x.upper() for x in supported_attributes]:
            logging.critical(f'The add feature has not been implemented for {self.target_property}. Please use -value and -property for modification.')
            logging.critical('Add feature is supported for:')
            for attr in supported_attributes:
                print(f'\t{attr}')
            print()
            sys.exit(0)


        upper_attr = self.add_value.upper()
        value_dict = ''
        value = ''

        # check to see if in name flags
        if self.target_property.upper() == "msPKI-Certificate-Name-Flag".upper():
            value_dict = MS_PKI_CERTIFICATE_NAME_FLAGS
            for x in MS_PKI_CERTIFICATE_NAME_FLAGS:
                if MS_PKI_CERTIFICATE_NAME_FLAGS[x].upper() == upper_attr:
                    value = x

        # check to see if in enrollment flags
        if self.target_property.upper() == "msPKI-Enrollment-Flag".upper():
            value_dict = MS_PKI_ENROLLMENT_FLAGS
            for x in MS_PKI_ENROLLMENT_FLAGS:
                if MS_PKI_ENROLLMENT_FLAGS[x].upper() == upper_attr:
                    value = x

        # check to see if in EKUs
        if self.target_property.upper() in ["pKIExtendedKeyUsage".upper(), "msPKI-Certificate-Application-Policy".upper()]:
            value_dict = OID_TO_STR_MAP
            for x in OID_TO_STR_MAP:
                if OID_TO_STR_MAP[x].upper() == upper_attr:
                    value = x

        # does not exist or not currently implemented
        if value == '':
            logging.critical(f'{self.add_value} not found as a valid value for {self.target_property}')
            logging.critical(f'Vaild values for {self.target_property} are:')
            for flag in value_dict:
                print(f'\t{value_dict[flag]}')
            print()
            sys.exit(0)
        
        # query the cert and get the current value, so we can add to the existing value(s)
        self.query_cert()
        try:
            current_value = self.ldap_session.entries[0][self.target_property]
            logging.info(f'Current {self.target_property} value: {current_value}')
        except ldap3.core.exceptions.LDAPKeyError: 
            logging.critical(f'Could not find proptery \'{self.target_property}\' on the object')
            sys.exit(1)

        current_value = list(current_value)

        # we need to submit a list of values
        if self.target_property.lower() in self.list_properties:
                        
            if value in current_value:
                logging.critical(f'{self.add_value} already in {self.target_property}')
                sys.exit(1)

            current_value.append(value)
            # current value is already formatted as a list
            new_value = {self.target_property: [ldap3.MODIFY_REPLACE, current_value]}
        
        # submitting a value from a bitwise or
        else: 
            new_value = {self.target_property: [ldap3.MODIFY_REPLACE, [int(current_value[0]) | int(value)]]}
        
        self.perform_ldap_modify(new_value)


    def perform_ldap_modify(self, new_value):
        self.ldap_session.modify(self.cert_dn, new_value)

        if self.ldap_session.result['result'] == 0:
            logging.info(f'Updated {self.target_property} attribute successfully')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s' % self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s' % self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s' % self.ldap_session.result['message'])


    def print_current_template(self):
        self.query_cert()
        logging.info('Certificate template:')
        if self.raw:
            print()
            print(self.ldap_session.entries[0])
        else:
            template = Template(self.ldap_session.entries[0])
            template.print_template()


    def get_acl(self):
        self.query_cert(acl=True)
        descriptor_data = self.ldap_session.entries[0]['nTSecurityDescriptor'].raw_values[0]
        descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(descriptor_data)
        logging.info('Printing Object ACL')
        for ace in descriptor['Dacl'].aces:
            new_ace = ACE(ace, self)
            new_ace.print_ace()
        print()


    def resolve_sid(self, sid):
        if type(sid) is not str:
            sid = sid.formatCanonical()

        try:
            name = KNOWN_SIDS[sid]
            return f'NT AUTHORITY\\{name}'
        except KeyError:
            pass

        try:
            return self.cached_sids[sid]
        except KeyError:
            pass
        
        domain_sid = "-".join(sid.split("-")[:-1])
        domain = self.get_domain_from_sid(domain_sid)

        self.ldap_session.search(self.search_base, '(objectsid=' + sid + ')', attributes=['objectsid', 'samaccountname'])
        if len(self.ldap_session.entries) > 0:
            name = self.ldap_session.entries[0]["sAMAccountName"]
            self.cached_sids[sid] = f'{domain}\\{name}'
            return f'{domain}\\{name}'

        raise KeyError

    def get_domain_from_sid(self, sid):
        try:
            return self.domain_sids[sid]
        except KeyError:
            pass
        
        self.ldap_session.search(self.search_base, search_filter=f'(objectsid={sid})', attributes=['name'])
        name = self.ldap_session.entries[0]['name']
        self.domain_sids[sid] = name
        return name
    

def main():
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "Modify the attributes of an Active Directory certificate template")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]')
    parser.add_argument('-template', action='store', metavar='template name', help='Name of the target certificate template')
    parser.add_argument('-property', action='store', metavar='property name', help='Name of the target template property')
    parser.add_argument('-value', action='store', metavar='new value', help='Value to set the specified template property to')
    parser.add_argument('-get-acl', action='store_true', help='Print the certificate\'s ACEs')
    parser.add_argument('-dn', action='store', metavar='distinguished name', help='Explicitly set the distinguished name of the certificate template')
    parser.add_argument('-raw', action='store_true', help='Output the raw certificate template attributes')
    parser.add_argument('-add', action='store', metavar='flag name', help='Add a flag to an attribute, maintaining the existing flags')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-ldaps', action="store_true", help='Use LDAPS instead of LDAP')
    
    options = parser.parse_args()
    domain, username, password = parse_credentials(options.target)
    
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if not options.dn and not options.template:
        logging.critical('-template or -dn must be specified')
        sys.exit(1)

    if options.value and not options.property:
        logging.critical('Value requires Property to be specified!')
        sys.exit(1)

    if options.add and not options.property:
        logging.critical('Add requires Property to be specified!')
        sys.exit(1)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass('Password:')
    
    lm_hash = ""
    nt_hash = ""
    if options.hashes is not None:
        if ":" in options.hashes:
            lm_hash = options.hashes.split(":")[0]
            nt_hash = options.hashes.split(":")[1]
        else:
            nt_hash = options.hashes

    cert_dn, search_base = get_dn(options.template, domain)
    if options.dn:
        cert_dn = options.dn
    
    ldap_server = ''
    ldap_session = ''
    certModifier = ''
    try:
        ldap_server, ldap_session = init_ldap_session(options=options, domain=domain, username=username,
                                                    password=password, lmhash=lm_hash, nthash=nt_hash)
        certModifier = CertificateModifier(ldap_server, ldap_session, cert_dn, search_base, options.property, options.value, options.add, options.raw)
        logging.debug('LDAP bind successful')
    except ldap3.core.exceptions.LDAPBindError:
        logging.critical('LDAP bind error: invalid credentials')
        exit()
    
    if options.get_acl:
        certModifier.get_acl()
    elif options.add:
        certModifier.add_to_attribute()
    elif options.property:
        certModifier.query_property()
    else:
        certModifier.print_current_template()
    
    ldap_session.unbind()


if __name__ == '__main__':
    main()

