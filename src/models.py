from src.crtd import *
from src.constants import *

class ACE:

    def __init__(self, ace, modifier):
        self.type_name = ace['TypeName']
        ace = ace['Ace']
        self.object_type_guid = '00000000-0000-0000-0000-000000000000'
        self.object_type_friendly = ''
        if self.type_name == 'ACCESS_ALLOWED_OBJECT_ACE':
            if ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
                object_type = ace['ObjectType']
                self.object_type_guid = self.guid_to_string(object_type)
                try:
                    self.object_type_friendly = MS_PKI_GUIDS[self.object_type_guid]
                except KeyError:
                    pass
        self.access_mask = ace['Mask']['Mask']
        self.sid = ace["Sid"].formatCanonical()
        self.identity = modifier.resolve_sid(self.sid)
        self.rights = self.resolve_flags(ace['Mask'])


    def guid_to_string(self, guid):
        # https://github.com/zer1t0/certi/blob/7415d18e537b92eba84cfde8289e8df2c3d1f8aa/certilib/main.py#L600
        return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
            guid[3], guid[2], guid[1], guid[0],
            guid[5], guid[4],
            guid[7], guid[6],
            guid[8], guid[9],
            guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
        )
    

    def resolve_flags(self, access_mask):
        rights = ''
        for flag in ACCESS_MASK_FLAGS:
            if access_mask.hasPriv(ACCESS_MASK_FLAGS[flag][1]):
                rights += ', ' + ACCESS_MASK_FLAGS[flag][0]
        
        for flag in ACCESS_ALLOWED_OBJECT_ACE_FLAGS:
            if access_mask.hasPriv(ACCESS_ALLOWED_OBJECT_ACE_FLAGS[flag][1]):
                rights += ', ' + ACCESS_ALLOWED_OBJECT_ACE_FLAGS[flag][0]
            
        return rights[2:]


    def print_ace(self):
        print()
        print(f'ActiveDirectoryRights:\t{self.rights}')
        if self.object_type_friendly != '':
            print(f'ObjectType:\t\t{self.object_type_guid} ({self.object_type_friendly})')
        else:
            print(f'ObjectType:\t\t{self.object_type_guid}')
        print(f'AccessControlType:\t{self.type_name}')
        print(f'IdentityReference:\t{self.identity}')


class Template:
    
    def __init__(self, raw_template):
        self.raw_template = raw_template
        self.name = self.raw_template['cn']
        self.ra_signiture = self.raw_template['msPKI-RA-Signature']
        self.schema_version = self.raw_template['msPKI-Template-Schema-Version']

        

        self.cert_app_policy_friendly = []
        self.EKUs_friendly = []
        self.cert_name_flags_friendly = []
        self.enrollment_flags_friendly = []
        self.private_key_flags_friendly = []
        
        self.get_EKUs('pKIExtendedKeyUsage', self.EKUs_friendly)
        self.get_EKUs('msPKI-Certificate-Application-Policy', self.cert_app_policy_friendly)
        self.get_flags('msPKI-Certificate-Name-Flag', MS_PKI_CERTIFICATE_NAME_FLAGS, self.cert_name_flags_friendly)
        self.get_flags('msPKI-Enrollment-Flag', MS_PKI_ENROLLMENT_FLAGS, self.enrollment_flags_friendly)


    def get_EKUs(self, attribute, result):
        try:
            for eku in self.raw_template[attribute]:
                result.append(OID_TO_STR_MAP[eku])
        except KeyError:
            pass

    
    def get_flags(self, attribute, PKI_DICT, result):
        flags = self.raw_template.entry_raw_attribute(attribute)[0]
        for key, val in PKI_DICT.items():
             if int(flags) & key == key:
                result.append(val)

    
    def print_template(self):
        print(template_str.format(
            self.name,
            self.schema_version,
            self.join_list(self.cert_name_flags_friendly),
            self.join_list(self.enrollment_flags_friendly),
            self.ra_signiture,
            self.join_list(self.EKUs_friendly),
            self.join_list(self.cert_app_policy_friendly)
        ))


    def join_list(self, arr):
        return ', '.join([str(word) for word in arr])


template_str = '''
  Common Name: {}
  msPKI-Template-Schema-Version: {}
  msPKI-Certificate-Name-Flag: {}
  msPKI-Enrollment-Flag: {}
  msPKI-RA-Signature: {}
  pKIExtendedKeyUsage: {}
  msPKI-Certificate-Application-Policy: {}
'''
