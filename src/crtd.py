
# 2.26 msPKI-Enrollment-Flag Attribute
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x00000004
CT_FLAG_PUBLISH_TO_DS = 0x00000008
CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
CT_FLAG_AUTO_ENROLLMENT = 0x00000020
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
CT_FLAG_USER_INTERACTION_REQUIRED = 0x00000100
CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
CT_FLAG_ADD_OCSP_NOCHECK = 0x00001000
CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
CT_FLAG_SKIP_AUTO_RENEWAL = 0x00040000

# 2.27 msPKI-Private-Key-Flag Attribute
CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
CT_FLAG_EXPORTABLE_KEY = 0x00000010
CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
CT_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x00000080
CT_FLAG_USE_LEGACY_PROVIDER = 0x00000100
CT_FLAG_ATTEST_NONE = 0x00000000
CT_FLAG_ATTEST_REQUIRED = 0x000002000
CT_FLAG_ATTEST_PREFERRED = 0x000001000
CT_FLAG_ATTESTATION_WITHOUT_POLICY = 0x00004000
CT_FLAG_EK_TRUST_ON_USE = 0x00000200
CT_FLAG_EK_VALIDATE_CERT = 0x00000400
CT_FLAG_EK_VALIDATE_KEY = 0x00000800
CT_FLAG_HELLO_LOGON_KEY = 0x00200000

# 2.28 msPKI-Certificate-Name-Flag
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008

# https://www.pkisolutions.com/object-identifiers-oid-in-pki/
OID_TO_STR_MAP = {
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.23.133.8.2": "Platform Certificate",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publisher",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKIINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

MS_PKI_ENROLLMENT_FLAGS = {
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS: "INCLUDE_SYMMETRIC_ALGORITHMS",
    CT_FLAG_PEND_ALL_REQUESTS: "PEND_ALL_REQUESTS",
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER: "PUBLISH_TO_KRA_CONTAINER",
    CT_FLAG_PUBLISH_TO_DS: "PUBLISH_TO_DS",
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    CT_FLAG_AUTO_ENROLLMENT: "AUTO_ENROLLMENT",
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    CT_FLAG_USER_INTERACTION_REQUIRED: "USER_INTERACTION_REQUIRED",
    CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF: "ALLOW_ENROLL_ON_BEHALF_OF",
    CT_FLAG_ADD_OCSP_NOCHECK: "ADD_OCSP_NOCHECK",
    CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS: "NOREVOCATIONINFOINISSUEDCERTS",
    CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST: "ISSUANCE_POLICIES_FROM_REQUEST",
    CT_FLAG_SKIP_AUTO_RENEWAL: "SKIP_AUTO_RENEWAL",
}

MS_PKI_CERTIFICATE_NAME_FLAGS = {
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: "ENROLLEE_SUPPLIES_SUBJECT",
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN: "SUBJECT_ALT_REQUIRE_SPN",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN: "SUBJECT_ALT_REQUIRE_UPN",
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL: "SUBJECT_ALT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS: "SUBJECT_ALT_REQUIRE_DNS",
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN: "SUBJECT_REQUIRE_DNS_AS_CN",
    CT_FLAG_SUBJECT_REQUIRE_EMAIL: "SUBJECT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME: "SUBJECT_REQUIRE_COMMON_NAME",
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME: "LD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"
}

# Map attribute GUIDs to names
MS_PKI_GUIDS = {
    # https://docs.microsoft.com/en-us/windows/win32/adschema/a-mspkiaccountcredentials
    "b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7": "ms-PKI-AccountCredentials",
    "dbd90548-aa37-4202-9966-8c537ba5ce32": "ms-PKI-Certificate-Application-Policy",
    "ea1dddc4-60ff-416e-8cc0-17cee534bce7": "ms-PKI-Certificate-Name-Flag",
    "38942346-cc5b-424b-a7d8-6ffd12029c5f": "ms-PKI-Certificate-Policy",
    "3164c36a-ba26-468c-8bda-c1e5cc256728": "ms-PKI-Cert-Template-OID",
    "b7ff5a38-0818-42b0-8110-d3d154c97f24": "ms-PKI-Credential-Roaming-Tokens",
    "b3f93023-9239-4f7c-b99c-6745d87adbc2": "ms-PKI-DPAPIMasterKeys",
    "d15ef7d8-f226-46db-ae79-b34e560bd12c": "ms-PKI-Enrollment-Flag",
    "22bd38f-a1d0-4832-8b28-0331438886a6": "ms-PKI-Enrollment-Servers",
    "e96a63f5-417f-46d3-be52-db7703c503df": "ms-PKI-Minimal-Key-Size",
    "8c9e1288-5028-4f4f-a704-76d026f246ef": "ms-PKI-OID-Attribute",
    "5f49940e-a79f-4a51-bb6f-3d446a54dc6b": "ms-PKI-OID-CPS",
    "7d59a816-bb05-4a72-971f-5c1331f67559": "ms-PKI-OID-LocalizedName",
    "04c4da7a-e114-4e69-88de-e293f2d3b395": "ms-PKI-OID-User-Notice",
    "bab04ac2-0435-4709-9307-28380e7c7001": "ms-PKI-Private-Key-Flag",
    "3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a": "ms-PKI-RA-Application-Policies",
    "d546ae22-0951-4d47-817e-1c9f96faad46": "ms-PKI-RA-Policies",
    "fe17e04b-937d-4f7e-8e0e-9292c8d5683e": "ms-PKI-RA-Signature",
    "6617e4ac-a2f1-43ab-b60c-11fbd1facf05": "ms-PKI-RoamingTimeStamp",
    "0cd8711f-0afc-4926-a4b1-09b08d3d436c": "ms-PKI-Site-Name",
    "9de8ae7d-7a5b-421d-b5e4-061f79dfd5d7": "ms-PKI-Supersede-Templates",
    "13f5236c-1884-46b1-b5d0-484e38990d58": "ms-PKI-Template-Minor-Revision",
    "0c15e9f5-491d-4594-918f-32813a091da9": "ms-PKI-Template-Schema-Version",

    # https://docs.microsoft.com/en-us/windows/win32/adschema/a-pkiextendedkeyusage
    "18976af6-3b9e-11d2-90cc-00c04fd91ab1": "PKI-Extended-Key-Usage",

    # not technically ms-PKI GUIDs, but commonly seen
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment"
}