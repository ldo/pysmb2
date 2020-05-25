"""A pure-Python wrapper for libsmb2 <https://www.samba.org> using
ctypes."""

#+
# Copyright 2020 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import ctypes as ct
from weakref import \
    ref as weak_ref, \
    WeakValueDictionary
import atexit
import select
import asyncio

smb2 = ct.cdll.LoadLibrary("libsmb2.so.1")

class SMB2 :
    "useful definitions adapted from the smb2 include files. You will need" \
    " to use the constants, but apart from that, see the more Pythonic wrappers" \
    " defined outside of this class in preference to accessing low-level structures" \
    " directly."

    # General ctypes gotcha: when passing addresses of ctypes-constructed objects
    # to routine calls, do not construct the objects directly in the call. Otherwise
    # the refcount goes to 0 before the routine is actually entered, and the object
    # can get prematurely disposed. Always store the object reference into a local
    # variable, and pass the value of the variable instead.

    # from smb2/smb2-errors.h:

    STATUS_SEVERITY_MASK = 0xc0000000
    STATUS_SEVERITY_SUCCESS = 0x00000000
    STATUS_SEVERITY_INFO = 0x40000000
    STATUS_SEVERITY_WARNING = 0x80000000
    STATUS_SEVERITY_ERROR = 0xc0000000
    STATUS_CUSTOMER_MASK = 0x20000000
    STATUS_FACILITY_MASK = 0x0fff0000
    STATUS_CODE_MASK = 0x0000ffff

    STATUS_SUCCESS = 0x00000000
    STATUS_CANCELLED = 0xffffffff
    STATUS_PENDING = 0x00000103
    STATUS_SMB_BAD_FID = 0x00060001
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_NOT_IMPLEMENTED = 0xC0000002
    STATUS_INVALID_HANDLE = 0xC0000008
    STATUS_INVALID_PARAMETER = 0xC000000d
    STATUS_NO_SUCH_DEVICE = 0xC000000E
    STATUS_NO_SUCH_FILE = 0xC000000F
    STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_NO_MEDIA_IN_DEVICE = 0xC0000013
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_INVALID_LOCK_SEQUENCE = 0xC000001E
    STATUS_INVALID_VIEW_SIZE = 0xC000001F
    STATUS_ALREADY_COMMITTED = 0xC0000021
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    STATUS_PORT_DISCONNECTED = 0xC0000037
    STATUS_OBJECT_PATH_INVALID = 0xC0000039
    STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B
    STATUS_DATA_ERROR = 0xC000003E
    STATUS_CRC_ERROR = 0xC000003F
    STATUS_SECTION_TOO_BIG = 0xC0000040
    STATUS_PORT_CONNECTION_REFUSED = 0xC0000041
    STATUS_INVALID_PORT_HANDLE = 0xC0000042
    STATUS_SHARING_VIOLATION = 0xC0000043
    STATUS_THREAD_IS_TERMINATING = 0xC000004B
    STATUS_FILE_LOCK_CONFLICT = 0xC0000054
    STATUS_LOCK_NOT_GRANTED = 0xC0000055
    STATUS_DELETE_PENDING = 0xC0000056
    STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
    STATUS_LOGON_FAILURE = 0xC000006d
    STATUS_ACCOUNT_RESTRICTION = 0xC000006E
    STATUS_INVALID_LOGON_HOURS = 0xC000006F
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_ACCOUNT_DISABLED = 0xC0000072
    STATUS_DISK_FULL = 0xC000007F
    STATUS_TOO_MANY_PAGING_FILES = 0xC0000097
    STATUS_DFS_EXIT_PATH_FOUND = 0xC000009B
    STATUS_DEVICE_DATA_ERROR = 0xC000009C
    STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2
    STATUS_ILLEGAL_FUNCTION = 0xC00000AF
    STATUS_PIPE_DISCONNECTED = 0xC00000B0
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NETWORK_ACCESS_DENIED = 0xC00000CA
    STATUS_BAD_NETWORK_NAME = 0xC00000CC
    STATUS_NOT_SAME_DEVICE = 0xC00000D4
    STATUS_FILE_RENAMED = 0xC00000D5
    STATUS_REDIRECTOR_NOT_STARTED = 0xC00000FB
    STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101
    STATUS_NOT_A_DIRECTORY = 0xC0000103
    STATUS_PROCESS_IS_TERMINATING = 0xC000010A
    STATUS_TOO_MANY_OPENED_FILES = 0xC000011F
    STATUS_CANNOT_DELETE = 0xC0000121
    STATUS_FILE_DELETED = 0xC0000123
    STATUS_FILE_CLOSED = 0xC0000128
    STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
    STATUS_HANDLE_NOT_CLOSABLE = 0xC0000235
    STATUS_NOT_A_REPARSE_POINT = 0xC0000275

    # from smb2/smb2.h:

    class c_timeval_t(ct.Structure) :
        _fields_ = \
            [
                ("tv_sec", ct.c_uint32),
                ("tv_usec", ct.c_uint32),
            ]
    #end c_timeval_t

    ERROR_REPLY_SIZE = 9

    class error_reply(ct.Structure) :
        _fields_ = \
            [
                ("error_context_count", ct.c_uint8),
                ("byte_count", ct.c_uint32),
                ("error_data", ct.POINTER(ct.c_uint8)),
            ]
    #end error_reply

    FLAGS_SERVER_TO_REDIR = 0x00000001
    FLAGS_ASYNC_COMMAND = 0x00000002
    FLAGS_RELATED_OPERATIONS = 0x00000004
    FLAGS_SIGNED = 0x00000008
    FLAGS_PRIORITY_MASK = 0x00000070
    FLAGS_DFS_OPERATIONS = 0x10000000
    FLAGS_REPLAY_OPERATION = 0x20000000

    # values for smb2_command
    NEGOTIATE = 0
    SESSION_SETUP = 1
    LOGOFF = 2
    TREE_CONNECT = 3
    TREE_DISCONNECT = 4
    CREATE = 5
    CLOSE = 6
    FLUSH = 7
    READ = 8
    WRITE = 9
    # LOCK = 10
    IOCTL = 11
    # CANCEL = 12
    ECHO = 13
    QUERY_DIRECTORY = 14
    # CHANGE_NOTIFY = 15
    QUERY_INFO = 16
    SET_INFO = 17
    # OPLOCK_BREAK = 18

    NEGOTIATE_SIGNING_ENABLED = 0x0001
    NEGOTIATE_SIGNING_REQUIRED = 0x0002

    # values for smb2_negotiate_version
    VERSION_ANY = 0
    VERSION_ANY2 = 2
    VERSION_ANY3 = 3
    VERSION_0202 = 0x0202
    VERSION_0210 = 0x0210
    VERSION_0300 = 0x0300
    VERSION_0302 = 0x0302

    GLOBAL_CAP_DFS = 0x00000001
    GLOBAL_CAP_LEASING = 0x00000002
    GLOBAL_CAP_LARGE_MTU = 0x00000004
    GLOBAL_CAP_MULTI_CHANNEL = 0x00000008
    GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
    GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020
    GLOBAL_CAP_ENCRYPTION = 0x00000040

    NEGOTIATE_MAX_DIALECTS = 10

    NEGOTIATE_REQUEST_SIZE = 36

    GUID_SIZE = 16
    guid = GUID_SIZE * ct.c_uint8

    class negotiate_request(ct.Structure) :
        pass
    negotiate_request._fields_ = \
        [
            ("dialect_count", ct.c_uint16),
            ("security_mode", ct.c_uint16),
            ("capabilities", ct.c_uint16),
            ("client_guid", guid),
            ("capabilities", ct.c_uint64),
            ("dialects", ct.c_uint * NEGOTIATE_MAX_DIALECTS),
        ]
     #end negotiate_request

    NEGOTIATE_REPLY_SIZE = 65

    class negotiate_reply(ct.Structure) :
        pass
    negotiate_reply._fields_ = \
        [
            ("security_mode", ct.c_uint16),
            ("dialect_revision", ct.c_uint16),
            ("server_guid", guid),
            ("capabilities", ct.c_uint32),
            ("max_transact_size", ct.c_uint32),
            ("max_read_size", ct.c_uint32),
            ("max_write_size", ct.c_uint32),
            ("system_time", ct.c_uint64),
            ("server_start_time", ct.c_uint64),
            ("security_buffer_length", ct.c_uint16),
            ("security_buffer_offset", ct.c_uint16),
            ("security_buffer", ct.POINTER(ct.c_uint8)),
        ]
    #end negotiate_reply

    SESSION_FLAG_BINDING = 0x01

    GLOBAL_CAP_DFS = 0x00000001
    GLOBAL_CAP_UNUSED1 = 0x00000002
    GLOBAL_CAP_UNUSED2 = 0x00000004
    GLOBAL_CAP_UNUSED4 = 0x00000008

    SESSION_SETUP_REQUEST_SIZE = 25

    class session_setup_request(ct.Structure) :
        _fields_ = \
            [
                ("flags", ct.c_uint8),
                ("security_mode", ct.c_uint8),
                ("capabilities", ct.c_uint32),
                ("channel", ct.c_uint32),
                ("previous_session_id", ct.c_uint64),
                ("security_buffer_length", ct.c_uint16),
                ("security_buffer", ct.POINTER(ct.c_uint8)),
            ]
    #end session_setup_request

    SESSION_FLAG_IS_GUEST = 0x0001
    SESSION_FLAG_IS_NULL = 0x0002
    SESSION_FLAG_IS_ENCRYPT_DATA = 0x0004

    SESSION_SETUP_REPLY_SIZE = 9

    class session_setup_reply(ct.Structure) :
        _fields_ = \
            [
                ("session_flags", ct.c_uint16),
                ("security_buffer_length", ct.c_uint16),
                ("security_buffer_offset", ct.c_uint16),
                ("security_buffer", ct.POINTER(ct.c_uint8)),
            ]
    #end session_setup_reply

    TREE_CONNECT_REQUEST_SIZE = 9

    SHAREFLAG_CLUSTER_RECONNECT = 0x0001

    class tree_connect_request(ct.Structure) :
        _fields_ = \
            [
                ("flags", ct.c_uint16),
                ("path_length", ct.c_uint16),
                ("path", ct.POINTER(ct.c_uint16)),
            ]
    #end tree_connect_request

    SHARE_TYPE_DISK = 0x01
    SHARE_TYPE_PIPE = 0x02
    SHARE_TYPE_PRINT = 0x03

    SHAREFLAG_MANUAL_CACHING = 0x00000000
    SHAREFLAG_DFS = 0x00000001
    SHAREFLAG_DFS_ROOT = 0x00000002
    SHAREFLAG_AUTO_CACHING = 0x00000010
    SHAREFLAG_VDO_CACHING = 0x00000020
    SHAREFLAG_NO_CACHING = 0x00000030
    SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100
    SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200
    SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400
    SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
    SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000
    SHAREFLAG_ENABLE_HASH_V1 = 0x00002000
    SHAREFLAG_ENABLE_HASH_V2 = 0x00004000
    SHAREFLAG_ENCRYPT_DATA = 0x00008000

    SHARE_CAP_DFS = 0x00000008
    SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010
    SHARE_CAP_SCALEOUT = 0x00000020
    SHARE_CAP_CLUSTER = 0x00000040
    SHARE_CAP_ASYMMETRIC = 0x00000080

    TREE_CONNECT_REPLY_SIZE = 16

    class tree_connect_reply(ct.Structure) :
        _fields_ = \
            [
                ("share_type", ct.c_uint8),
                ("share_flags", ct.c_uint32),
                ("capabilities", ct.c_uint32),
                ("maximal_access", ct.c_uint32),
            ]
    #end tree_connect_reply

    CREATE_REQUEST_SIZE = 57

    OPLOCK_LEVEL_NONE = 0x00
    OPLOCK_LEVEL_II = 0x01
    OPLOCK_LEVEL_EXCLUSIVE = 0x08
    OPLOCK_LEVEL_BATCH = 0x09
    OPLOCK_LEVEL_LEASE = 0xff

    IMPERSONATION_ANONYMOUS = 0x00000000
    IMPERSONATION_IDENTIFICATION = 0x00000001
    IMPERSONATION_IMPERSONATION = 0x00000002
    IMPERSONATION_DELEGATE = 0x00000003

    FILE_READ_EA = 0x00000008
    FILE_WRITE_EA = 0x00000010
    FILE_DELETE_CHILD = 0x00000040
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_WRITE_ATTRIBUTES = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DACL = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    MAXIMUM_ALLOWED = 0x02000000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000

    FILE_READ_DATA = 0x00000001
    FILE_WRITE_DATA = 0x00000002
    FILE_APPEND_DATA = 0x00000004
    FILE_EXECUTE = 0x00000020

    FILE_LIST_DIRECTORY = 0x00000001
    FILE_ADD_FILE = 0x00000002
    FILE_ADD_SUBDIRECTORY = 0x00000004
    FILE_TRAVERSE = 0x00000020

    FILE_ATTRIBUTE_READONLY = 0x00000001
    FILE_ATTRIBUTE_HIDDEN = 0x00000002
    FILE_ATTRIBUTE_SYSTEM = 0x00000004
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800
    FILE_ATTRIBUTE_OFFLINE = 0x00001000
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000

    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004

    FILE_SUPERSEDE = 0x00000000
    FILE_OPEN = 0x00000001
    FILE_CREATE = 0x00000002
    FILE_OPEN_IF = 0x00000003
    FILE_OVERWRITE = 0x00000004
    FILE_OVERWRITE_IF = 0x00000005

    FILE_DIRECTORY_FILE = 0x00000001
    FILE_WRITE_THROUGH = 0x00000002
    FILE_SEQUENTIAL_ONLY = 0x00000004
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    FILE_NON_DIRECTORY_FILE = 0x00000040
    FILE_COMPLETE_IF_OPLOCKED = 0x00000100
    FILE_NO_EA_KNOWLEDGE = 0x00000200
    FILE_RANDOM_ACCESS = 0x00000800
    FILE_DELETE_ON_CLOSE = 0x00001000
    FILE_OPEN_BY_FILE_ID = 0x00002000
    FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
    FILE_NO_COMPRESSION = 0x00008000
    FILE_OPEN_REMOTE_INSTANCE = 0x00000400
    FILE_OPEN_REQUIRING_OPLOCK = 0x00010000
    FILE_DISALLOW_EXCLUSIVE = 0x00020000
    FILE_RESERVE_OPFILTER = 0x00100000
    FILE_OPEN_REPARSE_POINT = 0x00200000
    FILE_OPEN_NO_RECALL = 0x00400000
    FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000

    class create_request(ct.Structure) :
        _fields_ = \
            [
                ("security_flags", ct.c_uint8),
                ("requested_oplock_level", ct.c_uint8),
                ("impersonation_level", ct.c_uint32),
                ("smb_create_flags", ct.c_uint64),
                ("desired_access", ct.c_uint32),
                ("file_attributes", ct.c_uint32),
                ("share_access", ct.c_uint32),
                ("create_disposition", ct.c_uint32),
                ("create_options", ct.c_uint32),
                ("name", ct.c_char_p), # UTF-8
                ("create_context_length", ct.c_uint32),
                ("*create_context", ct.c_uint8),
            ]
    #end create_request

    CREATE_REPLY_SIZE = 89

    FD_SIZE = 16
    file_id = FD_SIZE * ct.c_uint8

    fh_ptr = ct.c_void_p
    context_ptr = ct.c_void_p

    class create_reply(ct.Structure) :
        pass
    create_reply._fields_ = \
        [
            ("oplock_level", ct.c_uint8),
            ("flags", ct.c_uint8),
            ("create_action", ct.c_uint32),
            ("creation_time", ct.c_uint64),
            ("last_access_time", ct.c_uint64),
            ("last_write_time", ct.c_uint64),
            ("change_time", ct.c_uint64),
            ("allocation_size", ct.c_uint64),
            ("end_of_file", ct.c_uint64),
            ("file_attributes", ct.c_uint32),
            ("file_id", file_id),
            ("create_context_length", ct.c_uint32),
            ("create_context_offset", ct.c_uint32),
            ("create_context", ct.POINTER(ct.c_uint8)),
        ]
    #end create_reply

    CLOSE_REQUEST_SIZE = 24

    CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001

    class close_request(ct.Structure) :
        pass
    close_request._fields_ = \
        [
            ("flags", ct.c_uint16),
            ("file_id", file_id),
        ]
    #end close_request

    CLOSE_REPLY_SIZE = 60

    class close_reply(ct.Structure) :
        _fields_ = \
            [
                ("flags", ct.c_uint16),
                ("creation_time", ct.c_uint64),
                ("last_access_time", ct.c_uint64),
                ("last_write_time", ct.c_uint64),
                ("change_time", ct.c_uint64),
                ("allocation_size", ct.c_uint64),
                ("end_of_file", ct.c_uint64),
                ("file_attributes", ct.c_uint32),
            ]
    #end close_reply

    FLUSH_REQUEST_SIZE = 24

    class flush_request(ct.Structure) :
        pass
    flush_request._fields_ = \
        [
            ("file_id", file_id),
        ]
    #end flush_request

    FLUSH_REPLY_SIZE = 4

    QUERY_DIRECTORY_REQUEST_SIZE = 33

    FILE_DIRECTORY_INFORMATION = 0x01
    FILE_FULL_DIRECTORY_INFORMATION = 0x02
    FILE_BOTH_DIRECTORY_INFORMATION = 0x03
    FILE_NAMES_INFORMATION = 0x0c
    FILE_ID_BOTH_DIRECTORY_INFORMATION = 0x25
    FILE_ID_FULL_DIRECTORY_INFORMATION = 0x26

    RESTART_SCANS = 0x01
    RETURN_SINGLE_ENTRY = 0x02
    INDEX_SPECIFIED = 0x04
    REOPEN = 0x10

    class fileidfulldirectoryinformation(ct.Structure) :
        pass
    fileidfulldirectoryinformation._fields_ = \
        [
            ("next_entry_offset", ct.c_uint32),
            ("file_index", ct.c_uint32),
            ("creation_time", c_timeval_t),
            ("last_access_time", c_timeval_t),
            ("last_write_time", c_timeval_t),
            ("change_time", c_timeval_t),
            ("end_of_file", ct.c_uint64),
            ("allocation_size", ct.c_uint64),
            ("file_attributes", ct.c_uint32),
            ("ea_size", ct.c_uint32),
            ("file_id", ct.c_uint64),
            ("name", ct.c_void_p),
        ]
    #end fileidfulldirectoryinformation

    class query_directory_request(ct.Structure) :
        pass
    query_directory_request._fields_ = \
        [
            ("file_information_class", ct.c_uint8),
            ("flags", ct.c_uint8),
            ("file_index", ct.c_uint32),
            ("file_id", file_id),
            ("name", ct.c_char_p), # UTF-8
            ("output_buffer_length", ct.c_uint32),
        ]
    #end query_directory_request

    QUERY_DIRECTORY_REPLY_SIZE = 9

    class query_directory_reply(ct.Structure) :
        _fields_ = \
            [
                ("output_buffer_offset", ct.c_uint16),
                ("output_buffer_length", ct.c_uint32),
                ("*output_buffer", ct.c_uint8),
            ]
    #end query_directory_reply

    READ_REQUEST_SIZE = 49

    READFLAG_READ_UNBUFFERED = 0x01

    CHANNEL_NONE = 0x00000000
    CHANNEL_RDMA_V1 = 0x00000001
    CHANNEL_RDMA_V1_INVALIDATE = 0x00000002

    class read_request(ct.Structure) :
        pass
    read_request._fields_ = \
        [
            ("flags", ct.c_uint8),
            ("length", ct.c_uint32),
            ("offset", ct.c_uint64),
            ("*buf", ct.c_uint8),
            ("file_id", file_id),
            ("minimum_count", ct.c_uint32),
            ("channel", ct.c_uint32),
            ("remaining_bytes", ct.c_uint32),
            ("read_channel_info_length", ct.c_uint16),
            ("read_channel_info", ct.POINTER(ct.c_uint8)),
        ]
    #end read_request

    READ_REPLY_SIZE = 17

    class read_reply(ct.Structure) :
        _fields_ = \
            [
                ("data_offset", ct.c_uint8),
                ("data_length", ct.c_uint32),
                ("data_remaining", ct.c_uint32),
            ]
    #end read_reply

    QUERY_INFO_REQUEST_SIZE = 41

    s0_INFO_FILE = 0x01
    s0_INFO_FILESYSTEM = 0x02
    s0_INFO_SECURITY = 0x03
    s0_INFO_QUOTA = 0x04

    FILE_BASIC_INFORMATION = 0x04
    FILE_STANDARD_INFORMATION = 0x05
    FILE_RENAME_INFORMATION = 0x0a
    FILE_ALL_INFORMATION = 0x12
    FILE_END_OF_FILE_INFORMATION = 0x14

    FILE_FS_SIZE_INFORMATION = 3
    FILE_FS_DEVICE_INFORMATION = 4
    FILE_FS_CONTROL_INFORMATION = 6
    FILE_FS_FULL_SIZE_INFORMATION = 7
    FILE_FS_SECTOR_SIZE_INFORMATION = 11

    OWNER_SECURITY_INFORMATION = 0x00000001
    GROUP_SECURITY_INFORMATION = 0x00000002
    DACL_SECURITY_INFORMATION = 0x00000004
    SACL_SECURITY_INFORMATION = 0x00000008
    LABEL_SECURITY_INFORMATION = 0x00000010
    ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
    SCOPE_SECURITY_INFORMATION = 0x00000040
    BACKUP_SECURITY_INFORMATION = 0x00010000

    RESTART_SCAN = 0x00000001
    RETURN_SINGLE_ENTRY = 0x00000002
    INDEX_SPECIFIED = 0x00000004

    class file_basic_info(ct.Structure) :
        pass
    file_basic_info._fields_ = \
        [
            ("creation_time", c_timeval_t),
            ("last_access_time", c_timeval_t),
            ("last_write_time", c_timeval_t),
            ("change_time", c_timeval_t),
            ("file_attributes", ct.c_uint32),
        ]
    #end file_basic_info

    class file_standard_info(ct.Structure) :
        _fields_ = \
            [
                ("allocation_size", ct.c_uint64),
                ("end_of_file", ct.c_uint64),
                ("number_of_links", ct.c_uint32),
                ("delete_pending", ct.c_uint8),
                ("directory", ct.c_uint8),
            ]
    #end file_standard_info

    class file_all_info(ct.Structure) :
        pass
    file_all_info._fields_ = \
        [
            ("basic", file_basic_info),
            ("standard", file_standard_info),
            ("index_number", ct.c_uint64),
            ("ea_size", ct.c_uint32),
            ("access_flags", ct.c_uint32),
            ("current_byte_offset", ct.c_uint64),
            ("mode", ct.c_uint32),
            ("alignment_requirement", ct.c_uint32),
            ("name_information", ct.POINTER(ct.c_uint8)),
        ]
    #end file_all_info

    class query_info_request(ct.Structure) :
        pass
    query_info_request._fields_ = \
        [
            ("info_type", ct.c_uint8),
            ("file_info_class", ct.c_uint8),
            ("output_buffer_length", ct.c_uint32),
            ("input_buffer_length", ct.c_uint32),
            ("input_buffer", ct.POINTER(ct.c_uint8)),
            ("additional_information", ct.c_uint32),
            ("flags", ct.c_uint32),
            ("file_id", file_id),
        ]
    #end query_info_request

    class file_end_of_file_info(ct.Structure) :
        _fields_ = \
            [
                ("end_of_file", ct.c_uint64),
            ]
    #end file_end_of_file_info

    class file_rename_info(ct.Structure) :
        _fields_ = \
            [
                ("replace_if_exist", ct.c_uint8),
                ("file_name", ct.POINTER(ct.c_uint8)),
            ]
    #end file_rename_info

    SET_INFO_REQUEST_SIZE = 33

    class set_info_request(ct.Structure) :
        pass
    set_info_request._fields_ = \
        [
            ("info_type", ct.c_uint8),
            ("file_info_class", ct.c_uint8),
            ("input_data", ct.c_void_p),
            ("additional_information", ct.c_uint32),
            ("file_id", file_id),
        ]
    #end set_info_request

    SET_INFO_REPLY_SIZE = 2

    ID_AUTH_LEN = 6

    class sid(ct.Structure) :
        pass
    sid._fields_ = \
        [
            ("revision", ct.c_uint8),
            ("sub_auth_count", ct.c_uint8),
            ("id_auth", ID_AUTH_LEN * ct.c_uint8),
            ("sub_auth", 0 * ct.c_uint32),
        ]
    #end sid

    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02
    # SYSTEM_ALARM_ACE_TYPE = 0x03 # reserved for future use
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    # SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08 # reserved for future use
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13

    OBJECT_INHERIT_ACE = 0x01
    CONTAINER_INHERIT_ACE = 0x02
    NO_PROPAGATE_INHERIT_ACE = 0x04
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
    FAILED_ACCESS_ACE_FLAG = 0x80

    OBJECT_TYPE_SIZE = 16

    class ace(ct.Structure) :
        pass
    ace._fields_ = \
        [
            ("next", ct.POINTER(ace)),
            ("ace_type", ct.c_uint8),
            ("ace_flags", ct.c_uint8),
            ("ace_size", ct.c_uint16),
            ("mask", ct.c_uint32),
            ("flags", ct.c_uint32),
            ("sid", ct.POINTER(sid)),
            ("object_type", OBJECT_TYPE_SIZE * ct.c_uint8),
            ("inherited_object_type", OBJECT_TYPE_SIZE * ct.c_uint8),
            ("ad_len", ct.c_int),
            ("ad_data", ct.c_char_p),
            ("raw_len", ct.c_int),
            ("raw_data", ct.c_char_p),
        ]
    #end ace

    ACL_REVISION = 0x02
    ACL_REVISION_DS = 0x04

    class acl(ct.Structure) :
        pass
    acl._fields_ = \
        [
            ("revision", ct.c_uint8),
            ("ace_count", ct.c_uint16),
            ("aces", ct.POINTER(ace)),
        ]
    #end acl

    SD_CONTROL_OD = 0x0001
    SD_CONTROL_GD = 0x0002
    SD_CONTROL_DP = 0x0004
    SD_CONTROL_DD = 0x0008
    SD_CONTROL_SP = 0x0010
    SD_CONTROL_SD = 0x0020
    SD_CONTROL_SS = 0x0040
    SD_CONTROL_DT = 0x0080
    SD_CONTROL_DC = 0x0100
    SD_CONTROL_SC = 0x0200
    SD_CONTROL_DI = 0x0400
    SD_CONTROL_SI = 0x0800
    SD_CONTROL_PD = 0x1000
    SD_CONTROL_PS = 0x2000
    SD_CONTROL_RM = 0x4000
    SD_CONTROL_SR = 0x8000

    class security_descriptor(ct.Structure) :
        pass
    security_descriptor._fields_ = \
        [
            ("revision", ct.c_uint8),
            ("control", ct.c_uint16),
            ("owner", ct.POINTER(sid)),
            ("group", ct.POINTER(sid)),
            ("dacl", ct.POINTER(acl)),
        ]
    #end security_descriptor

    class file_fs_size_info(ct.Structure) :
        _fields_ = \
            [
                ("total_allocation_units", ct.c_uint64),
                ("available_allocation_units", ct.c_uint64),
                ("sectors_per_allocation_unit", ct.c_uint32),
                ("bytes_per_sector", ct.c_uint32),
            ]
    #end file_fs_size_info

    DEVICE_CD_ROM = 0x00000002
    DEVICE_DISK = 0x00000007

    REMOVABLE_MEDIA = 0x00000001
    READ_ONLY_DEVICE = 0x00000002
    FLOPPY_DISKETTE = 0x00000004
    WRITE_ONCE_MEDIA = 0x00000008
    REMOTE_DEVICE = 0x00000010
    DEVICE_IS_MOUNTED = 0x00000020
    VIRTUAL_VOLUME = 0x00000040
    DEVICE_SECURE_OPEN = 0x00000100
    CHARACTERISTIC_TS_DEVICE = 0x00001000
    CHARACTERISTIC_WEBDAV_DEVICE = 0x00002000
    DEVICE_ALLOW_APPCONTAINER_TRAVERSAL = 0x00020000
    PORTABLE_DEVICE = 0x00040000

    class file_fs_device_info(ct.Structure) :
        _fields_ = \
            [
                ("device_type", ct.c_uint32),
                ("characteristics", ct.c_uint32),
            ]
    #end file_fs_device_info

    VC_QUOTA_TRACK = 0x00000001
    VC_QUOTA_ENFORCE = 0x00000002
    VC_CONTENT_INDEX_DISABLED = 0x00000008
    VC_LOG_QUOTA_THRESHOLD = 0x00000010
    VC_LOG_QUOTA_LIMIT = 0x00000020
    VC_LOG_VOLUME_THRESHOLD = 0x00000040
    VC_LOG_VOLUME_LIMIT = 0x00000080
    VC_QUOTAS_INCOMPLETE = 0x00000100
    VC_QUOTAS_REBUILDING = 0x00000200

    class file_fs_control_info(ct.Structure) :
        _fields_ = \
            [
                ("free_space_start_filtering", ct.c_uint64),
                ("free_space_threshold", ct.c_uint64),
                ("free_space_stop_filtering", ct.c_uint64),
                ("default_quota_threshold", ct.c_uint64),
                ("default_quota_limit", ct.c_uint64),
                ("file_system_control_flags", ct.c_uint32),
            ]
    #end file_fs_control_info

    class file_fs_full_size_info(ct.Structure) :
        _fields_ = \
            [
                ("total_allocation_units", ct.c_uint64),
                ("caller_available_allocation_units", ct.c_uint64),
                ("actual_available_allocation_units", ct.c_uint64),
                ("sectors_per_allocation_unit", ct.c_uint32),
                ("bytes_per_sector", ct.c_uint32),
            ]
    #end file_fs_full_size_info

    FLAGS_ALIGNED_DEVICE = 0x00000001
    FLAGS_PARTITION_ALIGNED_ON_DEVICE = 0x00000002
    FLAGS_NO_SEEK_PENALTY = 0x00000004
    FLAGS_TRIM_ENABLED = 0x00000008

    class file_fs_sector_size_info(ct.Structure) :
        _fields_ = \
            [
                ("logical_bytes_per_sector", ct.c_uint32),
                ("physical_bytes_per_sector_for_atomicity", ct.c_uint32),
                ("physical_bytes_per_sector_for_performance", ct.c_uint32),
                ("file_system_effective_physical_bytes_per_sector_for_atomicity", ct.c_uint32),
                ("flags", ct.c_uint32),
                ("byte_offset_for_sector_alignment", ct.c_uint32),
                ("byte_offset_for_partition_alignment", ct.c_uint32),
            ]
    #dnd file_fs_sector_size_info

    QUERY_INFO_REPLY_SIZE = 9

    class query_info_reply(ct.Structure) :
        _fields_ = \
            [
                ("output_buffer_offset", ct.c_uint16),
                ("output_buffer_length", ct.c_uint32),
                ("output_buffer", ct.c_void_p),
            ]
    #end query_info_reply

    IOCTL_REQUEST_SIZE = 57

    FSCTL_DFS_GET_REFERRALS = 0x00060194
    FSCTL_PIPE_PEEK = 0x0011400C
    FSCTL_PIPE_WAIT = 0x00110018
    FSCTL_PIPE_TRANSCEIVE = 0x0011C017
    FSCTL_SRV_COPYCHUNK = 0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
    FSCTL_SRV_READ_HASH = 0x001441bb
    FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4
    FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    FSCTL_SET_REPARSE_POINT = 0x000900A4
    FSCTL_GET_REPARSE_POINT = 0X000900A8
    FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
    FSCTL_FILE_LEVEL_TRIM = 0x00098208
    FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204

    s0_IOCTL_IS_FSCTL = 0x00000001

    SYMLINK_FLAG_RELATIVE = 0x00000001

    class symlink_reparse_buffer(ct.Structure) :
        _fields_ = \
            [
                ("flags", ct.c_uint32),
                ("subname", ct.c_char_p),
                ("printname", ct.c_char_p),
            ]
    #end symlink_reparse_buffer

    REPARSE_TAG_SYMLINK = 0xa000000c

    class reparse_data_buffer(ct.Structure) :
        pass
    reparse_data_buffer._fields_ = \
        [
            ("reparse_tag", ct.c_uint32),
            ("reparse_data_length", ct.c_uint16),
            ("symlink", symlink_reparse_buffer), # was a union containing just this field in original
        ]
    #end reparse_data_buffer

    class ioctl_request(ct.Structure) :
        pass
    ioctl_request._fields_ = \
        [
            ("ctl_code", ct.c_uint32),
            ("file_id", file_id),
            ("input_count", ct.c_uint32),
            ("input", ct.c_void_p),
            ("flags", ct.c_uint32),
        ]
    #end ioctl_request

    IOCTL_REPLY_SIZE = 49

    class ioctl_reply(ct.Structure) :
        pass
    ioctl_reply._fields_ = \
        [
            ("ctl_code", ct.c_uint32),
            ("file_id", file_id),
            ("output_offset", ct.c_uint32),
            ("output_count", ct.c_uint32),
            ("output", ct.c_void_p),
            ("flags", ct.c_uint32),
        ]
    #end ioctl_reply

    WRITE_REQUEST_SIZE = 49

    WRITEFLAG_WRITE_THROUGH = 0x00000001
    WRITEFLAG_WRITE_UNBUFFERED = 0x00000002

    class write_request(ct.Structure) :
        pass
    write_request._fields_ = \
        [
            ("length", ct.c_uint32),
            ("offset", ct.c_uint64),
            ("buf", ct.POINTER(ct.c_uint8)),
            ("file_id", file_id),
            ("channel", ct.c_uint32),
            ("remaining_bytes", ct.c_uint32),
            ("write_channel_info_length", ct.c_uint16),
            ("write_channel_info", ct.POINTER(ct.c_uint8)),
            ("flags", ct.c_uint32),
        ]
    #end write_request

    WRITE_REPLY_SIZE = 17

    class write_reply(ct.Structure) :
        _fields_ = \
            [
                ("count", ct.c_uint32),
                ("remaining", ct.c_uint32),
            ]
    #end write_reply

    ECHO_REQUEST_SIZE = 4
    ECHO_REPLY_SIZE = 4

    LOGOFF_REQUEST_SIZE = 4
    LOGOFF_REPLY_SIZE = 4

    TREE_DISCONNECT_REQUEST_SIZE = 4
    TREE_DISCONNECT_REPLY_SIZE = 4

    ENCRYPTION_AES128_CCM = 0x0001

    # from smb2/libsmb2.h:

    class iovec(ct.Structure) :
        _fields_ = \
            [
                ("buf", ct.POINTER(ct.c_uint8)),
                ("len", ct.c_size_t),
                ("free", ct.CFUNCTYPE(None, ct.c_void_p)),
            ]
    #end iovec

    command_cb = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)

    TYPE_FILE = 0x00000000
    TYPE_DIRECTORY = 0x00000001
    TYPE_LINK = 0x00000002

    class stat_64(ct.Structure) :
        _fields_ = \
            [
                ("smb2_type", ct.c_uint32),
                ("smb2_nlink", ct.c_uint32),
                ("smb2_ino", ct.c_uint64),
                ("smb2_size", ct.c_uint64),
                ("smb2_atime", ct.c_uint64),
                ("smb2_atime_nsec", ct.c_uint64),
                ("smb2_mtime", ct.c_uint64),
                ("smb2_mtime_nsec", ct.c_uint64),
                ("smb2_ctime", ct.c_uint64),
                ("smb2_ctime_nsec", ct.c_uint64),
                ("smb2_btime", ct.c_uint64),
                ("smb2_btime_nsec", ct.c_uint64),
            ]
    #end stat_64

    class statvfs(ct.Structure) :
        _fields_ = \
            [
                ("f_bsize", ct.c_uint32),
                ("f_frsize", ct.c_uint32),
                ("f_blocks", ct.c_uint64),
                ("f_bfree", ct.c_uint64),
                ("f_bavail", ct.c_uint64),
                ("f_files", ct.c_uint32),
                ("f_ffree", ct.c_uint32),
                ("f_favail", ct.c_uint32),
                ("f_fsid", ct.c_uint32),
                ("f_flag", ct.c_uint32),
                ("f_namemax", ct.c_uint32),
            ]
    #end statvfs

    class dirent(ct.Structure) :
        pass
    dirent._fields_ = \
        [
            ("name", ct.c_char_p),
            ("st", stat_64),
        ]
    #end dirent

    t_socket = ct.c_int

    class url(ct.Structure) :
        _fields_ = \
            [
                ("domain", ct.c_char_p),
                ("user", ct.c_char_p),
                ("server", ct.c_char_p),
                ("share", ct.c_char_p),
                ("path", ct.c_char_p),
            ]
    #end url

    pdu_ptr = ct.c_void_p
    dir_ptr = ct.c_void_p

    TYPE_DISKTREE = 0
    TYPE_PRINTQ = 1
    TYPE_DEVICE = 2
    TYPE_IPC = 3

    TYPE_TEMPORARY = 0x40000000
    TYPE_HIDDEN = 0x80000000

    class srvsvc_netshareinfo1(ct.Structure) :
        _fields_ = \
            [
                ("name", ct.c_char_p),
                ("type", ct.c_uint32),
                ("comment", ct.c_char_p),
            ]
    #end srvsvc_netshareinfo1

    class srvsvc_netsharectr1(ct.Structure) :
        pass
    srvsvc_netsharectr1._fields_ = \
        [
                ("count", ct.c_uint32),
                ("array", ct.POINTER(srvsvc_netshareinfo1)),
        ]
    #end srvsvc_netsharectr1

    class srvsvc_netsharectr(ct.Structure) :
        pass
    srvsvc_netsharectr._fields_ = \
        [
            ("level", ct.c_uint32),
            ("ctr1", srvsvc_netsharectr1), # was a union containing just this field in original
        ]
    #end srvsvc_netsharectr

    class srvsvc_netshareenumall_req(ct.Structure) :
        pass
    srvsvc_netshareenumall_req._fields_ = \
        [
            ("server", ct.c_char_p),
            ("level", ct.c_uint32),
            ("ctr", ct.POINTER(srvsvc_netsharectr)),
            ("max_buffer", ct.c_uint32),
            ("resume_handle", ct.c_uint32),
        ]
    #end srvsvc_netshareenumall_req

    class srvsvc_netshareenumall_rep(ct.Structure) :
        pass
    srvsvc_netshareenumall_rep._fields_ = \
        [
            ("level", ct.c_uint32),
            ("ctr", ct.POINTER(srvsvc_netsharectr)),
            ("total_entries", ct.c_uint32),
            ("resume_handle", ct.c_uint32),
            ("status", ct.c_uint32),
        ]
    #end srvsvc_netshareenumall_rep

    # from smb2/libsmb2-dcerpc.h:

    dcerpc_context_ptr = ct.c_void_p
    dcerpc_pdu_ptr = ct.c_void_p

    dcerpc_coder = ct.CFUNCTYPE(ct.c_int, dcerpc_context_ptr, dcerpc_pdu_ptr, ct.POINTER(iovec), ct.c_int, ct.c_void_p)
    dcerpc_cb = ct.CFUNCTYPE(None, dcerpc_context_ptr, ct.c_int, ct.c_void_p, ct.c_void_p)

    ptr_type = ct.c_uint
    # values for ptr_type:
    PTR_REF = 0
    PTR_UNIQUE = 1

    class dcerpc_uuid(ct.Structure) :
        _fields_ = \
            [
                ("v1", ct.c_uint32),
                ("v2", ct.c_uint16),
                ("v3", ct.c_uint16),
                ("v4", ct.c_uint64),
            ]
    #end dcerpc_uuid

    class p_syntax_id_t(ct.Structure) :
        pass
    p_syntax_id_t._fields_ = \
        [
            ("uuid", dcerpc_uuid),
            ("vers", ct.c_uint16),
            ("vers_minor", ct.c_uint16),
        ]
    #end p_syntax_id_t

    class dcerpc_transfer_syntax(ct.Structure) :
        pass
    dcerpc_transfer_syntax._fields_ = \
        [
            ("uuid", dcerpc_uuid),
            ("vers", ct.c_uint16),
        ]
    #end dcerpc_transfer_syntax

    # from smb2/libsmb2-dcerpc-srvsvc.h:

    NETSHAREENUMALL = 15

#end SMB2

#+
# Routine arg/result types
#-

# from smb2/libsmb2-dcerpc.h:

srvsvc_interface = SMB2.p_syntax_id_t.in_dll(smb2, "srvsvc_interface")

smb2.dcerpc_create_context.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.POINTER(SMB2.p_syntax_id_t))
smb2.dcerpc_create_context.restype = SMB2.dcerpc_context_ptr
smb2.dcerpc_destroy_context.argtypes = (SMB2.dcerpc_context_ptr,)
smb2.dcerpc_destroy_context.restype = None

smb2.dcerpc_get_smb2_context.argtypes = (SMB2.dcerpc_context_ptr,)
smb2.dcerpc_get_smb2_context.restype = SMB2.context_ptr
smb2.dcerpc_get_pdu_payload.argtypes = (SMB2.dcerpc_pdu_ptr,)
smb2.dcerpc_get_pdu_payload.restype = ct.c_void_p

smb2.dcerpc_open_async.argtypes = (SMB2.dcerpc_context_ptr, SMB2.dcerpc_cb, ct.c_void_p)
smb2.dcerpc_open_async.restype = ct.c_int
if hasattr(smb2, "dcerpc_bind_async") :
    smb2.dcerpc_bind_async.argtypes = (SMB2.dcerpc_context_ptr, SMB2.dcerpc_cb, ct.c_void_p)
    smb2.dcerpc_bind_async.restype = ct.c_int
#end if
smb2.dcerpc_call_async.argtypes = \
    (SMB2.dcerpc_context_ptr, ct.c_int, SMB2.dcerpc_coder, ct.c_void_p,
    SMB2.dcerpc_coder, ct.c_int, SMB2.dcerpc_cb, ct.c_void_p)
smb2.dcerpc_call_async.restype = ct.c_int

smb2.dcerpc_decode_ptr.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int,
    ct.c_void_p, SMB2.ptr_type, SMB2.dcerpc_coder)
smb2.dcerpc_decode_ptr.restype = ct.c_int
smb2.dcerpc_decode_32.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
smb2.dcerpc_decode_32.restype = ct.c_int
smb2.dcerpc_decode_3264.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
smb2.dcerpc_decode_3264.restype = ct.c_int
smb2.dcerpc_decode_ucs2z.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
smb2.dcerpc_decode_ucs2z.restype = ct.c_int
smb2.dcerpc_encode_ptr.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int,
    ct.c_void_p, SMB2.ptr_type, SMB2.dcerpc_coder)
smb2.dcerpc_encode_ptr.restype = ct.c_int
smb2.dcerpc_encode_ucs2z.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
smb2.dcerpc_encode_ucs2z.restype = ct.c_int
smb2.dcerpc_encode_32.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
smb2.dcerpc_encode_32.restype = ct.c_int
smb2.dcerpc_encode_3264.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_uint64)
smb2.dcerpc_encode_3264.restype = ct.c_int
smb2.dcerpc_process_deferred_pointers.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int)
smb2.dcerpc_process_deferred_pointers.restype = ct.c_int
smb2.dcerpc_add_deferred_pointer.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, SMB2.dcerpc_coder, ct.c_void_p)
smb2.dcerpc_add_deferred_pointer.restype = None

# from smb2/libsmb2-dcerpc-srvsvc.h:

if hasattr(smb2, "srvsvc_netshareenumall_decoder") :
    smb2.srvsvc_netshareenumall_decoder.argtypes = \
        (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
    smb2.srvsvc_netshareenumall_decoder.restype = ct.c_int
    smb2.srvsvc_netshareenumall_encoder.argtypes = \
        (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, ct.POINTER(SMB2.iovec), ct.c_int, ct.c_void_p)
    smb2.srvsvc_netshareenumall_encoder.restype = ct.c_int
#end if

# from smb2/libsmb2.h:

smb2.smb2_get_file_id.restype = ct.POINTER(SMB2.file_id)
smb2.smb2_get_file_id.argtypes = (SMB2.fh_ptr,)
smb2.smb2_fh_from_file_id.restype = SMB2.fh_ptr
smb2.smb2_fh_from_file_id.argtypes = (SMB2.context_ptr, ct.POINTER(SMB2.file_id))
smb2.smb2_init_context.restype = SMB2.context_ptr
smb2.smb2_init_context.argtypes = ()
smb2.smb2_destroy_context.restype = None
smb2.smb2_destroy_context.argtypes = (SMB2.context_ptr,)
smb2.smb2_get_fd.restype = SMB2.t_socket
smb2.smb2_get_fd.argtypes = (SMB2.context_ptr,)
smb2.smb2_which_events.restype = ct.c_int
smb2.smb2_which_events.argtypes = (SMB2.context_ptr,)
smb2.smb2_service.restype = ct.c_int
smb2.smb2_service.argtypes = (SMB2.context_ptr, ct.c_int)
smb2.smb2_set_security_mode.restype = None
smb2.smb2_set_security_mode.argtypes = (SMB2.context_ptr, ct.c_uint16)
smb2.smb2_set_seal.restype = None
smb2.smb2_set_seal.argtypes = (SMB2.context_ptr, ct.c_int)
smb2.smb2_set_authentication.restype = None
smb2.smb2_set_authentication.argtypes = (SMB2.context_ptr, ct.c_int)
smb2.smb2_set_user.restype = None
smb2.smb2_set_user.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_set_password.restype = None
smb2.smb2_set_password.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_set_domain.restype = None
smb2.smb2_set_domain.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_set_workstation.restype = None
smb2.smb2_set_workstation.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_get_client_guid.restype = ct.c_char_p
smb2.smb2_get_client_guid.argtypes = (SMB2.context_ptr,)

smb2.smb2_connect_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_connect_async.restype = ct.c_int
smb2.smb2_connect_share_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.c_char_p, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_connect_share_async.restype = ct.c_int
smb2.smb2_connect_share.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.c_char_p, ct.c_char_p)
smb2.smb2_connect_share.restype = ct.c_int
smb2.smb2_disconnect_share_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_disconnect_share_async.restype = ct.c_int
smb2.smb2_disconnect_share.argtypes = (SMB2.context_ptr,)
smb2.smb2_disconnect_share.restype = ct.c_int
smb2.smb2_get_error.argtypes = (SMB2.context_ptr,)
smb2.smb2_get_error.restype = ct.c_char_p

smb2.nterror_to_str.argtypes = (ct.c_uint32,)
smb2.nterror_to_str.restype = ct.c_char_p

smb2.nterror_to_errno.argtypes = (ct.c_uint32,)
smb2.nterror_to_errno.restype = ct.c_int

smb2.smb2_parse_url.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_parse_url.restype = ct.POINTER(SMB2.url)
smb2.smb2_destroy_url.argtypes = (ct.POINTER(SMB2.url),)
smb2.smb2_destroy_url.restype = None

smb2.smb2_add_compound_pdu.argtypes = \
    (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr, SMB2.dcerpc_pdu_ptr)
smb2.smb2_add_compound_pdu.restype = None
smb2.smb2_free_pdu.argtypes = (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr)
smb2.smb2_free_pdu.restype = None
smb2.smb2_queue_pdu.argtypes = (SMB2.dcerpc_context_ptr, SMB2.dcerpc_pdu_ptr)
smb2.smb2_queue_pdu.restype = None

smb2.smb2_opendir_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_opendir_async.restype = ct.c_int
smb2.smb2_opendir.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_opendir.restype = SMB2.dir_ptr
smb2.smb2_closedir.argtypes = (SMB2.context_ptr, SMB2.dir_ptr)
smb2.smb2_closedir.restype = None
smb2.smb2_readdir.argtypes = (SMB2.context_ptr, SMB2.dir_ptr)
smb2.smb2_readdir.restype = ct.POINTER(SMB2.dirent)
smb2.smb2_rewinddir.argtypes = (SMB2.context_ptr, SMB2.dir_ptr)
smb2.smb2_rewinddir.restype = None
smb2.smb2_telldir.argtypes = (SMB2.context_ptr, SMB2.dir_ptr)
smb2.smb2_telldir.restype = ct.c_long
smb2.smb2_seekdir.argtypes = (SMB2.context_ptr, SMB2.dir_ptr, ct.c_long)
smb2.smb2_seekdir.restype = None

smb2.smb2_open_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.c_int, SMB2.command_cb, ct.c_void_p)
smb2.smb2_open_async.restype = ct.c_int
smb2.smb2_open.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.c_int)
smb2.smb2_open.restype = SMB2.fh_ptr
smb2.smb2_close_async.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_close_async.restype = ct.c_int
smb2.smb2_close.argtypes = (SMB2.context_ptr, SMB2.fh_ptr)
smb2.smb2_close.restype = ct.c_int
smb2.smb2_fsync_async.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_fsync_async.restype = ct.c_int
smb2.smb2_fsync.argtypes = (SMB2.context_ptr, SMB2.fh_ptr)
smb2.smb2_fsync.restype = ct.c_int
smb2.smb2_get_max_read_size.argtypes = (SMB2.context_ptr,)
smb2.smb2_get_max_read_size.restype = ct.c_uint32
smb2.smb2_get_max_write_size.argtypes = (SMB2.context_ptr,)
smb2.smb2_get_max_write_size.restype = ct.c_uint32
smb2.smb2_pread_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32, ct.c_uint64,
    SMB2.command_cb, ct.c_void_p)
smb2.smb2_pread_async.restype = ct.c_int
smb2.smb2_pread.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32, ct.c_uint64)
smb2.smb2_pread.restype = ct.c_int
smb2.smb2_pwrite_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32, ct.c_uint64,
    SMB2.command_cb, ct.c_void_p)
smb2.smb2_pwrite_async.restype = ct.c_int
smb2.smb2_pwrite.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32, ct.c_uint64)
smb2.smb2_pwrite.restype = ct.c_int
smb2.smb2_read_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32,
    SMB2.command_cb, ct.c_void_p)
smb2.smb2_read_async.restype = ct.c_int
smb2.smb2_read.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32)
smb2.smb2_read.restype = ct.c_int
smb2.smb2_write_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32,
    SMB2.command_cb, ct.c_void_p)
smb2.smb2_write_async.restype = ct.c_int
smb2.smb2_write.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(ct.c_uint8), ct.c_uint32)
smb2.smb2_write.restype = ct.c_int
smb2.smb2_lseek.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.c_int64, ct.c_int, ct.POINTER(ct.c_uint64))
smb2.smb2_lseek.restype = ct.c_int64

smb2.smb2_unlink_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_unlink_async.restype = ct.c_int
smb2.smb2_unlink.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_unlink.restype = ct.c_int
smb2.smb2_rmdir_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_rmdir_async.restype = ct.c_int
smb2.smb2_rmdir.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_rmdir.restype = ct.c_int
smb2.smb2_mkdir_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_mkdir_async.restype = ct.c_int
smb2.smb2_mkdir.argtypes = (SMB2.context_ptr, ct.c_char_p)
smb2.smb2_mkdir.restype = ct.c_int
smb2.smb2_statvfs_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.POINTER(SMB2.statvfs), SMB2.command_cb, ct.c_void_p)
smb2.smb2_statvfs_async.restype = ct.c_int
smb2.smb2_statvfs.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.POINTER(SMB2.statvfs))
smb2.smb2_statvfs.restype = ct.c_int
smb2.smb2_fstat_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(SMB2.stat_64), SMB2.command_cb, ct.c_void_p)
smb2.smb2_fstat_async.restype = ct.c_int
smb2.smb2_fstat.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, ct.POINTER(SMB2.stat_64))
smb2.smb2_fstat.restype = ct.c_int
smb2.smb2_stat_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.POINTER(SMB2.stat_64), SMB2.command_cb, ct.c_void_p)
smb2.smb2_stat_async.restype = ct.c_int
smb2.smb2_stat.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.POINTER(SMB2.stat_64))
smb2.smb2_stat.restype = ct.c_int
smb2.smb2_rename_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_rename_async.restype = ct.c_int
smb2.smb2_rename.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.c_char_p)
smb2.smb2_rename.restype = ct.c_int
smb2.smb2_truncate_async.argtypes = \
    (SMB2.context_ptr, ct.c_char_p, ct.c_uint64, SMB2.command_cb, ct.c_void_p)
smb2.smb2_truncate_async.restype = ct.c_int
smb2.smb2_truncate.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.c_uint64)
smb2.smb2_truncate.restype = ct.c_int
smb2.smb2_ftruncate_async.argtypes = \
    (SMB2.context_ptr, SMB2.fh_ptr, ct.c_uint64, SMB2.command_cb, ct.c_void_p)
smb2.smb2_ftruncate_async.restype = ct.c_int
smb2.smb2_ftruncate.argtypes = (SMB2.context_ptr, SMB2.fh_ptr, ct.c_uint64)
smb2.smb2_ftruncate.restype = ct.c_int
smb2.smb2_readlink_async.argtypes = (SMB2.context_ptr, ct.c_char_p, SMB2.command_cb, ct.c_void_p)
smb2.smb2_readlink_async.restype = ct.c_int
smb2.smb2_readlink.argtypes = (SMB2.context_ptr, ct.c_char_p, ct.POINTER(ct.c_char), ct.c_uint32)
smb2.smb2_readlink.restype = ct.c_int
smb2.smb2_echo_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_echo_async.restype = ct.c_int
smb2.smb2_echo.argtypes = (SMB2.context_ptr,)
smb2.smb2_echo.restype = ct.c_int

smb2.smb2_share_enum_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_share_enum_async.restype = ct.c_int

# from smb2/libsmb2-raw.h:
compound_file_id = SMB2.file_id.in_dll(smb2, "compound_file_id")

smb2.smb2_free_data.argtypes = (SMB2.context_ptr, ct.c_void_p)
smb2.smb2_free_data.restype = None
smb2.smb2_cmd_negotiate_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.negotiate_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_negotiate_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_session_setup_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.session_setup_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_session_setup_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_tree_connect_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.tree_connect_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_tree_connect_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_tree_disconnect_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_tree_disconnect_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_create_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.create_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_create_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_close_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.close_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_close_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_read_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.read_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_read_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_write_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.write_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_write_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_query_directory_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.query_directory_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_query_directory_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_query_info_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.query_info_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_query_info_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_set_info_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.set_info_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_set_info_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_ioctl_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.ioctl_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_ioctl_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_echo_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_echo_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_logoff_async.argtypes = (SMB2.context_ptr, SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_logoff_async.restype = SMB2.pdu_ptr
smb2.smb2_cmd_flush_async.argtypes = \
    (SMB2.context_ptr, ct.POINTER(SMB2.flush_request), SMB2.command_cb, ct.c_void_p)
smb2.smb2_cmd_flush_async.restype = SMB2.pdu_ptr

#+
# Higher-level stuff begins here
#-

def nterror_to_str(n) :
    result = smb2.nterror_to_str(n)
    if result != None :
        result = result.decode()
    #end if
    return \
        result
#end nterror_to_str

def nterror_to_errno(n) :
    return \
        smb2.nterror_to_errno(n)
#end nterror_to_errno

# TODO: dcerpc stuff

class FileID :

    def __init__(self, id) :
        if not isinstance(id, (bytes, bytearray)) or len(id) != SMB2.FD_SIZE :
            raise TypeError("id must consist of %d bytes" % SMB2.FD_SIZE)
        #end if
        self.id = bytes(id)
    #end __init__

#end FileID

class FileHandle :
    "wrapper for an smb2_fh_ptr object. Do not instantiate directly; use the" \
    " from_file_id() or Context.open() methods."

    __slots__ = ("_smbobj", "_ctx", "__weakref__") # to forestall typos

    def __init__(self, _smbobj, _ctx) :
        self._smbobj = _smbobj
        self._ctx = _ctx
    #end __init__

    @property
    def file_id(self) :
        return \
            FileID(smb2.smb2_get_file_id(self._smbobj)[:SMB2.FD_SIZE])
    #end file_id

    @classmethod
    def from_file_id(celf, ctx, id) :
        if not isinstance(ctx, Context) :
            raise TypeError("ctx must be a Context")
        #end if
        if not isinstance(id, FileID) :
            raise TypeError("id must be a FileID")
        #end if
        return \
            celf(smb2.smb2_fh_from_file_id(ctx._smbobj, ct.byref(id.id)))
    #end from_file_id

#end FileHandle

class URL :
    "wrapper for an smb2_url object. Do not instantiate directly; get from" \
    " Context.parse_url()."

    __slots__ = ("_smbobj", "_ctx", "__weakref__") # to forestall typos

    def __init__(self, _smbobj) :
        self._smbobj = _smbobj
    #end __init__

    def __del__(self) :
        if self._smbobj != None :
            smb2.smb2_destroy_url(self._smbobj)
            self._smbobj = None
        #end if
    #end __del__

#end URL
def def_url_field(name) :

    def field(self) :
        result = getattr(self._smbobj[0], name)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end field

#begin def_url_field
    field.__name__ = name
    field.__doc__ = "the %s field from the URL" % name
    return \
        property(field)
#end def_url_field
for name in ("domain", "user", "server", "share", "path") :
    setattr(URL, name, def_url_field(name))
#end for
del name, def_url_field

class SMB2Error(Exception) :
    "just to identify a libsmb2-specific error exception."

    def __init__(self, msg) :
        self.args = ("libsmb2 error: %s" % msg,)
    #end __init__

#end SMB2Error

# TODO clarify if SMB2OSError.raise_if should be used everywhere instead of Context.raise_error.

class SMB2OSError(Exception) :

    def __init__(self, status, msg) :
        errno = - status
        self.args = ("libsmb2 OS error %d -- %s: %s" % (errno, os.strerror(errno), msg),)
    #end __init__

    @classmethod
    def raise_if(celf, status, msg) :
        if status != 0 :
            raise celf(status, msg)
        #end if
    #end raise_if

#end SMB2OSError

class Dir :
    "a wrapper for an smb2dir pointer. Do not instantiate directly;" \
    " get from Context.opendir."

    __slots__ = ("_smbobj", "__weakref__", "_parent") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _smbobj, _parent) :
        self = celf._instances.get(_smbobj)
        if self == None :
            self = super().__new__(celf)
            self._smbobj = _smbobj
            self._parent = _parent
            celf._instances[_smbobj] = self
        #end if
        return \
            self
    #end __new__

    def close(self) :
        if self._smbobj != None :
            smb2.smb2_closedir(self._parent._smbobj, self._smbobj)
            self._smbobj = None
        #end if
    #end close
    __del__ = close

    def read(self) :
        c_dirent = smb2.smb2_readdir(self._parent._smbobj, self._smbobj)
        if c_dirent != None and ct.cast(c_dirent, ct.c_void_p).value != None :
            dirent = {"name" : c_dirent[0].name.decode()}
            c_st = c_dirent[0].st
            dirent["st"] = dict((f[0], getattr(c_st, f[0])) for f in SMB2.stat_64._fields_)
        else :
            dirent = None
        #end if
        return \
            dirent
    #end read

    def rewind(self) :
        smb2.smb2_rewinddir(self._parent._smbobj, self._smbobj)
    #end rewind

    def tell(self) :
        return \
            smb2.smb2_telldir(self._parent._smbobj, self._smbobj)
    #end tell

    def seek(self, loc) :
        smb2.smb2_seekdir(self._parent._smbobj, self._smbobj, loc)
    #end seek

#end Dir

class Context :
    "a wrapper for an smb2_context_ptr object. Do not instantiate directly;" \
    " use the create method."

    __slots__ = ("_smbobj", "__weakref__", "loop", "_pending_cb") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _smbobj) :
        self = celf._instances.get(_smbobj)
        if self == None :
            self = super().__new__(celf)
            self._smbobj = _smbobj
            self.loop = None
            self._pending_cb = {}
            celf._instances[_smbobj] = self
        #end if
        return \
            self
    #end __new__

    @classmethod
    def create(celf) :
        c_result = smb2.smb2_init_context()
        if c_result == None :
            raise RuntimeError("failed to create context")
        #end if
        return \
            celf(c_result)
    #end create

    def __del__(self) :
        if self._smbobj != None :
            smb2.smb2_destroy_context(self._smbobj)
            self._smbobj = None
        #end if
    #end __del__

    @property
    def error(self) :
        "returns the message text for the last error on this context."
        result = smb2.smb2_get_error(self._smbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end error

    def raise_error(self, doing_what) :
        "raises an exception for the last error encountered on this context."
        raise \
            SMB2Error("%s -- %s" % (self.error, doing_what))
    #end raise_error

    @property
    def fd(self) :
        "file descriptor to watch for this connection."
        return \
            smb2.smb2_get_fd(self._smbobj)
    #end fd

    def fileno(self) :
        "standard Python name for method returning file descriptor to watch for this connection."
        return \
            smb2.smb2_get_fd(self._smbobj)
    #end fileno

    @property
    def which_events(self) :
        "mask of events to be passed to poll(2) to watch for on this connection."
        return \
            smb2.smb2_which_events(self._smbobj)
    #end which_events

    def service(self, revents) :
        "lets libsmb2 service the specified events as returned from a poll(2) call."
        result = smb2.smb2_service(self._smbobj, revents)
        if result < 0 :
            self.raise_error("servicing events")
        #end if
    #end service

    @staticmethod
    def _handle_poll(w_self, writing) :
        self = w_self()
        assert self != None, "parent Context has gone away"
        mask = (select.POLLIN, select.POLLOUT)[writing]
        self.service(mask)
    #end _handle_poll

    def _start_pending_cb(self, cb) :
        assert self.loop != None, "no event loop to attach coroutines to"
        if len(self._pending_cb) == 0 :
            # ignore self.which_events, always watch for both read and write events
            # Unfortunately asyncio doesn’t seem to notify me about
            # POLLHUP, POLLRDHUP, POLLERR, POLLNVAL or POLLPRI events
            w_self = weak_ref(self)
            self.loop.add_reader(self.fd, self._handle_poll, w_self, False)
            self.loop.add_writer(self.fd, self._handle_poll, w_self, True)
        #end if
        key = id(cb)
        self._pending_cb[key] = cb
        return \
            key
    #end _start_pending_cb

    def _done_cb(self, cb_id) :
        self._pending_cb.pop(cb_id, None)
        if len(self._pending_cb) == 0 :
            self.loop.remove_reader(self.fd)
            self.loop.remove_writer(self.fd)
        #end if
    #end _done_cb

    def set_security_mode(self, security_mode) :
        smb2.smb2_set_security_mode(self._smbobj, security_mode)
    #end set_security_mode

    def set_seal(self, val) :
        smb2.smb2_set_seal(self._smbobj, val)
    #end set_seal

    def set_authentication(self, val) :
        smb2.smb2_set_authentication(self._smbobj, val)
    #end set_authentication

    def set_user(self, user) :
        smb2.smb2_set_user(self._smbobj, user.encode())
    #end set_user

    def set_password(self, password) :
        smb2.smb2_set_password(self._smbobj, password.encode())
    #end set_user

    def set_domain(self, domain) :
        smb2.smb2_set_domain(self._smbobj, domain.encode())
    #end set_user

    def set_workstation(self, workstation) :
        smb2.smb2_set_workstation(self._smbobj, workstation.encode())
    #end set_workstation

    @property
    def client_guid(self) :
        return \
            smb2.smb2_get_client_guid(self._smbobj).decode()
    #end client_guid

    # TODO: connect_async

    def connect_share_async_cb(self, server, share, user, cb, cb_data) :

        w_self = weak_ref(self)
          # to avoid a reference cycle

        def c_cb(c_self, status, c_command_data, _) :
            self = w_self()
            assert self != None, "parent Context has gone away"
            self._done_cb(ref_cb_id)
            cb(self, status, None, cb_data)
        #end c_cb

    #begin connect_share_async_cb
        c_server = server.encode()
        c_share = share.encode()
        if user != None :
            c_user = user.encode()
        else :
            c_user = None
        #end if
        ref_cb = SMB2.command_cb(c_cb)
        SMB2OSError.raise_if \
          (
            smb2.smb2_connect_share_async(self._smbobj, c_server, c_share, c_user, ref_cb, None),
            "on connect_share_async"
          )
        ref_cb_id = self._start_pending_cb(ref_cb)
    #end connect_share_async_cb

    async def connect_share_async(self, server, share, user) :

        def connect_share_done(self, status, _1, _2) :
            awaiting = ref_awaiting()
            if awaiting != None :
                if status != 0 :
                    awaiting.set_exception(SMB2OSError(status, "on connect_share_async done"))
                else :
                    awaiting.set_result(None)
                #end if
            #end if
        #end connect_share_done

    #begin connect_share_async
        assert self.loop != None, "no event loop to attach coroutines to"
        awaiting = self.loop.create_future()
        ref_awaiting = weak_ref(awaiting)
          # weak ref to avoid circular refs with loop
        self.connect_share_async_cb(server, share, user, connect_share_done, None)
        await awaiting
    #end connect_share_async

    def connect_share(self, server, share, user = None) :
        c_server = server.encode()
        c_share = share.encode()
        if user != None :
            c_user = user.encode()
        else :
            c_user = None
        #end if
        if smb2.smb2_connect_share(self._smbobj, c_server, c_share, c_user) != 0 :
            self.raise_error("on connect_share")
        #end if
    #end connect_share

    def disconnect_share_async_cb(self, cb, cb_data) :

        w_self = weak_ref(self)
          # to avoid a reference cycle

        def c_cb(c_self, status, c_command_data, _) :
            self = w_self()
            assert self != None, "parent Context has gone away"
            self._done_cb(ref_cb_id)
            cb(self, status, None, cb_data)
        #end c_cb

    #begin disconnect_share_async_cb
        ref_cb = SMB2.command_cb(c_cb)
        ref_cb_id = self._start_pending_cb(ref_cb)
        SMB2OSError.raise_if \
          (
            smb2.smb2_disconnect_share_async(self._smbobj, ref_cb, None),
            "on disconnect_share_async"
          )
    #end disconnect_share_async_cb

    async def disconnect_share_async(self) :

        def discconnect_share_done(self, status, _1, _2) :
            awaiting = ref_awaiting()
            if awaiting != None :
                if status != 0 :
                    awaiting.set_exception(SMB2OSError(status, "on disconnect_share_async done"))
                else :
                    awaiting.set_result(None)
                #end if
            #end if
        #end discconnect_share_done

    #begin disconnect_share_async
        assert self.loop != None, "no event loop to attach coroutines to"
        awaiting = self.loop.create_future()
        ref_awaiting = weak_ref(awaiting)
          # weak ref to avoid circular refs with loop
        self.discconnect_share_async_cb(server, disconnect_share_done, None)
        await awaiting
    #end disconnect_share_async

    def disconnect_share(self) :
        smb2.smb2_disconnect_share(self._smbobj) # ignore status?
    #end disconnect_share

    def opendir_async_cb(self, path, cb, cb_data) :

        w_self = weak_ref(self)
          # to avoid a reference cycle

        def c_cb(c_self, status, c_command_data, _) :
            self = w_self()
            assert self != None, "parent Context has gone away"
            self._done_cb(ref_cb_id)
            if status == 0 :
                dir = Dir(c_command_data, self)
            else :
                dir = None
            #end if
            cb(self, status, dir, cb_data)
        #end c_cb

    #begin opendir_async_cb
        c_path = path.encode()
        ref_cb = SMB2.command_cb(c_cb)
        ref_cb_id = self._start_pending_cb(ref_cb)
        SMB2OSError.raise_if \
          (
            smb2.smb2_opendir_async(self._smbobj, c_path, ref_cb, None),
            "on opendir_async"
          )
    #end opendir_async_cb

    async def opendir_async(self, path) :

        def opendir_done(self, status, dir, _) :
            awaiting = ref_awaiting()
            if awaiting != None :
                if status != 0 :
                    awaiting.set_exception(SMB2OSError(status, "on opendir_async done"))
                else :
                    awaiting.set_result(dir)
                #end if
            #end if
        #end opendir_done

    #begin opendir_async
        assert self.loop != None, "no event loop to attach coroutines to"
        awaiting = self.loop.create_future()
        ref_awaiting = weak_ref(awaiting)
          # weak ref to avoid circular refs with loop
        self.opendir_async_cb(path, opendir_done, None)
        return \
            await awaiting
    #end opendir_async

    def opendir(self, path) :
        c_path = path.encode()
        c_result = smb2.smb2_opendir(self._smbobj, c_path)
        if c_result == None :
            self.raise_error("on opendir")
        #end if
        return \
            Dir(self, c_result)
    #end opendir

    def share_enum_async_cb(self, cb, cb_data) :

        w_self = weak_ref(self)
          # to avoid a reference cycle

        def c_cb(c_self, status, c_command_data, _) :
            self = w_self()
            assert self != None, "parent Context has gone away"
            self._done_cb(ref_cb_id)
            info = {}
            connect_data = ct.cast(c_command_data, ct.POINTER(SMB2.srvsvc_netshareenumall_rep))[0]
            info["level"] = connect_data.level
            info["total_entries"] = connect_data.total_entries
            info["resume_handle"] = connect_data.resume_handle
            info["status"] = connect_data.status
            c_ctr = connect_data.ctr[0]
            c_array = c_ctr.ctr1.array
            ctr = {"level" : c_ctr.level, "count" : c_ctr.ctr1.count}
            array = []
            for i in range(c_ctr.ctr1.count) :
                c_elt = c_array[i]
                elt = \
                    {
                        "name" : c_elt.name.decode(),
                        "type" : c_elt.type,
                        "comment" : c_elt.comment.decode(),
                    }
                array.append(elt)
            #end for
            ctr["array"] = array
            info["ctr"] = ctr
            cb(self, status, info, cb_data)
        #end c_cb

    #begin share_enum_async_cb
        ref_cb = SMB2.command_cb(c_cb)
        ref_cb_id = self._start_pending_cb(ref_cb)
        if smb2.smb2_share_enum_async(self._smbobj, ref_cb, None) != 0 :
            self.raise_error("on share_enum_async")
        #end if
    #end share_enum_async_cb

    async def share_enum_async(self) :

        def share_enum_done(self, status, info, _) :
            awaiting = ref_awaiting()
            if awaiting != None :
                awaiting.set_result((status, info))
            #end if
        #end share_enum_done

    #begin share_enum_async
        assert self.loop != None, "no event loop to attach coroutines to"
        awaiting = self.loop.create_future()
        ref_awaiting = weak_ref(awaiting)
          # weak ref to avoid circular refs with loop
        self.share_enum_async_cb(share_enum_done, None)
        return \
            await awaiting
    #end share_enum_async

    def parse_url(self, urlstr) :
        result = smb2.smb2_parse_url(self._smbobj, urlstr.encode())
        if result == None or ct.cast(result, ct.c_void_p).value == None :
            self.raise_error("parsing url")
        #end if
        return \
            URL(result)
    #end parse_url

    def attach_asyncio(self, loop = None) :
        "attaches this Context object to an asyncio event loop. If none is" \
        " specified, the default event loop (as returned from asyncio.get_event_loop()" \
        " is used."
        assert self.loop == None, "already attached to an event loop"
        if loop == None :
            loop = asyncio.get_event_loop()
        #end if
        self.loop = loop
    #end attach_asyncio

#end Context

# more TBD

#+
# Overall
#-

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for cłass in URL, Dir, Context :
        delattr(cłass, "__del__")
    #end for
#end _atexit
atexit.register(_atexit)
del _atexit
