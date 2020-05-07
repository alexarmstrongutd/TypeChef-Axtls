// The C# to C interface definition file for the axTLS project
// Do not modify - this file is generated

using System;
using System.Runtime.InteropServices;

namespace axTLS
{
    public class axtls
    {
        public const int SSL_SESSION_ID_SIZE = 32;
        public const int SSL_CLIENT_AUTHENTICATION = 0x00010000;
        public const int SSL_SERVER_VERIFY_LATER = 0x00020000;
        public const int SSL_NO_DEFAULT_KEY = 0x00040000;
        public const int SSL_DISPLAY_STATES = 0x00080000;
        public const int SSL_DISPLAY_BYTES = 0x00100000;
        public const int SSL_DISPLAY_CERTS = 0x00200000;
        public const int SSL_DISPLAY_RSA = 0x00400000;
        public const int SSL_CONNECT_IN_PARTS = 0x00800000;
        public const int SSL_OK = 0;
        public const int SSL_NOT_OK = -1;
        public const int SSL_ERROR_DEAD = -2;
        public const int SSL_CLOSE_NOTIFY = -3;
        public const int SSL_ERROR_CONN_LOST = -256;
        public const int SSL_ERROR_RECORD_OVERFLOW = -257;
        public const int SSL_ERROR_SOCK_SETUP_FAILURE = -258;
        public const int SSL_ERROR_INVALID_HANDSHAKE = -260;
        public const int SSL_ERROR_INVALID_PROT_MSG = -261;
        public const int SSL_ERROR_INVALID_HMAC = -262;
        public const int SSL_ERROR_INVALID_VERSION = -263;
        public const int SSL_ERROR_UNSUPPORTED_EXTENSION = -264;
        public const int SSL_ERROR_INVALID_SESSION = -265;
        public const int SSL_ERROR_NO_CIPHER = -266;
        public const int SSL_ERROR_INVALID_CERT_HASH_ALG = -267;
        public const int SSL_ERROR_BAD_CERTIFICATE = -268;
        public const int SSL_ERROR_INVALID_KEY = -269;
        public const int SSL_ERROR_FINISHED_INVALID = -271;
        public const int SSL_ERROR_NO_CERT_DEFINED = -272;
        public const int SSL_ERROR_NO_CLIENT_RENOG = -273;
        public const int SSL_ERROR_NOT_SUPPORTED = -274;
        public const int SSL_X509_OFFSET = -512;
        public const int SSL_ALERT_TYPE_WARNING = 1;
        public const int SLL_ALERT_TYPE_FATAL = 2;
        public const int SSL_ALERT_CLOSE_NOTIFY = 0;
        public const int SSL_ALERT_UNEXPECTED_MESSAGE = 10;
        public const int SSL_ALERT_BAD_RECORD_MAC = 20;
        public const int SSL_ALERT_RECORD_OVERFLOW = 22;
        public const int SSL_ALERT_HANDSHAKE_FAILURE = 40;
        public const int SSL_ALERT_BAD_CERTIFICATE = 42;
        public const int SSL_ALERT_UNSUPPORTED_CERTIFICATE = 43;
        public const int SSL_ALERT_CERTIFICATE_EXPIRED = 45;
        public const int SSL_ALERT_CERTIFICATE_UNKNOWN = 46;
        public const int SSL_ALERT_ILLEGAL_PARAMETER = 47;
        public const int SSL_ALERT_UNKNOWN_CA = 48;
        public const int SSL_ALERT_DECODE_ERROR = 50;
        public const int SSL_ALERT_DECRYPT_ERROR = 51;
        public const int SSL_ALERT_INVALID_VERSION = 70;
        public const int SSL_ALERT_NO_RENEGOTIATION = 100;
        public const int SSL_ALERT_UNSUPPORTED_EXTENSION = 110;
        public const int SSL_AES128_SHA = 0x2f;
        public const int SSL_AES256_SHA = 0x35;
        public const int SSL_AES128_SHA256 = 0x3c;
        public const int SSL_AES256_SHA256 = 0x3d;
        public const int SSL_BUILD_SKELETON_MODE = 0x01;
        public const int SSL_BUILD_SERVER_ONLY = 0x02;
        public const int SSL_BUILD_ENABLE_VERIFICATION = 0x03;
        public const int SSL_BUILD_ENABLE_CLIENT = 0x04;
        public const int SSL_BUILD_FULL_MODE = 0x05;
        public const int SSL_BUILD_MODE = 0;
        public const int SSL_MAX_CERT_CFG_OFFSET = 1;
        public const int SSL_MAX_CA_CERT_CFG_OFFSET = 2;
        public const int SSL_HAS_PEM = 3;
        public const int SSL_DEFAULT_SVR_SESS = 5;
        public const int SSL_DEFAULT_CLNT_SESS = 1;
        public const int SSL_X509_CERT_COMMON_NAME = 0;
        public const int SSL_X509_CERT_ORGANIZATION = 1;
        public const int SSL_X509_CERT_ORGANIZATIONAL_NAME = 2;
        public const int SSL_X509_CERT_LOCATION = 3;
        public const int SSL_X509_CERT_COUNTRY = 4;
        public const int SSL_X509_CERT_STATE = 5;
        public const int SSL_X509_CA_CERT_COMMON_NAME = 6;
        public const int SSL_X509_CA_CERT_ORGANIZATION = 7;
        public const int SSL_X509_CA_CERT_ORGANIZATIONAL_NAME = 8;
        public const int SSL_X509_CA_CERT_LOCATION = 9;
        public const int SSL_X509_CA_CERT_COUNTRY = 10;
        public const int SSL_X509_CA_CERT_STATE = 11;
        public const int SSL_OBJ_X509_CERT = 1;
        public const int SSL_OBJ_X509_CACERT = 2;
        public const int SSL_OBJ_RSA_KEY = 3;
        public const int SSL_OBJ_PKCS8 = 4;
        public const int SSL_OBJ_PKCS12 = 5;
        [DllImport ("axtls")]
        public static extern IntPtr ssl_ctx_new(uint options, int num_sessions);
        [DllImport ("axtls")]
        public static extern void ssl_ctx_free(IntPtr ssl_ctx);
        [DllImport ("axtls")]
        public static extern SSL_EXTENSIONS * ssl_ext_new();
        [DllImport ("axtls")]
        public static extern void ssl_ext_free(SSL_EXTENSIONS *ssl_ext);
        [DllImport ("axtls")]
        public static extern IntPtr ssl_server_new(IntPtr ssl_ctx, int client_fd);
        [DllImport ("axtls")]
        public static extern IntPtr ssl_client_new(IntPtr ssl_ctx, int client_fd, byte[] session_id, byte sess_id_size, SSL_EXTENSIONS* ssl_ext);
        [DllImport ("axtls")]
        public static extern void ssl_free(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern int ssl_read(IntPtr ssl, ref IntPtr in_data);
        [DllImport ("axtls")]
        public static extern int ssl_write(IntPtr ssl, byte[] out_data, int out_len);
        [DllImport ("axtls")]
        public static extern IntPtr ssl_find(IntPtr ssl_ctx, int client_fd);
        [DllImport ("axtls")]
        public static extern IntPtr ssl_get_session_id(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern byte ssl_get_session_id_size(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern byte ssl_get_cipher_id(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern int ssl_handshake_status(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern int ssl_get_config(int offset);
        [DllImport ("axtls")]
        public static extern void ssl_display_error(int error_code);
        [DllImport ("axtls")]
        public static extern int ssl_verify_cert(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern string ssl_get_cert_dn(IntPtr ssl, int component);
        [DllImport ("axtls")]
        public static extern string ssl_get_cert_subject_alt_dnsname(IntPtr ssl, int dnsindex);
        [DllImport ("axtls")]
        public static extern int ssl_renegotiate(IntPtr ssl);
        [DllImport ("axtls")]
        public static extern int ssl_obj_load(IntPtr ssl_ctx, int obj_type, string filename, string password);
        [DllImport ("axtls")]
        public static extern int ssl_obj_memory_load(IntPtr ssl_ctx, int obj_type, byte[] data, int len, string password);
        [DllImport ("axtls")]
        public static extern string ssl_version();
    };
};
