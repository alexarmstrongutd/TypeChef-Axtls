' The VB.NET to C interface definition file for the axTLS project
' Do not modify - this file is generated

Imports System
Imports System.Runtime.InteropServices

Namespace axTLSvb
    Public Class axtls
        Public Const SSL_SESSION_ID_SIZE As Integer = 32
        Public Const SSL_CLIENT_AUTHENTICATION As Integer = &H00010000
        Public Const SSL_SERVER_VERIFY_LATER As Integer = &H00020000
        Public Const SSL_NO_DEFAULT_KEY As Integer = &H00040000
        Public Const SSL_DISPLAY_STATES As Integer = &H00080000
        Public Const SSL_DISPLAY_BYTES As Integer = &H00100000
        Public Const SSL_DISPLAY_CERTS As Integer = &H00200000
        Public Const SSL_DISPLAY_RSA As Integer = &H00400000
        Public Const SSL_CONNECT_IN_PARTS As Integer = &H00800000
        Public Const SSL_OK As Integer = 0
        Public Const SSL_NOT_OK As Integer = -1
        Public Const SSL_ERROR_DEAD As Integer = -2
        Public Const SSL_CLOSE_NOTIFY As Integer = -3
        Public Const SSL_ERROR_CONN_LOST As Integer = -256
        Public Const SSL_ERROR_RECORD_OVERFLOW As Integer = -257
        Public Const SSL_ERROR_SOCK_SETUP_FAILURE As Integer = -258
        Public Const SSL_ERROR_INVALID_HANDSHAKE As Integer = -260
        Public Const SSL_ERROR_INVALID_PROT_MSG As Integer = -261
        Public Const SSL_ERROR_INVALID_HMAC As Integer = -262
        Public Const SSL_ERROR_INVALID_VERSION As Integer = -263
        Public Const SSL_ERROR_UNSUPPORTED_EXTENSION As Integer = -264
        Public Const SSL_ERROR_INVALID_SESSION As Integer = -265
        Public Const SSL_ERROR_NO_CIPHER As Integer = -266
        Public Const SSL_ERROR_INVALID_CERT_HASH_ALG As Integer = -267
        Public Const SSL_ERROR_BAD_CERTIFICATE As Integer = -268
        Public Const SSL_ERROR_INVALID_KEY As Integer = -269
        Public Const SSL_ERROR_FINISHED_INVALID As Integer = -271
        Public Const SSL_ERROR_NO_CERT_DEFINED As Integer = -272
        Public Const SSL_ERROR_NO_CLIENT_RENOG As Integer = -273
        Public Const SSL_ERROR_NOT_SUPPORTED As Integer = -274
        Public Const SSL_X509_OFFSET As Integer = -512
        Public Const SSL_ALERT_TYPE_WARNING As Integer = 1
        Public Const SLL_ALERT_TYPE_FATAL As Integer = 2
        Public Const SSL_ALERT_CLOSE_NOTIFY As Integer = 0
        Public Const SSL_ALERT_UNEXPECTED_MESSAGE As Integer = 10
        Public Const SSL_ALERT_BAD_RECORD_MAC As Integer = 20
        Public Const SSL_ALERT_RECORD_OVERFLOW As Integer = 22
        Public Const SSL_ALERT_HANDSHAKE_FAILURE As Integer = 40
        Public Const SSL_ALERT_BAD_CERTIFICATE As Integer = 42
        Public Const SSL_ALERT_UNSUPPORTED_CERTIFICATE As Integer = 43
        Public Const SSL_ALERT_CERTIFICATE_EXPIRED As Integer = 45
        Public Const SSL_ALERT_CERTIFICATE_UNKNOWN As Integer = 46
        Public Const SSL_ALERT_ILLEGAL_PARAMETER As Integer = 47
        Public Const SSL_ALERT_UNKNOWN_CA As Integer = 48
        Public Const SSL_ALERT_DECODE_ERROR As Integer = 50
        Public Const SSL_ALERT_DECRYPT_ERROR As Integer = 51
        Public Const SSL_ALERT_INVALID_VERSION As Integer = 70
        Public Const SSL_ALERT_NO_RENEGOTIATION As Integer = 100
        Public Const SSL_ALERT_UNSUPPORTED_EXTENSION As Integer = 110
        Public Const SSL_AES128_SHA As Integer = &H2f
        Public Const SSL_AES256_SHA As Integer = &H35
        Public Const SSL_AES128_SHA256 As Integer = &H3c
        Public Const SSL_AES256_SHA256 As Integer = &H3d
        Public Const SSL_BUILD_SKELETON_MODE As Integer = &H01
        Public Const SSL_BUILD_SERVER_ONLY As Integer = &H02
        Public Const SSL_BUILD_ENABLE_VERIFICATION As Integer = &H03
        Public Const SSL_BUILD_ENABLE_CLIENT As Integer = &H04
        Public Const SSL_BUILD_FULL_MODE As Integer = &H05
        Public Const SSL_BUILD_MODE As Integer = 0
        Public Const SSL_MAX_CERT_CFG_OFFSET As Integer = 1
        Public Const SSL_MAX_CA_CERT_CFG_OFFSET As Integer = 2
        Public Const SSL_HAS_PEM As Integer = 3
        Public Const SSL_DEFAULT_SVR_SESS As Integer = 5
        Public Const SSL_DEFAULT_CLNT_SESS As Integer = 1
        Public Const SSL_X509_CERT_COMMON_NAME As Integer = 0
        Public Const SSL_X509_CERT_ORGANIZATION As Integer = 1
        Public Const SSL_X509_CERT_ORGANIZATIONAL_NAME As Integer = 2
        Public Const SSL_X509_CERT_LOCATION As Integer = 3
        Public Const SSL_X509_CERT_COUNTRY As Integer = 4
        Public Const SSL_X509_CERT_STATE As Integer = 5
        Public Const SSL_X509_CA_CERT_COMMON_NAME As Integer = 6
        Public Const SSL_X509_CA_CERT_ORGANIZATION As Integer = 7
        Public Const SSL_X509_CA_CERT_ORGANIZATIONAL_NAME As Integer = 8
        Public Const SSL_X509_CA_CERT_LOCATION As Integer = 9
        Public Const SSL_X509_CA_CERT_COUNTRY As Integer = 10
        Public Const SSL_X509_CA_CERT_STATE As Integer = 11
        Public Const SSL_OBJ_X509_CERT As Integer = 1
        Public Const SSL_OBJ_X509_CACERT As Integer = 2
        Public Const SSL_OBJ_RSA_KEY As Integer = 3
        Public Const SSL_OBJ_PKCS8 As Integer = 4
        Public Const SSL_OBJ_PKCS12 As Integer = 5
        <DllImport("axtls")> Public Shared Function _
            ssl_ctx_new(ByVal options As Integer, ByVal num_sessions As Integer) As IntPtr
        End Function

        <DllImport("axtls")> Public Shared Sub _
            ssl_ctx_free(ByVal ssl_ctx As IntPtr) 
        End Sub

        <DllImport("axtls")> Public Shared Function _
            ssl_ext_new() SSL_EXTENSIONS *
        End Function

        <DllImport("axtls")> Public Shared Sub _
            ssl_ext_free(SSL_EXTENSIONS *ssl_ext) 
        End Sub

        <DllImport("axtls")> Public Shared Function _
            ssl_server_new(ByVal ssl_ctx As IntPtr, ByVal client_fd As Integer) As IntPtr
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_client_new(ByVal ssl_ctx As IntPtr, ByVal client_fd As Integer, ByVal session_id() As Byte, ByVal sess_id_size As Byte, SSL_EXTENSIONS* ssl_ext) As IntPtr
        End Function

        <DllImport("axtls")> Public Shared Sub _
            ssl_free(ByVal ssl As IntPtr) 
        End Sub

        <DllImport("axtls")> Public Shared Function _
            ssl_read(ByVal ssl As IntPtr, ByRef in_data As IntPtr) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_write(ByVal ssl As IntPtr, ByVal out_data() As Byte, ByVal out_len As Integer) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_find(ByVal ssl_ctx As IntPtr, ByVal client_fd As Integer) As IntPtr
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_session_id(ByVal ssl As IntPtr) As IntPtr
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_session_id_size(ByVal ssl As IntPtr) As Byte
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_cipher_id(ByVal ssl As IntPtr) As Byte
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_handshake_status(ByVal ssl As IntPtr) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_config(ByVal offset As Integer) As Integer
        End Function

        <DllImport("axtls")> Public Shared Sub _
            ssl_display_error(ByVal error_code As Integer) 
        End Sub

        <DllImport("axtls")> Public Shared Function _
            ssl_verify_cert(ByVal ssl As IntPtr) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_cert_dn(ByVal ssl As IntPtr, ByVal component As Integer) As String
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_get_cert_subject_alt_dnsname(ByVal ssl As IntPtr, ByVal dnsindex As Integer) As String
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_renegotiate(ByVal ssl As IntPtr) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_obj_load(ByVal ssl_ctx As IntPtr, ByVal obj_type As Integer, ByVal filename As String, ByVal password As String) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_obj_memory_load(ByVal ssl_ctx As IntPtr, ByVal obj_type As Integer, ByVal data() As Byte, ByVal len As Integer, ByVal password As String) As Integer
        End Function

        <DllImport("axtls")> Public Shared Function _
            ssl_version() As String
        End Function

    End Class
End Namespace
