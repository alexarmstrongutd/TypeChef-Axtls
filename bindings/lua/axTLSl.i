%module axtlsl


/* include our own header */
%inline %{
#include "ssl.h"
%}

%include "typemaps.i"
/* Some SWIG magic to make the API a bit more Java friendly */
#ifdef SWIGJAVA

%apply long { SSL * };
%apply long { SSL_CTX * };
%apply long { SSLObjLoader * };

/* allow "unsigned char []" to become "byte[]" */
%include "arrays_java.i"

/* convert these pointers to use long */
%apply signed char[] {unsigned char *};
%apply signed char[] {signed char *};

/* allow ssl_get_session_id() to return "byte[]" */
%typemap(out) unsigned char * ssl_get_session_id "if (result) jresult = SWIG_JavaArrayOutSchar(jenv, result, ssl_get_session_id_size((SSL const *)arg1));"

/* allow ssl_client_new() to have a null session_id input */
%typemap(in) const signed char session_id[] (jbyte *jarr) {
    if (jarg3 == NULL)
    {
        jresult = (jint)ssl_client_new(arg1,arg2,NULL,0);
        return jresult;
    }
    
    if (!SWIG_JavaArrayInSchar(jenv, &jarr, &arg3, jarg3)) return 0;
}   

/* Lot's of work required for an ssl_read() due to its various custom
 * requirements.
 */
%native (ssl_read) int ssl_read(SSL *ssl, jobject in_data);
%{
JNIEXPORT jint JNICALL Java_axTLSj_axtlsjJNI_ssl_1read(JNIEnv *jenv, jclass jcls, jint jarg1, jobject jarg2) {
    jint jresult = 0 ;
    SSL *arg1;
    unsigned char *arg2;
    jbyte *jarr;
    int result;
    JNIEnv e = *jenv;
    jclass holder_class;
    jfieldID fid;

    arg1 = (SSL *)jarg1;
    result = (int)ssl_read(arg1, &arg2);

    /* find the "m_buf" entry in the SSLReadHolder class */
    if (!(holder_class = e->GetObjectClass(jenv,jarg2)) ||
            !(fid = e->GetFieldID(jenv,holder_class, "m_buf", "[B")))
        return SSL_NOT_OK;

    if (result > SSL_OK)
    {
        int i;

        /* create a new byte array to hold the read data */
        jbyteArray jarray = e->NewByteArray(jenv, result);

        /* copy the bytes across to the java byte array */
        jarr = e->GetByteArrayElements(jenv, jarray, 0);
        for (i = 0; i < result; i++)
            jarr[i] = (jbyte)arg2[i];

        /* clean up and set the new m_buf object */
        e->ReleaseByteArrayElements(jenv, jarray, jarr, 0);
        e->SetObjectField(jenv, jarg2, fid, jarray);
    }
    else    /* set to null */
        e->SetObjectField(jenv, jarg2, fid, NULL);

    jresult = (jint)result;
    return jresult;
}
%}

/* Big hack to get hold of a socket's file descriptor */
%typemap (jtype) long "Object"
%typemap (jstype) long "Object"
%native (getFd) int getFd(long sock);
%{
JNIEXPORT jint JNICALL Java_axTLSj_axtlsjJNI_getFd(JNIEnv *env, jclass jcls, jobject sock)
{
    JNIEnv e = *env;
    jfieldID fid;
    jobject impl;
    jobject fdesc;

    /* get the SocketImpl from the Socket */
    if (!(jcls = e->GetObjectClass(env,sock)) ||
            !(fid = e->GetFieldID(env,jcls,"impl","Ljava/net/SocketImpl;")) ||
            !(impl = e->GetObjectField(env,sock,fid))) return -1;

    /* get the FileDescriptor from the SocketImpl */
    if (!(jcls = e->GetObjectClass(env,impl)) ||
            !(fid = e->GetFieldID(env,jcls,"fd","Ljava/io/FileDescriptor;")) ||
            !(fdesc = e->GetObjectField(env,impl,fid))) return -1;

    /* get the fd from the FileDescriptor */
    if (!(jcls = e->GetObjectClass(env,fdesc)) ||
            !(fid = e->GetFieldID(env,jcls,"fd","I"))) return -1;

    /* return the descriptor */
    return e->GetIntField(env,fdesc,fid);
} 
%}

#endif

/* Some SWIG magic to make the API a bit more Perl friendly */
#ifdef SWIGPERL

/* for ssl_session_id() */
%typemap(out) const unsigned char * {
    SV *svs = newSVpv((unsigned char *)$1, ssl_get_session_id_size((SSL const *)arg1));
    $result = newRV(svs);
    sv_2mortal($result);
    argvi++;
}

/* for ssl_write() */
%typemap(in) const unsigned char out_data[] {
    SV* tempsv;
    if (!SvROK($input))
        croak("Argument $argnum is not a reference.");
    tempsv = SvRV($input);
    if (SvTYPE(tempsv) != SVt_PV)
        croak("Argument $argnum is not an string.");
    $1 = (unsigned char *)SvPV(tempsv, PL_na);
}

/* for ssl_read() */
%typemap(in) unsigned char **in_data (unsigned char *buf) {
    $1 = &buf;
}

%typemap(argout) unsigned char **in_data { 
    if (result > SSL_OK) {
        SV *svs = newSVpv(*$1, result);
        $result = newRV(svs);
        sv_2mortal($result);
        argvi++;
    }
}

/* for ssl_client_new() */
%typemap(in) const unsigned char session_id[] {
    /* check for a reference */
    if (SvOK($input) && SvROK($input)) {
        SV* tempsv = SvRV($input);
        if (SvTYPE(tempsv) != SVt_PV)
            croak("Argument $argnum is not an string.");
        $1 = (unsigned char *)SvPV(tempsv, PL_na); 
    } 
    else
        $1 = NULL;
}

#endif

/* Some SWIG magic to make the API a bit more Lua friendly */
#ifdef SWIGLUA
SWIG_NUMBER_TYPEMAP(unsigned char);
SWIG_TYPEMAP_NUM_ARR(uchar,unsigned char);

/* for ssl_session_id() */
%typemap(out) const unsigned char * {
    int i;
    lua_newtable(L);
    for (i = 0; i < ssl_get_session_id_size((SSL const *)arg1); i++){
        lua_pushnumber(L,(lua_Number)result[i]);
        lua_rawseti(L,-2,i+1); /* -1 is the number, -2 is the table */
    }
    SWIG_arg++;
}

/* for ssl_read() */
%typemap(in) unsigned char **in_data (unsigned char *buf) {
    $1 = &buf;
}

%typemap(argout) unsigned char **in_data { 
    if (result > SSL_OK) {
		int i;
		lua_newtable(L);
		for (i = 0; i < result; i++){
			lua_pushnumber(L,(lua_Number)buf2[i]);
			lua_rawseti(L,-2,i+1); /* -1 is the number, -2 is the table */
		}
        SWIG_arg++;
    }
}

/* for ssl_client_new() */
%typemap(in) const unsigned char session_id[] {
    if (lua_isnil(L,$input))
        $1 = NULL;
    else
        $1 = SWIG_get_uchar_num_array_fixed(L,$input, ssl_get_session_id((SSL const *)$1));
}

#endif

#define HEADER_SSL_H
#define SSL_SESSION_ID_SIZE                     32
#define SSL_CLIENT_AUTHENTICATION               0x00010000
#define SSL_SERVER_VERIFY_LATER                 0x00020000
#define SSL_NO_DEFAULT_KEY                      0x00040000
#define SSL_DISPLAY_STATES                      0x00080000
#define SSL_DISPLAY_BYTES                       0x00100000
#define SSL_DISPLAY_CERTS                       0x00200000
#define SSL_DISPLAY_RSA                         0x00400000
#define SSL_CONNECT_IN_PARTS                    0x00800000
#define SSL_OK                                  0
#define SSL_NOT_OK                              -1
#define SSL_ERROR_DEAD                          -2
#define SSL_CLOSE_NOTIFY                        -3
#define SSL_ERROR_CONN_LOST                     -256
#define SSL_ERROR_RECORD_OVERFLOW               -257
#define SSL_ERROR_SOCK_SETUP_FAILURE            -258
#define SSL_ERROR_INVALID_HANDSHAKE             -260
#define SSL_ERROR_INVALID_PROT_MSG              -261
#define SSL_ERROR_INVALID_HMAC                  -262
#define SSL_ERROR_INVALID_VERSION               -263
#define SSL_ERROR_UNSUPPORTED_EXTENSION         -264
#define SSL_ERROR_INVALID_SESSION               -265
#define SSL_ERROR_NO_CIPHER                     -266
#define SSL_ERROR_INVALID_CERT_HASH_ALG         -267
#define SSL_ERROR_BAD_CERTIFICATE               -268
#define SSL_ERROR_INVALID_KEY                   -269
#define SSL_ERROR_FINISHED_INVALID              -271
#define SSL_ERROR_NO_CERT_DEFINED               -272
#define SSL_ERROR_NO_CLIENT_RENOG               -273
#define SSL_ERROR_NOT_SUPPORTED                 -274
#define SSL_X509_OFFSET                         -512
#define SSL_X509_ERROR(A)                       (SSL_X509_OFFSET+A)
#define SSL_ALERT_TYPE_WARNING                  1
#define SLL_ALERT_TYPE_FATAL                    2
#define SSL_ALERT_CLOSE_NOTIFY                  0
#define SSL_ALERT_UNEXPECTED_MESSAGE            10
#define SSL_ALERT_BAD_RECORD_MAC                20
#define SSL_ALERT_RECORD_OVERFLOW               22
#define SSL_ALERT_HANDSHAKE_FAILURE             40
#define SSL_ALERT_BAD_CERTIFICATE               42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE       43
#define SSL_ALERT_CERTIFICATE_EXPIRED           45
#define SSL_ALERT_CERTIFICATE_UNKNOWN           46
#define SSL_ALERT_ILLEGAL_PARAMETER             47
#define SSL_ALERT_UNKNOWN_CA                    48
#define SSL_ALERT_DECODE_ERROR                  50
#define SSL_ALERT_DECRYPT_ERROR                 51
#define SSL_ALERT_INVALID_VERSION               70
#define SSL_ALERT_NO_RENEGOTIATION              100
#define SSL_ALERT_UNSUPPORTED_EXTENSION         110
#define SSL_AES128_SHA                          0x2f
#define SSL_AES256_SHA                          0x35
#define SSL_AES128_SHA256                       0x3c
#define SSL_AES256_SHA256                       0x3d
#define SSL_BUILD_SKELETON_MODE                 0x01
#define SSL_BUILD_SERVER_ONLY                   0x02
#define SSL_BUILD_ENABLE_VERIFICATION           0x03
#define SSL_BUILD_ENABLE_CLIENT                 0x04
#define SSL_BUILD_FULL_MODE                     0x05
#define SSL_BUILD_MODE                          0
#define SSL_MAX_CERT_CFG_OFFSET                 1
#define SSL_MAX_CA_CERT_CFG_OFFSET              2
#define SSL_HAS_PEM                             3
#define SSL_DEFAULT_SVR_SESS                    5
#define SSL_DEFAULT_CLNT_SESS                   1
#define SSL_X509_CERT_COMMON_NAME               0
#define SSL_X509_CERT_ORGANIZATION              1
#define SSL_X509_CERT_ORGANIZATIONAL_NAME       2
#define SSL_X509_CERT_LOCATION                  3
#define SSL_X509_CERT_COUNTRY                   4
#define SSL_X509_CERT_STATE                     5
#define SSL_X509_CA_CERT_COMMON_NAME            6
#define SSL_X509_CA_CERT_ORGANIZATION           7
#define SSL_X509_CA_CERT_ORGANIZATIONAL_NAME    8
#define SSL_X509_CA_CERT_LOCATION               9
#define SSL_X509_CA_CERT_COUNTRY                10
#define SSL_X509_CA_CERT_STATE                  11
#define SSL_OBJ_X509_CERT                       1
#define SSL_OBJ_X509_CACERT                     2
#define SSL_OBJ_RSA_KEY                         3
#define SSL_OBJ_PKCS8                           4
#define SSL_OBJ_PKCS12                          5
extern SSL_CTX * ssl_ctx_new(int options, int num_sessions);
extern void ssl_ctx_free(SSL_CTX *ssl_ctx);
extern SSL_EXTENSIONS * ssl_ext_new();
extern void ssl_ext_free(SSL_EXTENSIONS *ssl_ext);
extern SSL * ssl_server_new(SSL_CTX *ssl_ctx, int client_fd);
extern SSL * ssl_client_new(SSL_CTX *ssl_ctx, int client_fd, const unsigned char session_id[], unsigned char sess_id_size, SSL_EXTENSIONS* ssl_ext);
extern void ssl_free(SSL *ssl);
extern int ssl_read(SSL *ssl, unsigned char **in_data);
extern int ssl_write(SSL *ssl, unsigned char *INPUT, int out_len);
extern SSL * ssl_find(SSL_CTX *ssl_ctx, int client_fd);
extern const unsigned char * ssl_get_session_id(const SSL *ssl);
extern unsigned char ssl_get_session_id_size(const SSL *ssl);
extern unsigned char ssl_get_cipher_id(const SSL *ssl);
extern int ssl_handshake_status(const SSL *ssl);
extern int ssl_get_config(int offset);
extern void ssl_display_error(int error_code);
extern int ssl_verify_cert(const SSL *ssl);
extern const char * ssl_get_cert_dn(const SSL *ssl, int component);
extern const char * ssl_get_cert_subject_alt_dnsname(const SSL *ssl, int dnsindex);
extern int ssl_renegotiate(SSL *ssl);
extern int ssl_obj_load(SSL_CTX *ssl_ctx, int obj_type, const char *filename, const char *password);
extern int ssl_obj_memory_load(SSL_CTX *ssl_ctx, int obj_type, unsigned char *INPUT, int len, const char *password);
extern const char * ssl_version();
