#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <arpa/inet.h>
#include <libmilter/mfapi.h>
#include <netinet/in.h>

static PyObject *g_module_inst;

typedef struct {
    PyObject_HEAD
    SMFICTX *ctx;
} SMFICTXObject;

static void
SMFICTXObject_dealloc(SMFICTXObject *self)
{
    PyObject_Free(self);
}

static PyTypeObject SMFICTXObject_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "packetfrenzy.libmilter.libmilter.SMFICTX",
    .tp_doc = PyDoc_STR("SMFICTX"),
    .tp_basicsize = sizeof(SMFICTXObject),
    .tp_dealloc = (destructor)SMFICTXObject_dealloc,
};

static PyObject *
SMFICTXObject_New(SMFICTX *ctx)
{
    SMFICTXObject *obj;

    if (!ctx)
    {
        PyErr_SetString(PyExc_ValueError, "SMFICTXObject_New called with null ctx");
        return NULL;
    }

    obj = PyObject_New(SMFICTXObject, &SMFICTXObject_Type);
    if (obj == NULL)
        return NULL;

    obj->ctx = ctx;
    return (PyObject *)obj;
}

#define SMFICTXObject_Get(o) ((SMFICTX *)((SMFICTXObject *)o)->ctx)

typedef struct {
    bool decode_smtp_cmd_args;
    bool registered;
    sfsistat default_ret;
    sfsistat default_error;
    PyObject *xxfi_connect;
    PyObject *xxfi_helo;
    PyObject *xxfi_envfrom;
    PyObject *xxfi_envrcpt;
    PyObject *xxfi_header;
    PyObject *xxfi_eoh;
    PyObject *xxfi_body;
    PyObject *xxfi_eom;
    PyObject *xxfi_abort;
    PyObject *xxfi_close;
    PyObject *xxfi_unknown;
    PyObject *xxfi_data;
    PyObject *xxfi_negotiate;
    PyObject *error;
} libmilter_state_t;

static libmilter_state_t*
get_libmilter_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (libmilter_state_t *)state;
}

static void clear_callbacks(libmilter_state_t *state)
{
    Py_CLEAR(state->xxfi_connect);
    Py_CLEAR(state->xxfi_helo);
    Py_CLEAR(state->xxfi_envfrom);
    Py_CLEAR(state->xxfi_envrcpt);
    Py_CLEAR(state->xxfi_header);
    Py_CLEAR(state->xxfi_eoh);
    Py_CLEAR(state->xxfi_body);
    Py_CLEAR(state->xxfi_eom);
    Py_CLEAR(state->xxfi_abort);
    Py_CLEAR(state->xxfi_close);
    Py_CLEAR(state->xxfi_unknown);
    Py_CLEAR(state->xxfi_data);
    Py_CLEAR(state->xxfi_negotiate);
}

typedef struct {
    PyObject *cb_privatedata;
    unsigned long steps_offered;
    unsigned long steps_requested;

} libmilter_privatedata_t;

libmilter_privatedata_t*
get_privatedata(PyObject *module, SMFICTX *ctx)
{
    libmilter_privatedata_t *privatedata = smfi_getpriv(ctx);
    if (!privatedata) {
        privatedata = calloc(1, sizeof(libmilter_privatedata_t));
        if (!privatedata) {
            PyErr_NoMemory();
            return NULL;
        }
        if (smfi_setpriv(ctx, privatedata) == MI_FAILURE)
        {
            free(privatedata);
            libmilter_state_t *state = get_libmilter_state(module);
            PyErr_SetString(state->error, "smfi_setpriv");
            return NULL;
        }
        privatedata->cb_privatedata = Py_NewRef(Py_None);
    }
    return privatedata;
}

void
free_privatedata(SMFICTX *ctx)
{
    libmilter_privatedata_t *privatedata = smfi_getpriv(ctx);
    if (privatedata) {
        Py_DECREF(privatedata->cb_privatedata);
        free(privatedata);
    }
}

static inline PyObject *
convert_input(char *buf, bool decode, bool utf8)
{
    if (!buf)
        Py_RETURN_NONE;
    if (decode) {
        if (utf8)
            return PyUnicode_FromString(buf);
        else
            return PyUnicode_DecodeASCII(buf, strlen(buf), "surrogateescape");
    }
    return PyBytes_FromString(buf);
}

static sfsistat
handle_pycb_ret(
    PyObject *module, libmilter_state_t *state, SMFICTX *ctx,
    unsigned long smfip_nr_flag, PyObject *pycb_ret)
{
    unsigned long default_ret = state->default_ret;
    unsigned long default_error = state->default_error;
    sfsistat ret = default_error;
    int noreply = 0;

    if (!pycb_ret) {
        PyErr_Print();
        return ret;
    }

    if (state->xxfi_negotiate && smfip_nr_flag) {
        libmilter_privatedata_t *privatedata = get_privatedata(module, ctx);
        if (!privatedata) {
            PyErr_Print();
            goto finish;
        }
        if (privatedata->steps_offered & smfip_nr_flag &&
                privatedata->steps_requested & smfip_nr_flag) {
            noreply = 1;
            goto finish;
        }
    }

    if (pycb_ret == Py_None) {
        ret = default_ret;
    }
    else {
        ret = PyLong_AsLong(pycb_ret);
        if (ret == -1 && PyErr_Occurred()) {
            ret = default_error;
            PyErr_Print();
        }
    }

finish:
    Py_DECREF(pycb_ret);
    return noreply ? SMFIS_NOREPLY : ret;
}

static sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = NULL;
    PyObject *nameobj = NULL;
    PyObject *addrobj = NULL;
    PyObject *pycb_ret = NULL;

    ctxobj = SMFICTXObject_New(ctx);
    nameobj = PyUnicode_FromString(hostname);

    if (hostaddr) {
        switch (hostaddr->sa_family) {
            case AF_INET:
            {
                char buf[INET_ADDRSTRLEN];
                struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
                if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) == NULL)
                    PyErr_SetFromErrno(PyExc_OSError);
                else
                    addrobj = PyUnicode_FromString(buf);
            }
                break;
            case AF_INET6:
            {
                char buf[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)hostaddr;
                if (inet_ntop(AF_INET, &sa->sin6_addr, buf, sizeof(buf)) == NULL)
                    PyErr_SetFromErrno(PyExc_OSError);
                else
                    addrobj = PyUnicode_FromString(buf);
            }
                break;
            case AF_UNIX:
            default:
                // TODO:
                addrobj = Py_NewRef(Py_None);
        }
    }

    pycb_ret = PyObject_CallFunction(state->xxfi_connect, "OOO", ctxobj, nameobj, addrobj);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_CONN, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(nameobj);
    Py_XDECREF(addrobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_helo(SMFICTX *ctx, char *helohost)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *arg = convert_input(helohost, state->decode_smtp_cmd_args, true);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_helo, "OO", ctxobj, arg);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_HELO, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(arg);
    PyGILState_Release(gstate);
    return ret;
}

PyObject *
make_argv(char **argv, bool decode, bool utf8)
{
    char **p = argv;
    int count = 0;
    PyObject *ret;
    PyObject *value;

    while(*p++)
        count++;

    if (!(ret = PyTuple_New(count)))
        return NULL;

    for (int i=0; i < count; i++) {
        if (!(value = convert_input(argv[i], decode, utf8))) {
            Py_DECREF(ret);
            return NULL;
        }
        PyTuple_SET_ITEM(ret, i, value);
    }
    return ret;
}

static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **argv)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *argvobj = make_argv(argv, state->decode_smtp_cmd_args, true);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_envfrom, "OO", ctxobj, argvobj);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_MAIL, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(argvobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **argv)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *argvobj = make_argv(argv, state->decode_smtp_cmd_args, true);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_envrcpt, "OO", ctxobj, argvobj);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_RCPT, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(argvobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *fobj = convert_input(headerf, state->decode_smtp_cmd_args, false);
    PyObject *vobj = convert_input(headerv, state->decode_smtp_cmd_args, true);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_header, "OOO", ctxobj, fobj, vobj);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_HDR, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(fobj);
    Py_XDECREF(vobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_eoh(SMFICTX *ctx)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_EOH,
            PyObject_CallFunction(state->xxfi_eoh, "N", SMFICTXObject_New(ctx)));

    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_body, "Oy#", ctxobj, bodyp, len);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_BODY, pycb_ret);
    Py_XDECREF(ctxobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_eom(SMFICTX *ctx)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, 0,
            PyObject_CallFunction(state->xxfi_eom, "N", SMFICTXObject_New(ctx)));

    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_abort(SMFICTX *ctx)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, 0,
            PyObject_CallFunction(state->xxfi_abort, "N", SMFICTXObject_New(ctx)));

    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_close(SMFICTX *ctx)
{
    sfsistat ret = SMFIS_CONTINUE;

    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    if (state->xxfi_close) {
        ret = handle_pycb_ret(g_module_inst, state, ctx, 0,
            PyObject_CallFunction(state->xxfi_close, "N", SMFICTXObject_New(ctx)));
    }

    free_privatedata(ctx);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_unknown(SMFICTX *ctx, const char *arg)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *argobj = convert_input((char *)arg, state->decode_smtp_cmd_args, false);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_unknown, "OO", ctxobj, argobj);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, 0, pycb_ret);
    Py_XDECREF(ctxobj);
    Py_XDECREF(argobj);
    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_data(SMFICTX *ctx)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    sfsistat ret = handle_pycb_ret(g_module_inst, state, ctx, SMFIP_NR_DATA,
            PyObject_CallFunction(state->xxfi_data, "N", SMFICTXObject_New(ctx)));

    PyGILState_Release(gstate);
    return ret;
}

static sfsistat
mlfi_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1, unsigned long f2, unsigned long f3,
               unsigned long *pf0, unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    libmilter_state_t *state = get_libmilter_state(g_module_inst);

    sfsistat ret = SMFIS_REJECT;
    PyObject *ctxobj = SMFICTXObject_New(ctx);
    PyObject *pycb_ret = PyObject_CallFunction(state->xxfi_negotiate, "Okkkk", ctxobj, f0, f1, f2, f3);
    if (!pycb_ret) {
        PyErr_Print();
        goto finish;
    }
    if (pycb_ret == Py_None) {
        ret = SMFIS_ALL_OPTS;
    }
    else if (!PyTuple_Check(pycb_ret)) {
        PyObject *tmp = PyTuple_New(1);
        if (!tmp) {
            PyErr_Print();
            goto finish;
        }
        PyTuple_SET_ITEM(tmp, 0, pycb_ret);
        pycb_ret = tmp;
    }

    if (!PyArg_ParseTuple(pycb_ret, "i|kkkk:xxfi_negotiate", &ret, pf0, pf1, pf2, pf3)) {
        PyErr_Print();
        goto finish;
    }

    libmilter_privatedata_t *privatedata = get_privatedata(g_module_inst, ctx);
    if (!privatedata) {
        PyErr_Print();
        goto finish;
    }

    privatedata->steps_offered = f1;
    privatedata->steps_requested = *pf1;

finish:
    Py_XDECREF(ctxobj);
    Py_XDECREF(pycb_ret);
    PyGILState_Release(gstate);
    return ret;
}

/* Library Control Functions */

#define LIBMILTER_SMFI_OPENSOCKET_METHODDEF    \
    {"smfi_opensocket", (PyCFunction)libmilter_smfi_opensocket, METH_VARARGS, libmilter_smfi_opensocket__doc__},

PyDoc_STRVAR(libmilter_smfi_opensocket__doc__,
"smfi_opensocket()\n"
"--\n\n"
"Attempt to create the interface socket MTAs will use to connect to the filter.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_opensocket(PyObject *module, PyObject *args)
{
    int rmsocket;
    if (!PyArg_ParseTuple(args, "p:smfi_opensocket", &rmsocket))
        return NULL;

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_opensocket((bool)rmsocket);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_opensocket");
    return NULL;
}


#define LIBMILTER_SMFI_REGISTER_METHODDEF    \
    {"smfi_register", (PyCFunction)libmilter_smfi_register, METH_VARARGS | METH_KEYWORDS, libmilter_smfi_register__doc__},

PyDoc_STRVAR(libmilter_smfi_register__doc__,
"smfi_register()\n"
"--\n\n"
"Create a filter.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_register(PyObject *module, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "xxfi_name", "xxfi_flags",
        "decode_smtp_cmd_args",
        "default_ret", "default_error",
        "xxfi_connect", "xxfi_helo", "xxfi_envfrom",
        "xxfi_envrcpt", "xxfi_header", "xxfi_eoh",
        "xxfi_body", "xxfi_eom", "xxfi_abort",
        "xxfi_close", "xxfi_unknown", "xxfi_data",
        "xxfi_negotiate",
        NULL
    };
    struct smfiDesc smfilter = {0};
    int decode_smtp_cmd_args = 0;
    sfsistat default_ret = SMFIS_CONTINUE;
    sfsistat default_error = SMFIS_CONTINUE;
    PyObject *xxfi_connect = Py_None;
    PyObject *xxfi_helo = Py_None;
    PyObject *xxfi_envfrom = Py_None;
    PyObject *xxfi_envrcpt = Py_None;
    PyObject *xxfi_header = Py_None;
    PyObject *xxfi_eoh = Py_None;
    PyObject *xxfi_body = Py_None;
    PyObject *xxfi_eom = Py_None;
    PyObject *xxfi_abort = Py_None;
    PyObject *xxfi_close = Py_None;
    PyObject *xxfi_unknown = Py_None;
    PyObject *xxfi_data = Py_None;
    PyObject *xxfi_negotiate = Py_None;

    libmilter_state_t *state = get_libmilter_state(module);

    if (state->registered) {
        PyErr_SetString(state->error, "filter already registered");
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sk$pOOOOOOOOOOOOOOO:smfi_register", kwlist,
                                     &smfilter.xxfi_name, &smfilter.xxfi_flags,
                                     &decode_smtp_cmd_args,
                                     &default_ret, &default_error,
                                     &xxfi_connect, &xxfi_helo, &xxfi_envfrom,
                                     &xxfi_envrcpt, &xxfi_header, &xxfi_eoh,
                                     &xxfi_body, &xxfi_eom, &xxfi_abort,
                                     &xxfi_close, &xxfi_unknown, &xxfi_data,
                                     &xxfi_negotiate)) {
        return NULL;
    }

    smfilter.xxfi_version = SMFI_VERSION;

    state->decode_smtp_cmd_args = (bool)decode_smtp_cmd_args;
    state->default_ret = default_ret;
    state->default_error = default_error;

    if (xxfi_connect != Py_None) {
        // TODO: Add PyCallable_Check
        smfilter.xxfi_connect = mlfi_connect;
        state->xxfi_connect = Py_NewRef(xxfi_connect);
    }
    if (xxfi_helo != Py_None) {
        smfilter.xxfi_helo = mlfi_helo;
        state->xxfi_helo = Py_NewRef(xxfi_helo);
    }
    if (xxfi_envfrom != Py_None) {
        smfilter.xxfi_envfrom = mlfi_envfrom;
        state->xxfi_envfrom = Py_NewRef(xxfi_envfrom);
    }
    if (xxfi_envrcpt != Py_None) {
        smfilter.xxfi_envrcpt = mlfi_envrcpt;
        state->xxfi_envrcpt = Py_NewRef(xxfi_envrcpt);
    }
    if (xxfi_header != Py_None) {
        smfilter.xxfi_header = mlfi_header;
        state->xxfi_header = Py_NewRef(xxfi_header);
    }
    if (xxfi_eoh != Py_None) {
        smfilter.xxfi_eoh = mlfi_eoh;
        state->xxfi_eoh = Py_NewRef(xxfi_eoh);
    }
    if (xxfi_body != Py_None) {
        smfilter.xxfi_body = mlfi_body;
        state->xxfi_body = Py_NewRef(xxfi_body);
    }
    if (xxfi_eom != Py_None) {
        smfilter.xxfi_eom = mlfi_eom;
        state->xxfi_eom = Py_NewRef(xxfi_eom);
    }
    if (xxfi_abort != Py_None) {
        smfilter.xxfi_abort = mlfi_abort;
        state->xxfi_abort = Py_NewRef(xxfi_abort);
    }
    smfilter.xxfi_close = mlfi_close; // has required cleanup
    if (xxfi_close != Py_None) {
        state->xxfi_close = Py_NewRef(xxfi_close);
    }
    if (xxfi_unknown != Py_None) {
        smfilter.xxfi_unknown = mlfi_unknown;
        state->xxfi_unknown = Py_NewRef(xxfi_unknown);
    }
    if (xxfi_data != Py_None) {
        smfilter.xxfi_data = mlfi_data;
        state->xxfi_data = Py_NewRef(xxfi_data);
    }
    if (xxfi_negotiate != Py_None) {
        smfilter.xxfi_negotiate = mlfi_negotiate;
        state->xxfi_negotiate = Py_NewRef(xxfi_negotiate);
    }

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_register(smfilter);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS) {
        state->registered = true;
        Py_RETURN_NONE;
    }

    clear_callbacks(state);
    PyErr_SetString(state->error, "smfi_register failed");
    return NULL;
}


#define LIBMILTER_SMFI_SETCONN_METHODDEF    \
    {"smfi_setconn", (PyCFunction)libmilter_smfi_setconn, METH_VARARGS, libmilter_smfi_setconn__doc__},

PyDoc_STRVAR(libmilter_smfi_setconn__doc__,
"smfi_setconn(oconn)\n"
"--\n\n"
"Set the socket through which this filter should communicate with sendmail.\n"
"\n"
"Args:\n"
"   oconn (str): {unix|local}:/path/to/file -- A named pipe.\n"
"                inet:port@{hostname|ip-address} -- An IPV4 socket.\n"
"                inet6:port@{hostname|ip-address} -- An IPV6 socket.\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_setconn(PyObject *module, PyObject *args)
{
    char *oconn;
    if (!PyArg_ParseTuple(args, "s:smfi_setconn", &oconn))
        return NULL;

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_setconn(oconn);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_setconn");
    return NULL;
}


#define LIBMILTER_SMFI_SETTIMEOUT_METHODDEF    \
    {"smfi_settimeout", (PyCFunction)libmilter_smfi_settimeout, METH_VARARGS, libmilter_smfi_settimeout__doc__},

PyDoc_STRVAR(libmilter_smfi_settimeout__doc__,
"smfi_settimeout()\n"
"--\n\n"
"Set the filter's I/O timeout value.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_settimeout(PyObject *module, PyObject *args)
{
    int otimeout;
    if (!PyArg_ParseTuple(args, "i:smfi_settimeout", &otimeout))
        return NULL;

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_settimeout(otimeout);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_settimeout");
    return NULL;
}


#define LIBMILTER_SMFI_SETBACKLOG_METHODDEF    \
    {"smfi_setbacklog", (PyCFunction)libmilter_smfi_setbacklog, METH_VARARGS, libmilter_smfi_setbacklog__doc__},

PyDoc_STRVAR(libmilter_smfi_setbacklog__doc__,
"smfi_setbacklog()\n"
"--\n\n"
"Set the filter's listen(2) backlog value.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_setbacklog(PyObject *module, PyObject *args)
{
    int obacklog;
    if (!PyArg_ParseTuple(args, "i:smfi_setbacklog", &obacklog))
        return NULL;

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_setbacklog(obacklog);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_setbacklog");
    return NULL;
}


#define LIBMILTER_SMFI_SETDBG_METHODDEF    \
    {"smfi_setdbg", (PyCFunction)libmilter_smfi_setdbg, METH_VARARGS, libmilter_smfi_setdbg__doc__},

PyDoc_STRVAR(libmilter_smfi_setdbg__doc__,
"smfi_setdbg()\n"
"--\n\n"
"Set the debugging (tracing) level for the milter library.\n"
"\n"
"Returns:\n"
"    None\n"
);

static PyObject *
libmilter_smfi_setdbg(PyObject *module, PyObject *args)
{
    int level;
    if (!PyArg_ParseTuple(args, "i:smfi_setdbg", &level))
        return NULL;

    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_setdbg(level);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_setdbg");
    return NULL;
}


#define LIBMILTER_SMFI_STOP_METHODDEF    \
    {"smfi_stop", (PyCFunction)libmilter_smfi_stop, METH_NOARGS, libmilter_smfi_stop__doc__},

PyDoc_STRVAR(libmilter_smfi_stop__doc__,
"smfi_stop()\n"
"--\n\n"
"Shutdown the milter.\n"
"\n"
"Returns:\n"
"    None\n"
);

static PyObject *
libmilter_smfi_stop(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_stop();
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_stop");
    return NULL;
}


#define LIBMILTER_SMFI_MAIN_METHODDEF    \
    {"smfi_main", (PyCFunction)libmilter_smfi_main, METH_NOARGS, libmilter_smfi_main__doc__},

PyDoc_STRVAR(libmilter_smfi_main__doc__,
"smfi_main()\n"
"--\n\n"
"Hand control to libmilter event loop.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_main(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    libmilter_state_t *state = get_libmilter_state(module);
    if (!state->registered) {
        PyErr_SetString(state->error, "smfi_main: smfi_register() is required");
        return NULL;
    }
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_main();
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    PyErr_SetString(state->error, "smfi_main");
    return NULL;
}

/* Data Access Functions */

#define LIBMILTER_SMFI_GETSYMVAL_METHODDEF    \
    {"smfi_getsymval", (PyCFunction)libmilter_smfi_getsymval, METH_VARARGS, libmilter_smfi_getsymval__doc__},

PyDoc_STRVAR(libmilter_smfi_getsymval__doc__,
"smfi_getsymval(ctx, symname)\n"
"--\n\n"
"Get the macro value.\n"
"\n"
"Args:\n"
"    ctx (SMFICTX):\n"
"    symname (str):\n"
"Returns:\n"
"    bytes: macro value\n"
"Raises:\n"
"    LookupError"
);

static PyObject *
libmilter_smfi_getsymval(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *symname;
    char *value;

    if (!PyArg_ParseTuple(args, "O!s:smfi_getsymval", &SMFICTXObject_Type, &ctxobj, &symname))
        return NULL;

    if (!(value = smfi_getsymval(SMFICTXObject_Get(ctxobj), symname))) {
        PyErr_SetString(PyExc_LookupError, symname);
        return NULL;
    }

    return convert_input(value, true, true);
}


#define LIBMILTER_SMFI_GETPRIV_METHODDEF    \
    {"smfi_getpriv", (PyCFunction)libmilter_smfi_getpriv, METH_VARARGS, libmilter_smfi_getpriv__doc__},

PyDoc_STRVAR(libmilter_smfi_getpriv__doc__,
"smfi_getpriv()\n"
"--\n\n"
"Get the connection-specific data pointer for this connection.\n"
"\n"
"Returns:\n"
"    obj:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_getpriv(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    libmilter_privatedata_t *privatedata;

    if (!PyArg_ParseTuple(args, "O!:smfi_getpriv", &SMFICTXObject_Type, &ctxobj))
        return NULL;

    if (!(privatedata = get_privatedata(module, SMFICTXObject_Get(ctxobj))))
        return NULL;

    return Py_NewRef(privatedata->cb_privatedata);
}


#define LIBMILTER_SMFI_SETPRIV_METHODDEF    \
    {"smfi_setpriv", (PyCFunction)libmilter_smfi_setpriv, METH_VARARGS, libmilter_smfi_setpriv__doc__},

PyDoc_STRVAR(libmilter_smfi_setpriv__doc__,
"smfi_setpriv()\n"
"--\n\n"
"Set the private data pointer for this connection.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_setpriv(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    PyObject *new_data;

    if (!PyArg_ParseTuple(args, "O!O:smfi_setpriv", &SMFICTXObject_Type, &ctxobj, &new_data))
        return NULL;

    libmilter_privatedata_t *privatedata;
    if (!(privatedata = get_privatedata(module, SMFICTXObject_Get(ctxobj))))
    return NULL;

    Py_DECREF(privatedata->cb_privatedata);
    privatedata->cb_privatedata = Py_NewRef(new_data);

    Py_RETURN_NONE;
}


#define LIBMILTER_SMFI_SETREPLY_METHODDEF    \
    {"smfi_setreply", (PyCFunction)libmilter_smfi_setreply, METH_VARARGS, libmilter_smfi_setreply__doc__},

PyDoc_STRVAR(libmilter_smfi_setreply__doc__,
"smfi_setreply()\n"
"--\n\n"
"Set the specific reply code.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_setreply(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *rcode;
    char *xcode = NULL;
    char *message = NULL;

    if (!PyArg_ParseTuple(args, "O!s|zz:smfi_setreply", &SMFICTXObject_Type, &ctxobj, &rcode, &xcode, &message))
        return NULL;

    if (smfi_setreply(SMFICTXObject_Get(ctxobj), rcode, xcode, message) == MI_FAILURE) {
        libmilter_state_t *state = get_libmilter_state(module);
        PyErr_SetString(state->error, "smfi_setreply");
        return NULL;
    }
    Py_RETURN_NONE;
}


#define LIBMILTER_SMFI_SETMLREPLY_METHODDEF    \
    {"smfi_setmlreply", (PyCFunction)libmilter_smfi_setmlreply, METH_VARARGS, libmilter_smfi_setmlreply__doc__},

PyDoc_STRVAR(libmilter_smfi_setmlreply__doc__,
"smfi_setmlreply()\n"
"--\n\n"
"Set the reply code to a multi-line ret.\n"
"\n"
"Returns:\n"
"    None\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_setmlreply(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *rcode;
    char *xcode = NULL;
    char *m[32] = {NULL};

    if (!PyArg_ParseTuple(args, "O!s|zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:smfi_setmlreply", 
            &SMFICTXObject_Type, &ctxobj, &rcode, &xcode,
            &m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &m[6], &m[7], &m[8],
            &m[9], &m[10], &m[11], &m[12], &m[13], &m[14], &m[15], &m[16],
            &m[17], &m[18], &m[19], &m[20], &m[21], &m[22], &m[23], &m[24],
            &m[25], &m[26], &m[27], &m[28], &m[29], &m[30], &m[31])) {
        return NULL;
    }

    if (smfi_setmlreply(SMFICTXObject_Get(ctxobj), rcode, xcode,
            m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8],
            m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16],
            m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24],
            m[25], m[26], m[27], m[28], m[29], m[30], m[31], NULL) == MI_FAILURE) {
        libmilter_state_t *state = get_libmilter_state(module);
        PyErr_SetString(state->error, "smfi_setmlreply");
        return NULL;
    }
    Py_RETURN_NONE;
}

/* Message Modification Functions */

#define LIBMILTER_SMFI_ADDHEADER_METHODDEF    \
    {"smfi_addheader", (PyCFunction)libmilter_smfi_addheader, METH_VARARGS, libmilter_smfi_addheader__doc__},

PyDoc_STRVAR(libmilter_smfi_addheader__doc__,
"smfi_addheader(ctx, headerf, headerv)\n"
"--\n\n"
"Add a header to the current message.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_addheader(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *headerf;
    char *headerv;
    if (!PyArg_ParseTuple(args, "O!etet:smfi_addheader", &SMFICTXObject_Type, &ctxobj, NULL, &headerf, NULL, &headerv))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_addheader(ctx, headerf, headerv);
    Py_END_ALLOW_THREADS
    PyMem_Free(headerf);
    PyMem_Free(headerv);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_addheader");
    return NULL;
}


#define LIBMILTER_SMFI_CHGHEADER_METHODDEF    \
    {"smfi_chgheader", (PyCFunction)libmilter_smfi_chgheader, METH_VARARGS, libmilter_smfi_chgheader__doc__},

PyDoc_STRVAR(libmilter_smfi_chgheader__doc__,
"smfi_chgheader(ctx, headerf, hdridx, headerv)\n"
"--\n\n"
"Change or delete a message header.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_chgheader(PyObject *module, PyObject *args)
{
    PyObject *ret = NULL;
    PyObject *ctxobj;
    char *headerf;
    int hdridx;
    Py_buffer headerv;
    if (!PyArg_ParseTuple(args, "O!etiz*:smfi_chgheader", &SMFICTXObject_Type, &ctxobj, NULL, &headerf, &hdridx, &headerv))
        return NULL;

    if (headerv.buf && (size_t)headerv.len != strlen(headerv.buf)) {
        PyErr_SetString(PyExc_ValueError, "header field body contains embedded null byte");
        goto finish;
    }

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_chgheader(ctx, headerf, hdridx, headerv.buf);
    Py_END_ALLOW_THREADS

    if (res == MI_SUCCESS) {
        ret = Py_NewRef(Py_None);
        goto finish;
    }

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_chgheader");

finish:
    PyMem_Free(headerf);
    PyBuffer_Release(&headerv);
    return ret;
}


#define LIBMILTER_SMFI_INSHEADER_METHODDEF    \
    {"smfi_insheader", (PyCFunction)libmilter_smfi_insheader, METH_VARARGS, libmilter_smfi_insheader__doc__},

PyDoc_STRVAR(libmilter_smfi_insheader__doc__,
"smfi_insheader(ctx, hdridx, headerf, headerv)\n"
"--\n\n"
"Prepend a header to the current message.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_insheader(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    int hdridx;
    char *headerf;
    char *headerv;
    if (!PyArg_ParseTuple(args, "O!ietet:smfi_insheader", &SMFICTXObject_Type, &ctxobj, &hdridx, NULL, &headerf, NULL, &headerv))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_insheader(ctx, hdridx, headerf, headerv);
    Py_END_ALLOW_THREADS
    PyMem_Free(headerf);
    PyMem_Free(headerv);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_insheader");
    return NULL;
}


#define LIBMILTER_SMFI_CHGFROM_METHODDEF    \
    {"smfi_chgfrom", (PyCFunction)libmilter_smfi_chgfrom, METH_VARARGS, libmilter_smfi_chgfrom__doc__},

PyDoc_STRVAR(libmilter_smfi_chgfrom__doc__,
"smfi_chgfrom(ctx, mail, args)\n"
"--\n\n"
"Change the envelope sender (MAIL From) of the current message.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_chgfrom(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *mail;
    char *esmtp_args = NULL;
    if (!PyArg_ParseTuple(args, "O!et|et:smfi_chgfrom", &SMFICTXObject_Type, &ctxobj, &mail, &esmtp_args))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_chgfrom(ctx, mail, esmtp_args);
    Py_END_ALLOW_THREADS
    PyMem_Free(mail);
    PyMem_Free(esmtp_args);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_chgfrom");
    return NULL;
}


#define LIBMILTER_SMFI_ADDRCPT_METHODDEF    \
    {"smfi_addrcpt", (PyCFunction)libmilter_smfi_addrcpt, METH_VARARGS, libmilter_smfi_addrcpt__doc__},

PyDoc_STRVAR(libmilter_smfi_addrcpt__doc__,
"smfi_addrcpt(ctx, rcpt)\n"
"--\n\n"
"Add a recipient for the current message.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_addrcpt(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *rcpt;
    if (!PyArg_ParseTuple(args, "O!et:smfi_addrcpt", &SMFICTXObject_Type, &ctxobj, NULL, &rcpt))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_addrcpt(ctx, rcpt);
    Py_END_ALLOW_THREADS
    PyMem_Free(rcpt);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_addrcpt");
    return NULL;
}


#define LIBMILTER_SMFI_ADDRCPT_PAR_METHODDEF    \
    {"smfi_addrcpt_par", (PyCFunction)libmilter_smfi_addrcpt_par, METH_VARARGS, libmilter_smfi_addrcpt_par__doc__},

PyDoc_STRVAR(libmilter_smfi_addrcpt_par__doc__,
"smfi_addrcpt_par(ctx, rcpt, args)\n"
"--\n\n"
"Add a recipient for the current message including ESMTP arguments.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_addrcpt_par(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *rcpt;
    char *esmtp_args = NULL;
    if (!PyArg_ParseTuple(args, "O!et|et:smfi_addrcpt_par", &SMFICTXObject_Type, &ctxobj, &rcpt, &esmtp_args))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_addrcpt_par(ctx, rcpt, esmtp_args);
    Py_END_ALLOW_THREADS
    PyMem_Free(rcpt);
    PyMem_Free(esmtp_args);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_addrcpt_par");
    return NULL;
}


#define LIBMILTER_SMFI_DELRCPT_METHODDEF    \
    {"smfi_delrcpt", (PyCFunction)libmilter_smfi_delrcpt, METH_VARARGS, libmilter_smfi_delrcpt__doc__},

PyDoc_STRVAR(libmilter_smfi_delrcpt__doc__,
"smfi_delrcpt(ctx, rcpt)\n"
"--\n\n"
"Add a recipient for the current message.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_delrcpt(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *rcpt;
    if (!PyArg_ParseTuple(args, "O!et:smfi_delrcpt", &SMFICTXObject_Type, &ctxobj, NULL, &rcpt))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_delrcpt(ctx, rcpt);
    Py_END_ALLOW_THREADS
    PyMem_Free(rcpt);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_delrcpt");
    return NULL;
}


#define LIBMILTER_SMFI_REPLACEBODY_METHODDEF    \
    {"smfi_replacebody", (PyCFunction)libmilter_smfi_replacebody, METH_VARARGS, libmilter_smfi_replacebody__doc__},

PyDoc_STRVAR(libmilter_smfi_replacebody__doc__,
"smfi_replacebody(ctx, body)\n"
"--\n\n"
"Replace message-body data.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_replacebody(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    Py_buffer body;

    if (!PyArg_ParseTuple(args, "O!z*:smfi_replacebody", &SMFICTXObject_Type, &ctxobj, &body))
        return NULL;

    SMFICTX *ctx = SMFICTXObject_Get(ctxobj);
    int res;
    Py_BEGIN_ALLOW_THREADS
    res = smfi_replacebody(ctx, body.buf, body.len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&body);

    if (res == MI_SUCCESS)
        Py_RETURN_NONE;

    libmilter_state_t *state = get_libmilter_state(module);
    PyErr_SetString(state->error, "smfi_replacebody");
    return NULL;
}

/* Other Message Handling Functions */

#define LIBMILTER_SMFI_PROGRESS_METHODDEF    \
    {"smfi_progress", (PyCFunction)libmilter_smfi_progress, METH_VARARGS, libmilter_smfi_progress__doc__},

PyDoc_STRVAR(libmilter_smfi_progress__doc__,
"smfi_progress(ctx)\n"
"--\n\n"
"Notify the MTA that an operation is still in progress.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_progress(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;

    if (!PyArg_ParseTuple(args, "O!:smfi_progress", &SMFICTXObject_Type, &ctxobj))
        return NULL;

    if (smfi_progress(SMFICTXObject_Get(ctxobj)) == MI_FAILURE) {
        libmilter_state_t *state = get_libmilter_state(module);
        PyErr_SetString(state->error, "smfi_progress");
        return NULL;
    }

    Py_RETURN_NONE;
}


#define LIBMILTER_SMFI_QUARANTINE_METHODDEF    \
    {"smfi_quarantine", (PyCFunction)libmilter_smfi_quarantine, METH_VARARGS, libmilter_smfi_quarantine__doc__},

PyDoc_STRVAR(libmilter_smfi_quarantine__doc__,
"smfi_quarantine(ctx, reason)\n"
"--\n\n"
"Quarantine the message using the given reason.\n"
"\n"
"Returns:\n"
"    None:\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_quarantine(PyObject *module, PyObject *args)
{
    PyObject *ctxobj;
    char *reason;

    if (!PyArg_ParseTuple(args, "O!s:smfi_quarantine", &SMFICTXObject_Type, &ctxobj, &reason))
        return NULL;

    if (smfi_quarantine(SMFICTXObject_Get(ctxobj), reason) == MI_FAILURE) {
        libmilter_state_t *state = get_libmilter_state(module);
        PyErr_SetString(state->error, "smfi_quarantine");
        return NULL;
    }

    Py_RETURN_NONE;
}

/* Miscellaneous */

#define LIBMILTER_SMFI_VERSION_METHODDEF    \
    {"smfi_version", (PyCFunction)libmilter_smfi_version, METH_NOARGS, libmilter_smfi_version__doc__},

PyDoc_STRVAR(libmilter_smfi_version__doc__,
"smfi_version()\n"
"--\n\n"
"Returns the runtime version of libmilter.\n"
"\n"
"Returns:\n"
"    (int, int, int): major, minor, patch level\n"
"Raises:\n"
"    MilterError"
);

static PyObject *
libmilter_smfi_version(PyObject *module, PyObject *Py_UNUSED(args))
{
    unsigned int major, minor, pl;
    if (smfi_version(&major, &minor, &pl) != MI_SUCCESS) {
        libmilter_state_t *state = get_libmilter_state(module);
        PyErr_SetString(state->error, "smfi_version");
        return NULL;
    }

    return Py_BuildValue("III", major, minor, pl);
}


static int
libmilter_exec(PyObject *module)
{

#define ADD_INT_MACRO(module, macro)                                        \
    do {                                                                    \
        if (PyModule_AddIntConstant(module, #macro, macro) < 0) {           \
            return -1;                                                      \
        }                                                                   \
    } while (0)

    if (PyInterpreterState_Get() != PyInterpreterState_Main()) {
        PyErr_SetString(PyExc_ImportError,
                        "subinterpreter cannot import _libmilter module");
        return -1;
    }

    libmilter_state_t *state = get_libmilter_state(module);

    state->decode_smtp_cmd_args = false;

    state->error = PyErr_NewExceptionWithDoc("packetfrenzy.libmilter.MilterError",
                                             "Call to libmilter failed.", NULL, NULL);
    if (state->error == NULL)
        return -1;

    if (PyModule_AddType(module, (PyTypeObject *)state->error) < 0)
        return -1;

    if (PyModule_AddStringConstant(module, "__version__", VERSION) < 0)
        return -1;

    ADD_INT_MACRO(module, SMFI_VERSION);
    ADD_INT_MACRO(module, MI_SUCCESS);
    ADD_INT_MACRO(module, MI_FAILURE);
    ADD_INT_MACRO(module, MI_CONTINUE);
    ADD_INT_MACRO(module, SMFIF_NONE);
    ADD_INT_MACRO(module, SMFIF_ADDHDRS);
    ADD_INT_MACRO(module, SMFIF_CHGBODY);
    ADD_INT_MACRO(module, SMFIF_MODBODY);
    ADD_INT_MACRO(module, SMFIF_ADDRCPT);
    ADD_INT_MACRO(module, SMFIF_DELRCPT);
    ADD_INT_MACRO(module, SMFIF_CHGHDRS);
    ADD_INT_MACRO(module, SMFIF_QUARANTINE);
    ADD_INT_MACRO(module, SMFIF_CHGFROM);
    ADD_INT_MACRO(module, SMFIF_ADDRCPT_PAR);
    ADD_INT_MACRO(module, SMFIF_SETSYMLIST);
    ADD_INT_MACRO(module, SMFIM_CONNECT);
    ADD_INT_MACRO(module, SMFIM_HELO);
    ADD_INT_MACRO(module, SMFIM_ENVFROM);
    ADD_INT_MACRO(module, SMFIM_ENVRCPT);
    ADD_INT_MACRO(module, SMFIM_DATA);
    ADD_INT_MACRO(module, SMFIM_EOM);
    ADD_INT_MACRO(module, SMFIM_EOH);
    ADD_INT_MACRO(module, SMFIS_CONTINUE);
    ADD_INT_MACRO(module, SMFIS_REJECT);
    ADD_INT_MACRO(module, SMFIS_DISCARD);
    ADD_INT_MACRO(module, SMFIS_ACCEPT);
    ADD_INT_MACRO(module, SMFIS_TEMPFAIL);
    ADD_INT_MACRO(module, SMFIS_NOREPLY);
    ADD_INT_MACRO(module, SMFIS_SKIP);
    ADD_INT_MACRO(module, SMFIS_ALL_OPTS);

    ADD_INT_MACRO(module, SMFIP_NOCONNECT);
    ADD_INT_MACRO(module, SMFIP_NOHELO);
    ADD_INT_MACRO(module, SMFIP_NOMAIL);
    ADD_INT_MACRO(module, SMFIP_NORCPT);
    ADD_INT_MACRO(module, SMFIP_NOBODY);
    ADD_INT_MACRO(module, SMFIP_NOHDRS);
    ADD_INT_MACRO(module, SMFIP_NOEOH);
    ADD_INT_MACRO(module, SMFIP_NR_HDR);
    ADD_INT_MACRO(module, SMFIP_NOHREPL);
    ADD_INT_MACRO(module, SMFIP_NOUNKNOWN);
    ADD_INT_MACRO(module, SMFIP_NODATA);
    ADD_INT_MACRO(module, SMFIP_SKIP);
    ADD_INT_MACRO(module, SMFIP_RCPT_REJ);
    ADD_INT_MACRO(module, SMFIP_NR_CONN);
    ADD_INT_MACRO(module, SMFIP_NR_HELO);
    ADD_INT_MACRO(module, SMFIP_NR_MAIL);
    ADD_INT_MACRO(module, SMFIP_NR_RCPT);
    ADD_INT_MACRO(module, SMFIP_NR_DATA);
    ADD_INT_MACRO(module, SMFIP_NR_UNKN);
    ADD_INT_MACRO(module, SMFIP_NR_EOH);
    ADD_INT_MACRO(module, SMFIP_NR_BODY);
    ADD_INT_MACRO(module, SMFIP_HDR_LEADSPC);
    ADD_INT_MACRO(module, SMFIP_MDS_256K);
    ADD_INT_MACRO(module, SMFIP_MDS_1M);

    g_module_inst = module;

    return 0;
}

static PyMethodDef libmilter_methods[] = {
    /* Library Control Functions */
    LIBMILTER_SMFI_OPENSOCKET_METHODDEF
    LIBMILTER_SMFI_REGISTER_METHODDEF
    LIBMILTER_SMFI_SETCONN_METHODDEF
    LIBMILTER_SMFI_SETTIMEOUT_METHODDEF
    LIBMILTER_SMFI_SETBACKLOG_METHODDEF
    LIBMILTER_SMFI_SETDBG_METHODDEF
    LIBMILTER_SMFI_STOP_METHODDEF
    LIBMILTER_SMFI_MAIN_METHODDEF
    /* Data Access Functions */
    LIBMILTER_SMFI_GETSYMVAL_METHODDEF
    LIBMILTER_SMFI_GETPRIV_METHODDEF
    LIBMILTER_SMFI_SETPRIV_METHODDEF
    LIBMILTER_SMFI_SETREPLY_METHODDEF
    LIBMILTER_SMFI_SETMLREPLY_METHODDEF
    /* Message Modification Functions */
    LIBMILTER_SMFI_ADDHEADER_METHODDEF
    LIBMILTER_SMFI_CHGHEADER_METHODDEF
    LIBMILTER_SMFI_INSHEADER_METHODDEF
    LIBMILTER_SMFI_CHGFROM_METHODDEF
    LIBMILTER_SMFI_ADDRCPT_METHODDEF
    LIBMILTER_SMFI_ADDRCPT_PAR_METHODDEF
    LIBMILTER_SMFI_DELRCPT_METHODDEF
    LIBMILTER_SMFI_REPLACEBODY_METHODDEF

    /* Other Message Handling Functions */
    LIBMILTER_SMFI_PROGRESS_METHODDEF
    LIBMILTER_SMFI_QUARANTINE_METHODDEF

    /* Miscellaneous */
    LIBMILTER_SMFI_VERSION_METHODDEF
    {NULL}
};

static PyModuleDef_Slot libmilter_slots[] = {
    {Py_mod_exec, libmilter_exec},
    {0, NULL}
};

static int
libmilter_traverse(PyObject *module, visitproc visit, void *arg)
{
    libmilter_state_t *state = get_libmilter_state(module);
    Py_VISIT(state->xxfi_connect);
    Py_VISIT(state->xxfi_helo);
    Py_VISIT(state->xxfi_envfrom);
    Py_VISIT(state->xxfi_envrcpt);
    Py_VISIT(state->xxfi_header);
    Py_VISIT(state->xxfi_eoh);
    Py_VISIT(state->xxfi_body);
    Py_VISIT(state->xxfi_eom);
    Py_VISIT(state->xxfi_abort);
    Py_VISIT(state->xxfi_close);
    Py_VISIT(state->xxfi_unknown);
    Py_VISIT(state->xxfi_data);
    Py_VISIT(state->xxfi_negotiate);
    Py_VISIT(state->error);
    return 0;
}

static int
libmilter_clear(PyObject *module)
{
    libmilter_state_t *state = get_libmilter_state(module);
    clear_callbacks(state);
    Py_CLEAR(state->error);
    return 0;
}

static void
libmilter_free(void *module)
{
    libmilter_clear((PyObject *)module);
}

static PyModuleDef libmiltermodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "packetfrenzy.libmilter",
    .m_size = sizeof(libmilter_state_t),
    .m_methods = libmilter_methods,
    .m_slots = libmilter_slots,
    .m_traverse = libmilter_traverse,
    .m_clear = libmilter_clear,
    .m_free = libmilter_free,
};

PyMODINIT_FUNC
PyInit_libmilter(void)
{
    return PyModuleDef_Init(&libmiltermodule);
}
