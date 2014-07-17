#include <gpgme.h>

gpgme_err_code_t gpgme_err_code_uninlined (gpgme_error_t err){
    return gpgme_err_code(err);
}

gpgme_err_source_t gpgme_err_source_uninlined (gpgme_error_t err){
    return gpgme_err_source(err);
}

gpgme_error_t gpgme_err_make_uninlined ( gpgme_err_source_t err_source
                                         , gpgme_err_code_t err_code){
    return gpgme_err_make(err_source, err_code);
}
