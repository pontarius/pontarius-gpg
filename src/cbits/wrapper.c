#include <gpgme.h>

gpgme_err_code_t gpgme_err_code_uninlined (gpgme_error_t err){
    return gpgme_err_code(err);
}

gpgme_err_source_t gpgme_err_source_uninlined (gpgme_error_t err){
    return gpgme_err_source(err);
}
