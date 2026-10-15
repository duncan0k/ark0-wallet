/*
 * The single translation unit build.rs compiles: mldsa-native's own single-unit file, configured by
 * pqw_mldsa44_config.h. Defining MLD_CONFIG_FILE here rather than on the command line avoids quoting a
 * string-valued macro through every compiler driver (gcc, clang, clang-cl).
 */
#define MLD_CONFIG_FILE "pqw_mldsa44_config.h"
#include "mldsa-native/mldsa_native.c"
