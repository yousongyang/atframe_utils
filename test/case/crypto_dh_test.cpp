// Copyright 2026 atframework

#include "algorithm/crypto_dh.h"
#include <cstring>
#include "algorithm/crypto_cipher.h"
#include "common/file_system.h"
#include "frame/test_macros.h"

#ifdef CRYPTO_DH_ENABLED

#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
struct openssl_test_init_wrapper_for_dh {
  openssl_test_init_wrapper_for_dh() { atfw::util::crypto::cipher::init_global_algorithm(); }

  ~openssl_test_init_wrapper_for_dh() { atfw::util::crypto::cipher::cleanup_global_algorithm(); }
};

static std::shared_ptr<openssl_test_init_wrapper_for_dh> openssl_test_inited_for_dh;

#  endif

CASE_TEST(crypto_dh, get_all_curve_names) {
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
  if (!openssl_test_inited_for_dh) {
    openssl_test_inited_for_dh = std::make_shared<openssl_test_init_wrapper_for_dh>();
  }
#  endif
  const std::vector<std::string> &all_curves = atfw::util::crypto::dh::get_all_curve_names();
  std::stringstream ss;
  for (size_t i = 0; i < all_curves.size(); ++i) {
    if (i) {
      ss << ",";
    }

    ss << all_curves[i];
  }

  CASE_MSG_INFO() << "All curves: " << ss.str() << std::endl;
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
  // Openssl 1.0.1 or lower do not support ECDH
#    if (defined(OPENSSL_API_COMPAT) && OPENSSL_API_COMPAT >= 0x10002000L) ||    \
        (defined(OPENSSL_API_LEVEL) && OPENSSL_API_LEVEL >= 10002) ||            \
        (!defined(LIBRESSL_VERSION_NUMBER) && defined(OPENSSL_VERSION_NUMBER) && \
         OPENSSL_VERSION_NUMBER >= 0x10002000L)
  CASE_EXPECT_NE(0, all_curves.size());
#    endif
#  endif
}

// Expected per-curve availability for the active backend, used as adaptation
// regression checks. Exactly one crypto backend is active inside CRYPTO_DH_ENABLED.
//   * OpenSSL/LibreSSL/BoringSSL expose a curve iff its NID is defined.
//   * mbedtls exposes a curve iff the MBEDTLS_ECP_DP_*_ENABLED config is set.
// X448 is forced to 0 on mbedtls because mbedtls_ecdh_can_do reports curve448 as
// unsupported for ECDH. Only the universally available curves are hard-asserted;
// the remaining curves are exercised when the backend reports them.
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_MBEDTLS)
#    ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#      define CRYPTO_DH_TEST_EXPECT_X25519 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_X25519 0
#    endif
#    define CRYPTO_DH_TEST_EXPECT_X448 0
#    ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#      define CRYPTO_DH_TEST_EXPECT_SECP224R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP224R1 0
#    endif
#    ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
#      define CRYPTO_DH_TEST_EXPECT_SECP256R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP256R1 0
#    endif
#    ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#      define CRYPTO_DH_TEST_EXPECT_SECP384R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP384R1 0
#    endif
#    ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#      define CRYPTO_DH_TEST_EXPECT_SECP521R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP521R1 0
#    endif
#  elif defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
#    ifdef NID_X25519
#      define CRYPTO_DH_TEST_EXPECT_X25519 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_X25519 0
#    endif
#    ifdef NID_X448
#      define CRYPTO_DH_TEST_EXPECT_X448 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_X448 0
#    endif
#    ifdef NID_secp224r1
#      define CRYPTO_DH_TEST_EXPECT_SECP224R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP224R1 0
#    endif
#    ifdef NID_X9_62_prime256v1
#      define CRYPTO_DH_TEST_EXPECT_SECP256R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP256R1 0
#    endif
#    ifdef NID_secp384r1
#      define CRYPTO_DH_TEST_EXPECT_SECP384R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP384R1 0
#    endif
#    ifdef NID_secp521r1
#      define CRYPTO_DH_TEST_EXPECT_SECP521R1 1
#    else
#      define CRYPTO_DH_TEST_EXPECT_SECP521R1 0
#    endif
#  else
#    define CRYPTO_DH_TEST_EXPECT_X25519 0
#    define CRYPTO_DH_TEST_EXPECT_X448 0
#    define CRYPTO_DH_TEST_EXPECT_SECP224R1 0
#    define CRYPTO_DH_TEST_EXPECT_SECP256R1 0
#    define CRYPTO_DH_TEST_EXPECT_SECP384R1 0
#    define CRYPTO_DH_TEST_EXPECT_SECP521R1 0
#  endif

namespace {
// Case-insensitive check for whether a curve (e.g. "x25519", "p-256") is reported by
// get_all_curve_names(). Names are stored as "ecdh:<name>" with the canonical casing of
// the supported_dh_curves table, so the suffix comparison ignores case.
static bool crypto_dh_test_has_curve(const char *name) {
  const std::vector<std::string> &all_curves = atfw::util::crypto::dh::get_all_curve_names();
  size_t name_len = strlen(name);
  for (const std::string &curve_name : all_curves) {
    if (curve_name.size() != name_len + 5 || curve_name.compare(0, 5, "ecdh:") != 0) {
      continue;
    }

    bool match = true;
    for (size_t i = 0; i < name_len; ++i) {
      char lhs = curve_name[5 + i];
      char rhs = name[i];
      if (lhs >= 'A' && lhs <= 'Z') {
        lhs = static_cast<char>(lhs - 'A' + 'a');
      }
      if (rhs >= 'A' && rhs <= 'Z') {
        rhs = static_cast<char>(rhs - 'A' + 'a');
      }
      if (lhs != rhs) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

// Runs a full client/server ECDH key exchange for the given curve name (e.g. "x25519").
// Returns the shared secret size in bytes on success, or 0 on any failure.
static size_t crypto_dh_test_exchange(const char *curve_name) {
  std::string ecdh_name = std::string("ecdh:") + curve_name;
  atfw::util::crypto::dh cli_dh;
  atfw::util::crypto::dh svr_dh;

  {
    atfw::util::crypto::dh::shared_context::ptr_t svr_shctx = atfw::util::crypto::dh::shared_context::create();
    if (atfw::util::crypto::dh::error_code_t::kOk != svr_shctx->init(ecdh_name.c_str()) ||
        atfw::util::crypto::dh::error_code_t::kOk != svr_dh.init(svr_shctx)) {
      return 0;
    }
  }
  {
    atfw::util::crypto::dh::shared_context::ptr_t cli_shctx = atfw::util::crypto::dh::shared_context::create();
    if (atfw::util::crypto::dh::error_code_t::kOk != cli_shctx->init(atfw::util::crypto::dh::method_t::kEcdh) ||
        atfw::util::crypto::dh::error_code_t::kOk != cli_dh.init(cli_shctx)) {
      return 0;
    }
  }

  std::vector<unsigned char> switch_params;
  std::vector<unsigned char> switch_public;
  std::vector<unsigned char> cli_secret;
  std::vector<unsigned char> svr_secret;

  if (atfw::util::crypto::dh::error_code_t::kOk != svr_dh.make_params(switch_params) ||
      atfw::util::crypto::dh::error_code_t::kOk != cli_dh.read_params(switch_params.data(), switch_params.size()) ||
      atfw::util::crypto::dh::error_code_t::kOk != cli_dh.make_public(switch_public) ||
      atfw::util::crypto::dh::error_code_t::kOk != cli_dh.calc_secret(cli_secret) ||
      atfw::util::crypto::dh::error_code_t::kOk != svr_dh.read_public(switch_public.data(), switch_public.size()) ||
      atfw::util::crypto::dh::error_code_t::kOk != svr_dh.calc_secret(svr_secret)) {
    return 0;
  }

  if (cli_secret.empty() || cli_secret.size() != svr_secret.size() ||
      0 != memcmp(cli_secret.data(), svr_secret.data(), svr_secret.size())) {
    return 0;
  }
  return svr_secret.size();
}
}  // namespace

// Checks that the crypto backend (OpenSSL/LibreSSL/BoringSSL/mbedtls) and its version
// correctly adapt every supported key agreement algorithm. For each algorithm it verifies
// runtime availability reported by get_all_curve_names() and runs a full key exchange.
// Universally available curves are hard-asserted; provider/config dependent curves
// (secp256k1, brainpool, ...) are exercised only when the backend reports them.
CASE_TEST(crypto_dh, ecdh_algorithm_adaptation) {
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
  if (!openssl_test_inited_for_dh) {
    openssl_test_inited_for_dh = std::make_shared<openssl_test_init_wrapper_for_dh>();
  }
#  endif

  struct curve_case {
    const char *name;
    bool expected;
  };
  const curve_case cases[] = {
      {"x25519", CRYPTO_DH_TEST_EXPECT_X25519 != 0},
      {"x448", CRYPTO_DH_TEST_EXPECT_X448 != 0},
      {"secp224r1", CRYPTO_DH_TEST_EXPECT_SECP224R1 != 0},
      {"secp256r1", CRYPTO_DH_TEST_EXPECT_SECP256R1 != 0},
      {"secp384r1", CRYPTO_DH_TEST_EXPECT_SECP384R1 != 0},
      {"secp521r1", CRYPTO_DH_TEST_EXPECT_SECP521R1 != 0},
      {"secp192r1", false},
      {"secp256k1", false},
      {"secp224k1", false},
      {"secp192k1", false},
      {"brainpoolP256r1", false},
      {"brainpoolP384r1", false},
      {"brainpoolP512r1", false},
  };

  size_t available_count = 0;
  size_t exchange_ok = 0;
  for (const curve_case &c : cases) {
    bool available = crypto_dh_test_has_curve(c.name);
    CASE_MSG_INFO() << "Algorithm ecdh:" << c.name << " => expected=" << (c.expected ? "yes" : "no")
                    << ", available=" << (available ? "yes" : "no") << std::endl;
    if (c.expected) {
      // Adaptation regression check: a curve the backend supports must be exposed.
      CASE_EXPECT_TRUE(available);
    }
    if (!available) {
      continue;
    }
    ++available_count;
    size_t secret_bytes = crypto_dh_test_exchange(c.name);
    CASE_MSG_INFO() << "  Exchange ecdh:" << c.name << " => secret " << (secret_bytes * 8) << " bits" << std::endl;
    CASE_EXPECT_GT(secret_bytes, 0);
    if (secret_bytes > 0) {
      ++exchange_ok;
    }
  }

  CASE_MSG_INFO() << "ECDH adaptation: " << available_count << " curves available, " << exchange_ok
                  << " key exchanges passed." << std::endl;
  CASE_EXPECT_GT(exchange_ok, 0);
}

#  if !defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
CASE_TEST(crypto_dh, dh) {
#    if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL)
  if (!openssl_test_inited_for_dh) {
    openssl_test_inited_for_dh = std::make_shared<openssl_test_init_wrapper_for_dh>();
  }
#    endif

  int test_times = 32;
  int left_times = test_times;
  size_t key_bits = 0;
  // 单元测试多次以定位openssl是否内存泄漏的问题
  // 单元测试发现openssl内部有11处still
  // reachable内存大约72KB。并且不随测试次数增加而增加。初步判断为openssl内部分配的全局数据未释放

  while (left_times-- > 0) {
    // client shared context & dh
    atfw::util::crypto::dh cli_dh;

    // server shared context & dh
    atfw::util::crypto::dh svr_dh;

    // server - init: read and setup server dh params
    {
      atfw::util::crypto::dh::shared_context::ptr_t svr_shctx = atfw::util::crypto::dh::shared_context::create();

      std::string dir;
      CASE_EXPECT_TRUE(atfw::util::file_system::dirname(__FILE__, 0, dir, 2));
      dir += atfw::util::file_system::DIRECTORY_SEPARATOR;
      dir += "resource";
      dir += atfw::util::file_system::DIRECTORY_SEPARATOR;
      dir += "test-dhparam.pem";
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_shctx->init(dir.c_str()));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.init(svr_shctx));
    }

    // client - init: read and setup client shared context
    {
      atfw::util::crypto::dh::shared_context::ptr_t cli_shctx = atfw::util::crypto::dh::shared_context::create();
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_shctx->init(atfw::util::crypto::dh::method_t::kDh));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.init(cli_shctx));
    }

    std::vector<unsigned char> switch_params;
    std::vector<unsigned char> switch_public;
    std::vector<unsigned char> cli_secret;
    std::vector<unsigned char> svr_secret;

    // step 1 - server: make private key and public key
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.make_params(switch_params));

    // step 2 - client: read dhparam and public key of server
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                   cli_dh.read_params(switch_params.data(), switch_params.size()));

    // step 3 - client: make public key
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.make_public(switch_public));

    // step 4 - client: calculate secret
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.calc_secret(cli_secret));

    // step 5 - server: read public key of client
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                   svr_dh.read_public(switch_public.data(), switch_public.size()));

    // step 6 - server: calculate secret
    CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.calc_secret(svr_secret));

    // DH process done
    CASE_EXPECT_EQ(cli_secret.size(), svr_secret.size());
    if (cli_secret.size() == svr_secret.size()) {
      CASE_EXPECT_EQ(0, memcmp(cli_secret.data(), svr_secret.data(), svr_secret.size()));
    }
    CASE_EXPECT_GT(cli_secret.size(), 0);
    key_bits = cli_secret.size();
  }

  CASE_MSG_INFO() << "Test DH algorithm " << test_times << " times, key len " << key_bits << " bits. " << std::endl;
}
#  endif

CASE_TEST(crypto_dh, ecdh) {
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
  if (!openssl_test_inited_for_dh) {
    openssl_test_inited_for_dh = std::make_shared<openssl_test_init_wrapper_for_dh>();
  }
#  endif

  int test_times = 16;
  // 单元测试多次以定位openssl是否内存泄漏的问题
  const std::vector<std::string> &all_curves = atfw::util::crypto::dh::get_all_curve_names();

  clock_t min_cost_clock = 0;
  clock_t max_cost_clock = 0;
  size_t min_cost_idx = 0;
  size_t min_cost_bits = 0;
  size_t max_cost_idx = 0;
  size_t max_cost_bits = 0;
  for (size_t curve_idx = 0; curve_idx < all_curves.size(); ++curve_idx) {
    CASE_MSG_INFO() << "Test ECDH algorithm " << all_curves[curve_idx] << std::endl;
    clock_t beg_time_clk = clock();
    int left_times = test_times;
    size_t secret_bits = 0;
    while (left_times-- > 0) {
      // client shared context & dh
      atfw::util::crypto::dh cli_dh;

      // server shared context & dh
      atfw::util::crypto::dh svr_dh;

      // server - init: read and setup server dh params
      {
        atfw::util::crypto::dh::shared_context::ptr_t svr_shctx = atfw::util::crypto::dh::shared_context::create();
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_shctx->init(all_curves[curve_idx].c_str()));
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.init(svr_shctx));
      }

      // client - init: read and setup client shared context
      {
        atfw::util::crypto::dh::shared_context::ptr_t cli_shctx = atfw::util::crypto::dh::shared_context::create();
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                       cli_shctx->init(atfw::util::crypto::dh::method_t::kEcdh));
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.init(cli_shctx));
      }

      std::vector<unsigned char> switch_params;
      std::vector<unsigned char> switch_public;
      std::vector<unsigned char> cli_secret;
      std::vector<unsigned char> svr_secret;

      // step 1 - server: make private key and public key
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.make_params(switch_params));

      // step 2 - client: read dhparam and public key of server
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                     cli_dh.read_params(switch_params.data(), switch_params.size()));

      // step 3 - client: make public key
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.make_public(switch_public));

      // step 4 - client: calculate secret
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, cli_dh.calc_secret(cli_secret));

      // step 5 - server: read public key of client
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                     svr_dh.read_public(switch_public.data(), switch_public.size()));

      // step 6 - server: calculate secret
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh.calc_secret(svr_secret));

      // DH process done
      CASE_EXPECT_EQ(cli_secret.size(), svr_secret.size());
      if (cli_secret.size() == svr_secret.size()) {
        CASE_EXPECT_EQ(0, memcmp(cli_secret.data(), svr_secret.data(), svr_secret.size()));
      }
      secret_bits = cli_secret.size();
      CASE_EXPECT_GT(secret_bits, 0);
    }

    clock_t end_time_clk = clock();
    if (0 == curve_idx) {
      min_cost_clock = end_time_clk - beg_time_clk;
      max_cost_clock = end_time_clk - beg_time_clk;
      min_cost_idx = 0;
      max_cost_idx = 0;
      min_cost_bits = secret_bits * 8;
      max_cost_bits = secret_bits * 8;
    } else {
      clock_t off_clk = end_time_clk - beg_time_clk;
      if (off_clk > max_cost_clock) {
        max_cost_clock = off_clk;
        max_cost_idx = curve_idx;
        max_cost_bits = secret_bits * 8;
      }
      if (off_clk < min_cost_clock) {
        min_cost_clock = off_clk;
        min_cost_idx = curve_idx;
        min_cost_bits = secret_bits * 8;
      }
    }
  }

  CASE_MSG_INFO() << "Test ECDH algorithm " << test_times << " times for " << all_curves.size() << " curves done. "
                  << std::endl;
  if (!all_curves.empty()) {
    CASE_MSG_INFO() << "  Fastest => " << all_curves[min_cost_idx] << " cost "
                    << (1000.0 * min_cost_clock / CLOCKS_PER_SEC / test_times) << "ms(avg.) key len " << min_cost_bits
                    << " bits. " << std::endl;
    CASE_MSG_INFO() << "  Slowest => " << all_curves[max_cost_idx] << " cost "
                    << (1000.0 * max_cost_clock / CLOCKS_PER_SEC / test_times) << "ms(avg.) key len " << max_cost_bits
                    << " bits. " << std::endl;
  }
}

CASE_TEST(crypto_dh, ecdh_alias_and_both_server) {
#  if defined(ATFRAMEWORK_UTILS_CRYPTO_USE_OPENSSL) || defined(ATFRAMEWORK_UTILS_CRYPTO_USE_LIBRESSL) || \
      defined(ATFRAMEWORK_UTILS_CRYPTO_USE_BORINGSSL)
  if (!openssl_test_inited_for_dh) {
    openssl_test_inited_for_dh = std::make_shared<openssl_test_init_wrapper_for_dh>();
  }
#  endif

  int test_times = 16;
  // 单元测试多次以定位openssl是否内存泄漏的问题
  std::vector<std::string> all_curves = {"ecdh:P-256", "ecdh:p-384", "ecdh:p-521", "ecdh:X25519"};

  clock_t min_cost_clock = 0;
  clock_t max_cost_clock = 0;
  size_t min_cost_idx = 0;
  size_t min_cost_bits = 0;
  size_t max_cost_idx = 0;
  size_t max_cost_bits = 0;
  for (size_t curve_idx = 0; curve_idx < all_curves.size(); ++curve_idx) {
    CASE_MSG_INFO() << "Test ECDH algorithm " << all_curves[curve_idx] << std::endl;
    clock_t beg_time_clk = clock();
    int left_times = test_times;
    size_t secret_bits = 0;
    while (left_times-- > 0) {
      // client shared context & dh
      atfw::util::crypto::dh svr_dh2;

      // server shared context & dh
      atfw::util::crypto::dh svr_dh1;

      // server - init: read and setup server dh params
      {
        atfw::util::crypto::dh::shared_context::ptr_t svr_shctx = atfw::util::crypto::dh::shared_context::create();
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_shctx->init(all_curves[curve_idx].c_str()));
        auto svr_dh1_init_result = svr_dh1.init(svr_shctx);
        if (svr_dh1_init_result != atfw::util::crypto::dh::error_code_t::kOk &&
            all_curves[curve_idx] == "ecdh:X25519") {
          break;
        }
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh1_init_result);
      }

      // client - init: read and setup client shared context
      {
        atfw::util::crypto::dh::shared_context::ptr_t svr_shctx = atfw::util::crypto::dh::shared_context::create();
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_shctx->init(all_curves[curve_idx].c_str()));
        CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh2.init(svr_shctx));
      }

      std::vector<unsigned char> switch_params;
      std::vector<unsigned char> switch_public_svr1;
      std::vector<unsigned char> switch_public_svr2;
      std::vector<unsigned char> svr1_secret;
      std::vector<unsigned char> svr2_secret;

      // step 1 - server: make private key and public key
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh1.make_params(switch_params));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh2.make_params(switch_params));

      // step 2 - server: make and export public key
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh1.make_public(switch_public_svr1));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh2.make_public(switch_public_svr2));

      // step 3 - server: read remote public
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                     svr_dh1.read_public(switch_public_svr2.data(), switch_public_svr2.size()));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk,
                     svr_dh2.read_public(switch_public_svr1.data(), switch_public_svr1.size()));

      // step 4 - client: calculate secret
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh2.calc_secret(svr2_secret));
      CASE_EXPECT_EQ(atfw::util::crypto::dh::error_code_t::kOk, svr_dh1.calc_secret(svr1_secret));

      // DH process done
      CASE_EXPECT_EQ(svr2_secret.size(), svr1_secret.size());
      if (svr2_secret.size() == svr1_secret.size()) {
        CASE_EXPECT_EQ(0, memcmp(svr2_secret.data(), svr1_secret.data(), svr1_secret.size()));
      }
      secret_bits = svr2_secret.size();
      CASE_EXPECT_GT(secret_bits, 0);
    }

    clock_t end_time_clk = clock();
    if (0 == curve_idx) {
      min_cost_clock = end_time_clk - beg_time_clk;
      max_cost_clock = end_time_clk - beg_time_clk;
      min_cost_idx = 0;
      max_cost_idx = 0;
      min_cost_bits = secret_bits * 8;
      max_cost_bits = secret_bits * 8;
    } else {
      clock_t off_clk = end_time_clk - beg_time_clk;
      if (off_clk > max_cost_clock) {
        max_cost_clock = off_clk;
        max_cost_idx = curve_idx;
        max_cost_bits = secret_bits * 8;
      }
      if (off_clk < min_cost_clock) {
        min_cost_clock = off_clk;
        min_cost_idx = curve_idx;
        min_cost_bits = secret_bits * 8;
      }
    }
  }

  CASE_MSG_INFO() << "Test ECDH algorithm " << test_times << " times for " << all_curves.size() << " curves done. "
                  << std::endl;
  if (!all_curves.empty()) {
    CASE_MSG_INFO() << "  Fastest => " << all_curves[min_cost_idx] << " cost "
                    << (1000.0 * min_cost_clock / CLOCKS_PER_SEC / test_times) << "ms(avg.) key len " << min_cost_bits
                    << " bits. " << std::endl;
    CASE_MSG_INFO() << "  Slowest => " << all_curves[max_cost_idx] << " cost "
                    << (1000.0 * max_cost_clock / CLOCKS_PER_SEC / test_times) << "ms(avg.) key len " << max_cost_bits
                    << " bits. " << std::endl;
  }
}

#endif
