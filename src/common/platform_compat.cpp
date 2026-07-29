// Copyright 2026 atframework
//
// Created by owent on 2024-08-26.

#ifndef __STDC_WANT_LIB_EXT1__
#  define __STDC_WANT_LIB_EXT1__ 1
#endif

#if defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__CYGWIN__) || defined(_AIX) || \
    defined(__sun) || defined(__hpux)
#  define ATFRAMEWORK_UTILS_HAS_PTHREAD 1
#  if !defined(_GNU_SOURCE) && !defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)
#    define _POSIX_C_SOURCE 200112L
#  endif
#  if defined(_GNU_SOURCE) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || \
      (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)
#    define ATFRAMEWORK_UTILS_PLATFORM_HAS_STRERROR_R 1
#  endif
#endif

#include "common/platform_compat.h"

#if defined(ATFRAMEWORK_UTILS_HAS_PTHREAD) && ATFRAMEWORK_UTILS_HAS_PTHREAD
#  include <pthread.h>
#endif

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>  // IWYU pragma: keep
#include <type_traits>

namespace {

template <class TMessage>
static gsl::string_view copy_strerror_message(TMessage message, gsl::span<char> buffer) noexcept {
  if (message == nullptr) {
    return {};
  }

  const std::size_t buffer_size = static_cast<std::size_t>(buffer.size());
  std::size_t message_size = 0;
  while (message_size + 1 < buffer_size && message[message_size] != '\0') {
    ++message_size;
  }

  if (message != buffer.data()) {
    std::memmove(buffer.data(), message, message_size);
  }
  buffer.data()[message_size] = '\0';
  return gsl::string_view{buffer.data(), message_size};
}

template <class TResult>
static gsl::string_view handle_strerror_r_result(TResult result, gsl::span<char> buffer, std::true_type) noexcept {
  (void)result;
  return copy_strerror_message(buffer.data(), buffer);
}

template <class TResult>
static gsl::string_view handle_strerror_r_result(TResult result, gsl::span<char> buffer, std::false_type) noexcept {
  return copy_strerror_message(result, buffer);
}

template <class TResult>
static gsl::string_view handle_strerror_r_result(TResult result, gsl::span<char> buffer) noexcept {
  return handle_strerror_r_result(result, buffer, typename std::is_integral<TResult>::type{});
}

}  // namespace

ATFRAMEWORK_UTILS_NAMESPACE_BEGIN
namespace platform {

ATFRAMEWORK_UTILS_API int32_t get_errno() noexcept { return errno; }

ATFRAMEWORK_UTILS_API gsl::string_view get_strerrno(int32_t result_from_get_errno, gsl::span<char> buffer) noexcept {
  if (buffer.empty()) {
    return {};
  }
  *buffer.data() = '\0';
  if (buffer.size() == 1) {
    return {};
  }
  buffer.data()[buffer.size() - 1] = '\0';

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__) || defined(__STDC_LIB_EXT1__)
  const int strerror_result =
      ::strerror_s(buffer.data(), static_cast<std::size_t>(buffer.size()), result_from_get_errno);
  if (strerror_result != 0 && *buffer.data() == '\0') {
    return {};
  }
  return copy_strerror_message(buffer.data(), buffer);
#elif defined(ATFRAMEWORK_UTILS_PLATFORM_HAS_STRERROR_R)
  return handle_strerror_r_result(
      ::strerror_r(result_from_get_errno, buffer.data(), static_cast<std::size_t>(buffer.size())), buffer);
#else
  return copy_strerror_message(std::strerror(result_from_get_errno), buffer);
#endif
}

ATFRAMEWORK_UTILS_API int32_t atfork(void (*prepare)(), void (*parent)(), void (*child)()) noexcept {
#if defined(ATFRAMEWORK_UTILS_HAS_PTHREAD) && ATFRAMEWORK_UTILS_HAS_PTHREAD
  return ::pthread_atfork(prepare, parent, child);
#else
  (void)prepare;
  (void)parent;
  (void)child;
  return 0;
#endif
}

}  // namespace platform
ATFRAMEWORK_UTILS_NAMESPACE_END
