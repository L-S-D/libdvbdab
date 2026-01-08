#pragma once
// Callback-based logging system for libdvbdab
// Allows integration with external logging systems (e.g., tvheadend)

#include <cstdarg>

namespace dvbdab {

// Log levels (matching typical logging frameworks)
enum class LogLevel {
    ERROR = 0,
    WARN  = 1,
    INFO  = 2,
    DEBUG = 3,
    TRACE = 4
};

// Log callback signature: level, tag, message
using LogCallback = void(*)(LogLevel level, const char* tag, const char* message);

// Set the log callback (nullptr = use default stderr output)
void set_log_callback(LogCallback callback);

// Set minimum log level (messages below this level are filtered)
void set_log_level(LogLevel level);

// Get current log level
LogLevel get_log_level();

// Internal logging function (use macros below)
void log_message(LogLevel level, const char* tag, const char* fmt, ...);

// Check if a level would be logged (for expensive debug computations)
bool should_log(LogLevel level);

} // namespace dvbdab

// C API for setting callback (for use from C code or tvheadend)
extern "C" {
    typedef void(*dvbdab_log_callback_t)(int level, const char* tag, const char* message);
    void dvbdab_set_log_callback(dvbdab_log_callback_t callback);
    void dvbdab_set_log_level(int level);
}

// Logging macros - use these in code
// Tag is typically the component name (e.g., "DABPLUS", "PAD", "MUXER")

#define LOG_ERROR(tag, msg) \
    do { if (dvbdab::should_log(dvbdab::LogLevel::ERROR)) { \
        std::ostringstream _oss; _oss << msg; \
        dvbdab::log_message(dvbdab::LogLevel::ERROR, #tag, "%s", _oss.str().c_str()); \
    }} while(0)

#define LOG_WARN(tag, msg) \
    do { if (dvbdab::should_log(dvbdab::LogLevel::WARN)) { \
        std::ostringstream _oss; _oss << msg; \
        dvbdab::log_message(dvbdab::LogLevel::WARN, #tag, "%s", _oss.str().c_str()); \
    }} while(0)

#define LOG_INFO(tag, msg) \
    do { if (dvbdab::should_log(dvbdab::LogLevel::INFO)) { \
        std::ostringstream _oss; _oss << msg; \
        dvbdab::log_message(dvbdab::LogLevel::INFO, #tag, "%s", _oss.str().c_str()); \
    }} while(0)

#define LOG_DEBUG(tag, msg) \
    do { if (dvbdab::should_log(dvbdab::LogLevel::DEBUG)) { \
        std::ostringstream _oss; _oss << msg; \
        dvbdab::log_message(dvbdab::LogLevel::DEBUG, #tag, "%s", _oss.str().c_str()); \
    }} while(0)

#define LOG_TRACE(tag, msg) \
    do { if (dvbdab::should_log(dvbdab::LogLevel::TRACE)) { \
        std::ostringstream _oss; _oss << msg; \
        dvbdab::log_message(dvbdab::LogLevel::TRACE, #tag, "%s", _oss.str().c_str()); \
    }} while(0)

// Include sstream for the macros
#include <sstream>
