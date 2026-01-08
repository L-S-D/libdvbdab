// Callback-based logging implementation for libdvbdab

#include "logging.h"
#include <cstdio>
#include <cstdarg>
#include <atomic>

namespace dvbdab {

// Global state
static LogCallback g_callback = nullptr;
static std::atomic<LogLevel> g_level{LogLevel::INFO};  // Default: INFO and above

// Level names for default output
static const char* level_names[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

void set_log_callback(LogCallback callback) {
    g_callback = callback;
}

void set_log_level(LogLevel level) {
    g_level.store(level, std::memory_order_relaxed);
}

LogLevel get_log_level() {
    return g_level.load(std::memory_order_relaxed);
}

bool should_log(LogLevel level) {
    return static_cast<int>(level) <= static_cast<int>(g_level.load(std::memory_order_relaxed));
}

void log_message(LogLevel level, const char* tag, const char* fmt, ...) {
    // Early exit if level is filtered
    if (!should_log(level)) return;

    // Format the message
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    if (g_callback) {
        // Use external callback
        g_callback(level, tag, buffer);
    } else {
        // Default: stderr output
        int lvl = static_cast<int>(level);
        if (lvl >= 0 && lvl <= 4) {
            fprintf(stderr, "[%s] [%s] %s\n", level_names[lvl], tag, buffer);
        } else {
            fprintf(stderr, "[?] [%s] %s\n", tag, buffer);
        }
    }
}

} // namespace dvbdab

// C API implementation
extern "C" {

// Adapter to convert C callback to C++ callback
static dvbdab_log_callback_t g_c_callback = nullptr;

static void c_callback_adapter(dvbdab::LogLevel level, const char* tag, const char* message) {
    if (g_c_callback) {
        g_c_callback(static_cast<int>(level), tag, message);
    }
}

void dvbdab_set_log_callback(dvbdab_log_callback_t callback) {
    g_c_callback = callback;
    if (callback) {
        dvbdab::set_log_callback(c_callback_adapter);
    } else {
        dvbdab::set_log_callback(nullptr);
    }
}

void dvbdab_set_log_level(int level) {
    if (level >= 0 && level <= 4) {
        dvbdab::set_log_level(static_cast<dvbdab::LogLevel>(level));
    }
}

} // extern "C"
