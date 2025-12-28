#pragma once

// Simple logging macros - can be replaced with a proper logging framework
#include <iostream>

#define LOG_DEBUG(tag, msg) do { /* debug disabled by default */ } while(0)
#define LOG_INFO(tag, msg) do { std::cerr << "[INFO] " << msg << std::endl; } while(0)
#define LOG_WARN(tag, msg) do { std::cerr << "[WARN] " << msg << std::endl; } while(0)
#define LOG_ERROR(tag, msg) do { std::cerr << "[ERROR] " << msg << std::endl; } while(0)

// Tag names (unused in simple implementation)
#define SERVER 0
