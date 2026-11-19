#pragma once
/**
 * @file spi_si_parser.hpp
 * @brief The service information file of a DAB programme guide (SPI), binary
 *        (ETSI TS 102 371): which logos the services of an ensemble have
 *
 * The file names the logos by the ContentName of the MOT objects that carry
 * them in the same carousel.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dvbdab {

/// A logo of a service as the service information says it
struct SpiLogo {
    uint32_t sid{0};      ///< service (of a bearer in the dab: domain)
    uint8_t ecc{0};       ///< country and ensemble of that bearer
    uint16_t eid{0};
    std::string url;      ///< ContentName of the MOT object with the image
    uint8_t type{0};      ///< 2 logo_unrestricted, 4 logo_colour_square (32x32), 6 logo_colour_rectangle (112x32); 0 = not said
    uint16_t width{0};    ///< as the file says it, 0 = not said
    uint16_t height{0};
};

/// What a service information file says
struct SpiServiceInfo {
    bool has_ensemble{false};
    uint8_t ecc{0};       ///< of the ensemble element
    uint16_t eid{0};
    std::vector<SpiLogo> logos;   ///< one per logo and bearer of its service
};

/// Reads a binary service information file (top-level element 0x03). False
/// for another file or one that is not well formed; elements and attributes
/// that are not known are skipped.
bool parseSpiServiceInformation(const uint8_t* data, size_t len, SpiServiceInfo& out);

/// What an image file is, from its first bytes: "image/png" or "image/jpeg"
/// with its size in pixels (0 when the file does not get as far as saying
/// it); nullptr for anything else.
const char* imageFileInfo(const uint8_t* data, size_t len, int& width, int& height);

} // namespace dvbdab
