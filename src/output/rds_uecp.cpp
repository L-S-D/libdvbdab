// RDS RadioText in UECP frames (IEC 62106-10)

#include "rds_uecp.hpp"
#include "charsets.hpp"

namespace dvbdab {

namespace {

constexpr uint8_t UECP_STA = 0xFE;   // start of a frame
constexpr uint8_t UECP_STP = 0xFF;   // its end
constexpr uint8_t UECP_STUFF = 0xFD; // FD, FE, FF inside a frame: FD 00, FD 01, FD 02
constexpr uint8_t MEC_RT = 0x0A;     // RadioText

// CRC of a UECP frame: CCITT (x^16 + x^12 + x^5 + 1), preset to ones, inverted,
// over address, sequence counter, message field length and message field
uint16_t crc16(const std::vector<uint8_t>& data) {
    uint16_t crc = 0xFFFF;
    for (uint8_t d : data) {
        crc ^= static_cast<uint16_t>(d << 8);
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021) : static_cast<uint16_t>(crc << 1);
    }
    return static_cast<uint16_t>(~crc);
}

} // namespace

std::string rdsRadioText(const std::string& utf8) {
    std::string rds = utf8ToRds(utf8);
    if (rds.size() > RDS_RT_MAX) {
        size_t cut = rds.rfind(' ', RDS_RT_MAX);
        rds.resize(cut != std::string::npos && cut >= RDS_RT_MAX / 2 ? cut : RDS_RT_MAX);
    }
    while (!rds.empty() && rds.back() == ' ') rds.pop_back();
    return rds;
}

std::vector<uint8_t> uecpRadioTextFrame(const std::string& rds_text, bool ab_flag) {
    // message element: MEC, data set number, programme service number, message
    // element length, then the RadioText configuration (buffer configuration
    // 00 = this text alone, number of transmissions 0, A/B flag) and the text
    std::vector<uint8_t> body = {0x00, 0x00,  // address: all sites and encoders
                                 0x00};       // sequence counter: not used
    std::vector<uint8_t> msg = {MEC_RT, 0x00, 0x00, static_cast<uint8_t>(1 + rds_text.size()),
                                static_cast<uint8_t>(ab_flag ? 0x01 : 0x00)};
    msg.insert(msg.end(), rds_text.begin(), rds_text.end());
    body.push_back(static_cast<uint8_t>(msg.size()));
    body.insert(body.end(), msg.begin(), msg.end());
    uint16_t crc = crc16(body);
    body.push_back(static_cast<uint8_t>(crc >> 8));
    body.push_back(static_cast<uint8_t>(crc));

    std::vector<uint8_t> frame = {UECP_STA};
    for (uint8_t b : body) {
        if (b >= UECP_STUFF) {
            frame.push_back(UECP_STUFF);
            frame.push_back(static_cast<uint8_t>(b - UECP_STUFF));
        } else {
            frame.push_back(b);
        }
    }
    frame.push_back(UECP_STP);
    return frame;
}

} // namespace dvbdab
