#include "dab_tables.hpp"

namespace dvbdab {

namespace {

// TS 101 756 table 9: 0x00 to 0x2B (ISO 639-2/B)
const char* const LANGUAGES_LOW[0x2C] = {
    "",    "alb", "bre", "cat", "hrv", "wel", "cze", "dan",   // -, Albanian, Breton, Catalan, Croatian, Welsh, Czech, Danish
    "ger", "eng", "spa", "epo", "est", "baq", "fao", "fre",   // German, English, Spanish, Esperanto, Estonian, Basque, Faroese, French
    "fry", "gle", "gla", "glg", "ice", "ita", "smi", "lat",   // Frisian, Irish, Gaelic, Galician, Icelandic, Italian, Sami, Latin
    "lav", "ltz", "lit", "hun", "mlt", "dut", "nor", "oci",   // Latvian, Luxembourgian, Lithuanian, Hungarian, Maltese, Dutch, Norwegian, Occitan
    "pol", "por", "rum", "roh", "srp", "slo", "slv", "fin",   // Polish, Portuguese, Romanian, Romansh, Serbian, Slovak, Slovene, Finnish
    "swe", "tur", "dut", "wln",                               // Swedish, Turkish, Flemish, Walloon
};

// TS 101 756 table 10: 0x7F down to 0x45. Without an ISO 639-2 code of
// their own, or with two that could be meant: Dari, Ndebele, Rusyn,
// Serbo-Croat.
const char* const LANGUAGES_HIGH[0x7F - 0x45 + 1] = {
    "amh", "ara", "arm", "asm", "aze", "bam", "bel", "ben",   // Amharic, Arabic, Armenian, Assamese, Azerbaijani, Bambara, Belorussian, Bengali
    "bul", "bur", "chi", "chv", "",    "ful", "geo", "gre",   // Bulgarian, Burmese, Chinese, Chuvash, Dari, Fulani, Georgian, Greek
    "guj", "grn", "hau", "heb", "hin", "ind", "jpn", "kan",   // Gujarati, Guarani, Hausa, Hebrew, Hindi, Indonesian, Japanese, Kannada
    "kaz", "khm", "kor", "lao", "mac", "mlg", "may", "rum",   // Kazakh, Khmer, Korean, Laotian, Macedonian, Malagasy, Malaysian, Moldavian
    "mar", "",    "nep", "ori", "pap", "per", "pan", "pus",   // Marathi, Ndebele, Nepali, Oriya, Papiamento, Persian, Punjabi, Pushtu
    "que", "rus", "",    "",    "sna", "sin", "som", "srn",   // Quechua, Russian, Rusyn, Serbo-Croat, Shona, Sinhalese, Somali, Sranan Tongo
    "swa", "tgk", "tam", "tat", "tel", "tha", "ukr", "urd",   // Swahili, Tadzhik, Tamil, Tatar, Telugu, Thai, Ukrainian, Urdu
    "uzb", "vie", "zul",                                      // Uzbek, Vietnamese, Zulu
};

// TS 101 756 table 12 (international table 1) to EN 300 468 table 28
const uint8_t PTY_CONTENT[30] = {
    0x00,  //  0 no programme type
    0x20,  //  1 News                 -> news/current affairs
    0x20,  //  2 Current Affairs
    0x20,  //  3 Information
    0x40,  //  4 Sport                -> sports
    0x90,  //  5 Education            -> education/science/factual
    0x10,  //  6 Drama                -> movie/drama
    0x70,  //  7 Culture              -> arts/culture
    0x90,  //  8 Science
    0x30,  //  9 Varied               -> show/game show
    0x61,  // 10 Pop Music            -> rock/pop
    0x61,  // 11 Rock Music
    0x60,  // 12 Easy Listening Music -> music/ballet/dance
    0x62,  // 13 Light Classical      -> serious music/classical music
    0x62,  // 14 Serious Classical
    0x60,  // 15 Other Music
    0x21,  // 16 Weather              -> news/weather report
    0x80,  // 17 Finance/Business     -> social/political issues/economics
    0x50,  // 18 Children's programmes -> children's/youth programmes
    0x80,  // 19 Social Affairs
    0x73,  // 20 Religion             -> religion
    0x33,  // 21 Phone In             -> talk show
    0xA1,  // 22 Travel               -> tourism/travel
    0xA0,  // 23 Leisure              -> leisure hobbies
    0x64,  // 24 Jazz Music           -> jazz
    0x63,  // 25 Country Music        -> folk/traditional music
    0x63,  // 26 National Music
    0x60,  // 27 Oldies Music
    0x63,  // 28 Folk Music
    0x23,  // 29 Documentary          -> documentary
};

} // namespace

const char* dabLanguageIso639(uint8_t language) {
    if (language < 0x2C) return LANGUAGES_LOW[language];
    if (language >= 0x45 && language <= 0x7F) return LANGUAGES_HIGH[0x7F - language];
    return "";
}

uint8_t dabPtyToDvbContent(uint8_t pty, uint8_t international_table) {
    if (international_table != 0x01 || pty >= 30) return 0;
    return PTY_CONTENT[pty];
}

} // namespace dvbdab
