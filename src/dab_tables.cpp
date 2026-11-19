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

// ISO 639-1 to ISO 639-2/B: the languages of the two tables above that have
// a code of two letters
const char* const ISO639_1_TO_2[][2] = {
    {"sq", "alb"}, {"br", "bre"}, {"ca", "cat"}, {"hr", "hrv"}, {"cy", "wel"}, {"cs", "cze"}, {"da", "dan"},
    {"de", "ger"}, {"en", "eng"}, {"es", "spa"}, {"eo", "epo"}, {"et", "est"}, {"eu", "baq"}, {"fo", "fao"},
    {"fr", "fre"}, {"fy", "fry"}, {"ga", "gle"}, {"gd", "gla"}, {"gl", "glg"}, {"is", "ice"}, {"it", "ita"},
    {"se", "sme"}, {"la", "lat"}, {"lv", "lav"}, {"lb", "ltz"}, {"lt", "lit"}, {"hu", "hun"}, {"mt", "mlt"},
    {"nl", "dut"}, {"no", "nor"}, {"nb", "nob"}, {"nn", "nno"}, {"oc", "oci"}, {"pl", "pol"}, {"pt", "por"},
    {"ro", "rum"}, {"rm", "roh"}, {"sr", "srp"}, {"sk", "slo"}, {"sl", "slv"}, {"fi", "fin"}, {"sv", "swe"},
    {"tr", "tur"}, {"wa", "wln"}, {"am", "amh"}, {"ar", "ara"}, {"hy", "arm"}, {"as", "asm"}, {"az", "aze"},
    {"bm", "bam"}, {"be", "bel"}, {"bn", "ben"}, {"bg", "bul"}, {"my", "bur"}, {"zh", "chi"}, {"cv", "chv"},
    {"ff", "ful"}, {"ka", "geo"}, {"el", "gre"}, {"gu", "guj"}, {"gn", "grn"}, {"ha", "hau"}, {"he", "heb"},
    {"hi", "hin"}, {"id", "ind"}, {"ja", "jpn"}, {"kn", "kan"}, {"kk", "kaz"}, {"km", "khm"}, {"ko", "kor"},
    {"lo", "lao"}, {"mk", "mac"}, {"mg", "mlg"}, {"ms", "may"}, {"mr", "mar"}, {"ne", "nep"}, {"or", "ori"},
    {"fa", "per"}, {"pa", "pan"}, {"ps", "pus"}, {"qu", "que"}, {"ru", "rus"}, {"sn", "sna"}, {"si", "sin"},
    {"so", "som"}, {"sw", "swa"}, {"tg", "tgk"}, {"ta", "tam"}, {"tt", "tat"}, {"te", "tel"}, {"th", "tha"},
    {"uk", "ukr"}, {"ur", "urd"}, {"uz", "uzb"}, {"vi", "vie"}, {"zu", "zul"},
};

} // namespace

std::string iso639ForDvb(const std::string& language) {
    if (language.size() == 3) return language;
    if (language.size() == 2) {
        for (const auto& pair : ISO639_1_TO_2) {
            if (language == pair[0]) return pair[1];
        }
    }
    return "";
}

const char* dabLanguageIso639(uint8_t language) {
    if (language < 0x2C) return LANGUAGES_LOW[language];
    if (language >= 0x45 && language <= 0x7F) return LANGUAGES_HIGH[0x7F - language];
    return "";
}

uint8_t dabPtyToDvbContent(uint8_t pty, uint8_t international_table) {
    if (international_table != 0x01 || pty >= 30) return 0;
    return PTY_CONTENT[pty];
}

AacSignalling dabPlusAacSignalling(bool sbr, bool ps, bool stereo) {
    if (sbr && ps) return {0x30, 0x43};          // HE AAC v2 profile level 2; HE AAC v2 audio, stereo
    uint8_t type = stereo ? 0x03 : 0x01;         // HE AAC audio, stereo / single mono channel
    if (sbr) return {0x2C, type};                // HE AAC profile level 2
    return {AAC_PROFILE_LC_L2, type};            // AAC profile level 2
}

} // namespace dvbdab
