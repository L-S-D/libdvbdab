// A main() for the fuzz harnesses when they are not linked with libFuzzer
// (GCC has none): it runs LLVMFuzzerTestOneInput() on files, and makes new
// inputs itself by simple mutations of them - enough to replay findings, to
// run the seeds with every ctest, and to fuzz a little without clang.
//
//   fuzz_x [-runs=N] [-seed=S] [-max_len=L] [file or directory ...]
//
// Every file is run once; with -runs=N, N more inputs follow, each a
// mutation of one of the files (or of nothing). The same seed gives the same
// inputs. When the harness dies under a sanitizer, the input it died on is
// written to ./crash-input.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" void __sanitizer_set_death_callback(void (*)(void)) __attribute__((weak));

namespace {

using Bytes = std::vector<uint8_t>;

Bytes g_current;

void dump_current() {
    FILE* f = fopen("crash-input", "wb");
    if (!f) return;
    fwrite(g_current.data(), 1, g_current.size(), f);
    fclose(f);
    fprintf(stderr, "standalone: the input (%zu bytes) is in ./crash-input\n", g_current.size());
}

uint64_t g_state = 1;
uint64_t rnd() {
    g_state ^= g_state << 13;
    g_state ^= g_state >> 7;
    g_state ^= g_state << 17;
    return g_state;
}

bool read_file(const std::string& path, Bytes& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    out.clear();
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    fclose(f);
    return true;
}

void collect(const std::string& path, std::vector<Bytes>& corpus) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        fprintf(stderr, "standalone: cannot read %s\n", path.c_str());
        exit(2);
    }
    if (S_ISDIR(st.st_mode)) {
        DIR* d = opendir(path.c_str());
        if (!d) return;
        std::vector<std::string> names;
        while (dirent* e = readdir(d))
            if (e->d_name[0] != '.') names.push_back(e->d_name);
        closedir(d);
        // the order of readdir() is not the same everywhere
        for (size_t i = 0; i < names.size(); i++)
            for (size_t j = i + 1; j < names.size(); j++)
                if (names[j] < names[i]) names[i].swap(names[j]);
        for (const auto& n : names) collect(path + "/" + n, corpus);
        return;
    }
    Bytes b;
    if (read_file(path, b)) corpus.push_back(std::move(b));
}

void mutate(Bytes& b, const std::vector<Bytes>& corpus, size_t max_len) {
    int n = 1 + static_cast<int>(rnd() % 6);
    for (int i = 0; i < n; i++) {
        switch (rnd() % 9) {
        case 0:  // flip a bit
            if (!b.empty()) b[rnd() % b.size()] ^= static_cast<uint8_t>(1u << (rnd() % 8));
            break;
        case 1:  // a byte of any value
            if (!b.empty()) b[rnd() % b.size()] = static_cast<uint8_t>(rnd());
            break;
        case 2:  // a byte at an edge of its range
            if (!b.empty()) {
                static const uint8_t edge[] = {0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF};
                b[rnd() % b.size()] = edge[rnd() % sizeof(edge)];
            }
            break;
        case 3:  // cut the end off
            if (!b.empty()) b.resize(rnd() % b.size());
            break;
        case 4: {  // take a piece out
            if (b.size() < 2) break;
            size_t at = rnd() % b.size(), len = 1 + rnd() % (b.size() - at);
            b.erase(b.begin() + at, b.begin() + at + len);
            break;
        }
        case 5: {  // put random bytes in
            size_t at = b.empty() ? 0 : rnd() % (b.size() + 1), len = 1 + rnd() % 16;
            Bytes ins(len);
            for (auto& x : ins) x = static_cast<uint8_t>(rnd());
            b.insert(b.begin() + at, ins.begin(), ins.end());
            break;
        }
        case 6: {  // a piece again somewhere else
            if (b.size() < 2) break;
            size_t from = rnd() % b.size(), len = 1 + rnd() % (b.size() - from), to = rnd() % (b.size() + 1);
            Bytes piece(b.begin() + from, b.begin() + from + len);
            b.insert(b.begin() + to, piece.begin(), piece.end());
            break;
        }
        case 7: {  // a piece of another input
            if (corpus.empty()) break;
            const Bytes& o = corpus[rnd() % corpus.size()];
            if (o.empty()) break;
            size_t from = rnd() % o.size(), len = 1 + rnd() % (o.size() - from), to = b.empty() ? 0 : rnd() % (b.size() + 1);
            b.insert(b.begin() + to, o.begin() + from, o.begin() + from + len);
            break;
        }
        default: {  // a number of two bytes, big endian, at an edge
            if (b.size() < 2) break;
            static const uint16_t edge[] = {0, 1, 0x00FF, 0x0100, 0x3FFF, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF};
            size_t at = rnd() % (b.size() - 1);
            uint16_t v = edge[rnd() % (sizeof(edge) / sizeof(edge[0]))];
            b[at] = v >> 8;
            b[at + 1] = v & 0xFF;
            break;
        }
        }
    }
    if (b.size() > max_len) b.resize(max_len);
}

void run(const Bytes& b) {
    g_current = b;
    // from a block of exactly the size: a sanitizer sees a read behind it
    uint8_t* copy = static_cast<uint8_t*>(malloc(b.size() ? b.size() : 1));
    if (!b.empty()) memcpy(copy, b.data(), b.size());
    LLVMFuzzerTestOneInput(copy, b.size());
    free(copy);
}

} // namespace

int main(int argc, char** argv) {
    long runs = 0;
    size_t max_len = 65536;
    std::vector<Bytes> corpus;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-runs=", 6)) runs = atol(argv[i] + 6);
        else if (!strncmp(argv[i], "-seed=", 6)) g_state = strtoull(argv[i] + 6, nullptr, 10) * 0x9E3779B97F4A7C15ull + 1;
        else if (!strncmp(argv[i], "-max_len=", 9)) max_len = strtoul(argv[i] + 9, nullptr, 10);
        else if (argv[i][0] == '-') {
            fprintf(stderr, "usage: %s [-runs=N] [-seed=S] [-max_len=L] [file or directory ...]\n", argv[0]);
            return 2;
        } else collect(argv[i], corpus);
    }
    if (__sanitizer_set_death_callback) __sanitizer_set_death_callback(dump_current);

    for (const auto& b : corpus) run(b);
    for (long r = 0; r < runs; r++) {
        Bytes b;
        if (!corpus.empty() && rnd() % 16) b = corpus[rnd() % corpus.size()];
        mutate(b, corpus, max_len);
        run(b);
    }
    printf("%zu files, %ld mutated inputs: done\n", corpus.size(), runs);
    return 0;
}
