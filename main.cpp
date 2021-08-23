#include <rpm/rpmio.h>
#include <rpm/header.h>
#include <rpm/rpmlib.h>
#include <memory>
#include <iostream>
#include <openssl/sha.h>
#include <fstream>

#define sha256rpm_static static

sha256rpm_static int char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;

  throw std::invalid_argument("Invalid input string");
}

sha256rpm_static int parseVFile(const std::string& vfile, unsigned char* h, std::string* ftv) {
    std::ifstream infile(vfile);
    char ch, pch;
    int h_idx = 0;

    memset(h, 0, SHA256_DIGEST_LENGTH);

    while (infile >> std::noskipws >> ch) {
        if (h_idx > 0 && h_idx % 2 == 1)
            h[h_idx>>1] = char2int(pch)<<4 | char2int(ch);
        h_idx++;
        pch = ch;

        if (h_idx>=SHA256_DIGEST_LENGTH*2)
            break;
    }
    if (h_idx != SHA256_DIGEST_LENGTH*2)
        return 8;
    // now skip the space
    while (infile >> std::noskipws >> ch) {
        if (!std::isspace(ch))
            break;
    }

    if (!std::getline(infile, *ftv))
        return 9;
    *ftv = ch + *ftv;

    return 0;
}

sha256rpm_static void dump(const uint8_t* hash) {
    const char * hex = "0123456789abcdef";
    for (int idx=0;idx<SHA256_DIGEST_LENGTH;++idx) {
        std::cout << hex[(hash[idx] >> 4) & 0x0f];
        std::cout << hex[hash[idx]        & 0x0f];
    }
}


int main(int argc, char *argv[]) {

    std::string rpmFile;
    bool show_hash_only = false;
    bool no_newline = false;
    bool verify_mode = false;
    unsigned char hash_to_verify[SHA256_DIGEST_LENGTH];
    std::string file_to_verify;

    if (argc==1) { // no args
        std::cout << "Usage: \n";
        std::cout << "    sha256rpm [options] <rpm_binary/file_to_verify> - calculates the sha256\n";
        std::cout << "Options:\n";
        std::cout << "    -x\tshow hash only\n";
        std::cout << "    -q\tno newline at the end (also quiet when verifying)\n";
        std::cout << "    -v\tverify the hash\n";
        return 7;
    } else {
        for (int idx=0;idx<argc-1;++idx) {
            if (std::string(argv[idx]) == "-x")
                show_hash_only = true;
            else if (std::string(argv[idx]) == "-q")
                no_newline = true;
            else if (std::string(argv[idx]) == "-v")
                verify_mode = true;
        }
        rpmFile = argv[argc-1];
    }

    if (verify_mode) {
        int ret = 0;
        if ((ret = parseVFile(rpmFile, hash_to_verify, &rpmFile))!=0)
            return ret;
    }

    FD_t f = Fopen(rpmFile.c_str(), "r");
    if (!f) {
        std::cerr << "failed to open afu\n";
        return 1;
    }
    auto deleter = [](FD_t* p) { Fclose(*p); };
    std::unique_ptr<FD_t, decltype(deleter)> au(&f, deleter);

    Header rh;
    rpmRC ret = rpmReadPackageFile(0, f, "afu", &rh);
    if (ret != RPMRC_OK) {
        std::cerr << "failed to read package file\n";
        return 2;
    }
    if (!rh) {
        std::cerr << "invalid header\n";
        return 3;
    }

    auto headerDeleter = [](Header* hdr) { headerFree(*hdr); };
    std::unique_ptr<Header, decltype (headerDeleter)> auHD(&rh, headerDeleter);

    HeaderIterator iter;
    iter = headerInitIterator(rh);

    if (!iter) {
        std::cerr << "invalid iterator\n";
        return 4;
    }

    auto iteratorDeleter = [](HeaderIterator* iter) {headerFreeIterator(*iter); };
    std::unique_ptr<HeaderIterator, decltype (iteratorDeleter)> auHI(&iter, iteratorDeleter);

    rpmtd td = rpmtdNew();
    if (!td) {
        std::cerr << "invalid td\n";
        return 5;
    }

    auto rpmtdDeleter = [](rpmtd* t) {rpmtdFree(*t);};
    std::unique_ptr<rpmtd, decltype (rpmtdDeleter)> auRtD(&td, rpmtdDeleter);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    if (!SHA256_Init(&sha256)) {
        std::cerr << "failed to initialize sha256 context\n";
        return 6;
    }

    while (headerNext(iter, td)) {
        if (td->tag == RPMTAG_FILESIZES) {
            int32_t* pd = reinterpret_cast<int32_t*>(td->data);
            for (int idx=0;idx<td->count;++idx) {
                SHA256_Update(&sha256, pd, sizeof(*pd));
            }
        } else if (td->tag == RPMTAG_FILEDIGESTS) {
            const char* pstr = nullptr;
            while ((pstr = rpmtdNextString(td))) {
                if (pstr && pstr[0]) {
                    SHA256_Update(&sha256, pstr, strlen(pstr));
                }
            }
        }
    }

    SHA256_Final(hash, &sha256);

    if (verify_mode) {
        // check the final hash
        if (!no_newline)
            dump(hash_to_verify);
        if (memcmp(hash, hash_to_verify, SHA256_DIGEST_LENGTH)!=0) {
            if (!no_newline)
                std::cout <<" "<<rpmFile<< " [FAIL]\n";
            return 1;
        } else {
            if (!no_newline)
                std::cout <<" "<<rpmFile<< " [OK]\n";
        }
        return 0;
    }

    dump(hash);

    if (show_hash_only)
        return 0;
    std::cout << " "<<rpmFile;
    if (no_newline)
        return 0;
    std::cout << '\n';
    return 0;
}
