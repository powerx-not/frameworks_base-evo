/*
 * Copyright (C) 2026
 *
 * Licensed under the Apache License, Version 2.0
 */

#include "truebackup_archive.h"

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

namespace truebackup {
namespace {

constexpr size_t kBufferSize = 8192;
constexpr size_t kKeySize = 32;
constexpr size_t kIvSize = 16;
constexpr size_t kSaltSize = 8;
constexpr int kPbkdf2Iter = 100000;
constexpr uint8_t kEncMagic[4] = {'T', 'B', 'K', '2'};
constexpr size_t kTarBlock = 512;

static bool IsDotOrDotDot(const char* name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static bool IsPathTraversal(const std::string& entryName) {
    if (entryName.empty() || entryName[0] == '/') return true;
    if (entryName.find("..") == std::string::npos) return false;
    size_t start = 0;
    while (start < entryName.size()) {
        size_t end = entryName.find('/', start);
        if (end == std::string::npos) end = entryName.size();
        if (entryName.substr(start, end - start) == "..") return true;
        start = end + 1;
    }
    return false;
}

static bool ShouldSkipForBackupClass(BackupPathClass cls, const std::string& relPrefix,
                                     const std::string& name) {
    if (name.empty()) return false;
    if (cls == BackupPathClass::kUserData && relPrefix.empty()) {
        return name == ".ota" || name == "cache" || name == "lib" || name == "code_cache"
                || name == "no_backup";
    }
    if (cls == BackupPathClass::kSharedAndroid) {
        if (relPrefix.empty() && name == "cache") return true;
        if (android::base::StartsWith(name, "Backup_")) return true;
    }
    return false;
}

static bool DeriveKey(const std::string& password, const uint8_t* salt, uint8_t* key) {
    return PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt,
                             kSaltSize, kPbkdf2Iter, EVP_sha256(), static_cast<int>(kKeySize),
                             key) == 1;
}

static std::string Dirname(const std::string& path) {
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

static bool EnsureDir(const std::string& path, mode_t mode = 0755) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    std::string parent = Dirname(path);
    if (parent != path && parent != "." && parent != "/") {
        if (!EnsureDir(parent, mode)) return false;
    }
    if (mkdir(path.c_str(), mode) == 0) return true;
    return errno == EEXIST;
}

// --- ustar tar helpers ---

struct TarHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

static void OctalField(char* dst, size_t len, uint64_t value) {
    snprintf(dst, len, "%0*lo", static_cast<int>(len - 1), static_cast<unsigned long>(value));
}

static uint32_t TarChecksum(const TarHeader& hdr) {
    const auto* p = reinterpret_cast<const unsigned char*>(&hdr);
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(TarHeader); ++i) {
        sum += (i >= offsetof(TarHeader, chksum) && i < offsetof(TarHeader, chksum) + 8) ? ' '
                                                                                          : p[i];
    }
    return sum;
}

static bool WriteTarBlock(FILE* out, const void* block) {
    return fwrite(block, 1, kTarBlock, out) == kTarBlock;
}

static bool WriteTarPadding(FILE* out, uint64_t size) {
    const uint64_t rem = size % kTarBlock;
    if (rem == 0) return true;
    static const char zero[kTarBlock] = {};
    return fwrite(zero, 1, kTarBlock - rem, out) == (kTarBlock - rem);
}

static bool WriteTarHeader(FILE* out, const std::string& path, char typeflag, uint64_t size,
                           mode_t mode) {
    TarHeader hdr{};
    const size_t fullLen = path.size();
    if (fullLen > 256) {
        LOG(ERROR) << "tar path too long: " << path;
        return false;
    }
    if (fullLen <= 100) {
        memcpy(hdr.name, path.c_str(), fullLen);
    } else {
        const size_t split = fullLen - 100;
        if (split > 155) {
            LOG(ERROR) << "tar path too long for ustar prefix: " << path;
            return false;
        }
        memcpy(hdr.prefix, path.c_str(), split);
        memcpy(hdr.name, path.c_str() + split, 100);
    }
    OctalField(hdr.mode, sizeof(hdr.mode), mode & 07777);
    OctalField(hdr.uid, sizeof(hdr.uid), 0);
    OctalField(hdr.gid, sizeof(hdr.gid), 0);
    OctalField(hdr.size, sizeof(hdr.size), size);
    OctalField(hdr.mtime, sizeof(hdr.mtime), 0);
    hdr.typeflag = typeflag;
    memcpy(hdr.magic, "ustar", 5);
    memcpy(hdr.version, "00", 2);
    snprintf(hdr.chksum, sizeof(hdr.chksum), "%06o", TarChecksum(hdr));
    hdr.chksum[7] = ' ';
    return WriteTarBlock(out, &hdr);
}

static bool WriteTarEnd(FILE* out) {
    static const char zero[kTarBlock * 2] = {};
    return fwrite(zero, 1, sizeof(zero), out) == sizeof(zero);
}

static bool TarAddFile(FILE* out, const std::string& absPath, const std::string& relPath) {
    android::base::unique_fd fd(open(absPath.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) {
        PLOG(ERROR) << "open failed: " << absPath;
        return false;
    }
    struct stat st;
    if (fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG(ERROR) << "not a regular file: " << absPath;
        return false;
    }
    if (!WriteTarHeader(out, relPath, '0', static_cast<uint64_t>(st.st_size), st.st_mode)) {
        return false;
    }
    std::vector<char> buf(kBufferSize);
    uint64_t remaining = static_cast<uint64_t>(st.st_size);
    while (remaining > 0) {
        ssize_t n = read(fd.get(), buf.data(), std::min(buf.size(), static_cast<size_t>(remaining)));
        if (n < 0) {
            if (errno == EINTR) continue;
            PLOG(ERROR) << "read failed: " << absPath;
            return false;
        }
        if (n == 0) break;
        if (fwrite(buf.data(), 1, static_cast<size_t>(n), out) != static_cast<size_t>(n)) {
            return false;
        }
        remaining -= static_cast<uint64_t>(n);
    }
    return WriteTarPadding(out, static_cast<uint64_t>(st.st_size));
}

static bool TarDirInternal(FILE* out, const std::string& current, const std::string& relPrefix,
                           BackupPathClass pathClass) {
    DIR* dir = opendir(current.c_str());
    if (!dir) {
        PLOG(ERROR) << "opendir failed: " << current;
        return false;
    }
    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        std::string childAbs = current + "/" + de->d_name;
        struct stat st;
        if (lstat(childAbs.c_str(), &st) != 0) {
            PLOG(ERROR) << "lstat failed: " << childAbs;
            closedir(dir);
            return false;
        }
        if (S_ISLNK(st.st_mode)) continue;
        if (ShouldSkipForBackupClass(pathClass, relPrefix, de->d_name)) continue;

        std::string childRel =
                relPrefix.empty() ? std::string(de->d_name) : (relPrefix + "/" + de->d_name);

        if (S_ISDIR(st.st_mode)) {
            std::string dirPath = childRel;
            if (!android::base::EndsWith(dirPath, "/")) dirPath += "/";
            if (!WriteTarHeader(out, dirPath, '5', 0, st.st_mode)) {
                closedir(dir);
                return false;
            }
            if (!TarDirInternal(out, childAbs, childRel, pathClass)) {
                closedir(dir);
                return false;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (!TarAddFile(out, childAbs, childRel)) {
                closedir(dir);
                return false;
            }
        }
    }
    closedir(dir);
    return true;
}

static bool ReadTarHeader(FILE* in, TarHeader* hdr) {
    if (fread(hdr, 1, kTarBlock, in) != kTarBlock) return false;
    bool allZero = true;
    const auto* p = reinterpret_cast<const unsigned char*>(hdr);
    for (size_t i = 0; i < kTarBlock; ++i) {
        if (p[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) return false;
    return true;
}

static std::string TarEntryPath(const TarHeader& hdr) {
    std::string path;
    if (hdr.prefix[0] != '\0') {
        path.assign(hdr.prefix, strnlen(hdr.prefix, sizeof(hdr.prefix)));
        path += "/";
    }
    path.append(hdr.name, strnlen(hdr.name, sizeof(hdr.name)));
    while (!path.empty() && path.back() == '/') {
        path.pop_back();
    }
    return path;
}

static uint64_t ParseOctal(const char* field, size_t len) {
    uint64_t v = 0;
    for (size_t i = 0; i < len && field[i] != '\0' && field[i] != ' '; ++i) {
        if (field[i] < '0' || field[i] > '7') break;
        v = (v << 3) + static_cast<uint64_t>(field[i] - '0');
    }
    return v;
}

// --- encryption ---

struct EncryptWriter {
    FILE* out = nullptr;
    EVP_CIPHER_CTX* evp = nullptr;
};

static bool EncryptWriterInit(EncryptWriter* w, FILE* out, const std::string& password,
                              uint8_t saltOut[kSaltSize], uint8_t ivOut[kIvSize]) {
    w->out = out;
    if (RAND_bytes(saltOut, kSaltSize) != 1 || RAND_bytes(ivOut, kIvSize) != 1) return false;
    uint8_t key[kKeySize];
    if (!DeriveKey(password, saltOut, key)) return false;
    w->evp = EVP_CIPHER_CTX_new();
    if (!w->evp) return false;
    if (EVP_EncryptInit_ex(w->evp, EVP_aes_256_cbc(), nullptr, key, ivOut) != 1) {
        EVP_CIPHER_CTX_free(w->evp);
        w->evp = nullptr;
        return false;
    }
    OPENSSL_cleanse(key, sizeof(key));
    if (fwrite(kEncMagic, 1, sizeof(kEncMagic), out) != sizeof(kEncMagic)) return false;
    if (fwrite(saltOut, 1, kSaltSize, out) != kSaltSize) return false;
    if (fwrite(ivOut, 1, kIvSize, out) != kIvSize) return false;
    return true;
}

static bool EncryptWriterUpdate(EncryptWriter* w, const void* data, size_t len) {
    if (len == 0) return true;
    unsigned char outbuf[kBufferSize + EVP_MAX_BLOCK_LENGTH];
    int outLen = 0;
    if (EVP_EncryptUpdate(w->evp, outbuf, &outLen, static_cast<const unsigned char*>(data),
                          static_cast<int>(len)) != 1) {
        return false;
    }
    if (outLen > 0 && fwrite(outbuf, 1, static_cast<size_t>(outLen), w->out) != static_cast<size_t>(outLen)) {
        return false;
    }
    return true;
}

static bool EncryptWriterFinal(EncryptWriter* w) {
    unsigned char outbuf[EVP_MAX_BLOCK_LENGTH];
    int outLen = 0;
    if (EVP_EncryptFinal_ex(w->evp, outbuf, &outLen) != 1) return false;
    if (outLen > 0 && fwrite(outbuf, 1, static_cast<size_t>(outLen), w->out) != static_cast<size_t>(outLen)) {
        return false;
    }
    EVP_CIPHER_CTX_free(w->evp);
    w->evp = nullptr;
    return true;
}

static bool ReadEncHeader(FILE* in, uint8_t salt[kSaltSize], uint8_t iv[kIvSize]) {
    uint8_t magic[4];
    if (fread(magic, 1, 4, in) != 4) return false;
    if (memcmp(magic, kEncMagic, 4) != 0) return false;
    return fread(salt, 1, kSaltSize, in) == kSaltSize && fread(iv, 1, kIvSize, in) == kIvSize;
}

}  // namespace

BackupPathClass ClassifyBackupSource(const std::string& srcDir) {
    if (android::base::StartsWith(srcDir, "/data/user/")
            || android::base::StartsWith(srcDir, "/data/user_de/")) {
        return BackupPathClass::kUserData;
    }
    if (android::base::StartsWith(srcDir, "/data/media/")
            && (srcDir.find("/Android/data/") != std::string::npos
                    || srcDir.find("/Android/obb/") != std::string::npos
                    || srcDir.find("/Android/media/") != std::string::npos)) {
        return BackupPathClass::kSharedAndroid;
    }
    return BackupPathClass::kOther;
}

bool IsEncryptedArchivePath(const std::string& path) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) return false;
    uint8_t magic[4];
    return read(fd.get(), magic, 4) == 4 && memcmp(magic, kEncMagic, 4) == 0;
}

bool TarDirectory(const std::string& srcDir, const std::string& outTarPath, BackupPathClass pathClass) {
    struct stat st;
    if (stat(srcDir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG(ERROR) << "Source not a directory: " << srcDir;
        return false;
    }
    if (!EnsureDir(Dirname(outTarPath))) return false;

    FILE* fp = fopen(outTarPath.c_str(), "wb");
    if (!fp) {
        PLOG(ERROR) << "fopen failed: " << outTarPath;
        return false;
    }
    const bool ok = TarDirInternal(fp, srcDir, "", pathClass) && WriteTarEnd(fp);
    fclose(fp);
    if (!ok) unlink(outTarPath.c_str());
    return ok;
}

bool TarFiles(const std::vector<std::pair<std::string, std::string>>& files,
              const std::string& outTarPath) {
    if (files.empty()) return false;
    if (!EnsureDir(Dirname(outTarPath))) return false;
    FILE* fp = fopen(outTarPath.c_str(), "wb");
    if (!fp) return false;
    bool ok = true;
    for (const auto& it : files) {
        if (it.second.empty() || IsPathTraversal(it.second)) {
            ok = false;
            break;
        }
        struct stat st;
        if (stat(it.first.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            ok = false;
            break;
        }
        if (!TarAddFile(fp, it.first, it.second)) {
            ok = false;
            break;
        }
    }
    ok = ok && WriteTarEnd(fp);
    fclose(fp);
    if (!ok) unlink(outTarPath.c_str());
    return ok;
}

bool UntarToDirectory(const std::string& tarPath, const std::string& outDir) {
    if (!EnsureDir(outDir)) return false;
    FILE* in = fopen(tarPath.c_str(), "rb");
    if (!in) return false;

    bool done = false;
    while (!done) {
        TarHeader hdr;
        if (!ReadTarHeader(in, &hdr)) {
            done = true;
            break;
        }
        const std::string path = TarEntryPath(hdr);
        if (path.empty() || IsPathTraversal(path)) {
            fclose(in);
            return false;
        }
        const uint64_t size = ParseOctal(hdr.size, sizeof(hdr.size));
        const std::string outPath = outDir + "/" + path;

        if (hdr.typeflag == '5' || (hdr.typeflag == '\0' && size == 0)) {
            if (!EnsureDir(outPath)) {
                fclose(in);
                return false;
            }
            chmod(outPath.c_str(), 0755);
            continue;
        }

        if (hdr.typeflag == '0' || hdr.typeflag == '\0') {
            if (!EnsureDir(Dirname(outPath))) {
                fclose(in);
                return false;
            }
            FILE* out = fopen(outPath.c_str(), "wb");
            if (!out) {
                fclose(in);
                return false;
            }
            uint64_t remaining = size;
            std::vector<char> buf(kBufferSize);
            while (remaining > 0) {
                const size_t chunk =
                        static_cast<size_t>(std::min<uint64_t>(remaining, buf.size()));
                if (fread(buf.data(), 1, chunk, in) != chunk) {
                    fclose(out);
                    fclose(in);
                    unlink(outPath.c_str());
                    return false;
                }
                if (fwrite(buf.data(), 1, chunk, out) != chunk) {
                    fclose(out);
                    fclose(in);
                    unlink(outPath.c_str());
                    return false;
                }
                remaining -= chunk;
            }
            fclose(out);
            // truebackupd runs as root; system_server must read APKs from this tree.
            chmod(outPath.c_str(), 0644);
            const uint64_t pad = (kTarBlock - (size % kTarBlock)) % kTarBlock;
            if (pad > 0 && fseek(in, static_cast<long>(pad), SEEK_CUR) != 0) {
                fclose(in);
                return false;
            }
        } else {
            const uint64_t pad = (kTarBlock - (size % kTarBlock)) % kTarBlock;
            if (fseek(in, static_cast<long>(size + pad), SEEK_CUR) != 0) {
                fclose(in);
                return false;
            }
        }
    }
    fclose(in);
    return true;
}

bool EncryptTarInPlace(const std::string& path, const std::string& password) {
    if (path.empty() || path[0] != '/' || password.empty()) return false;
    if (IsEncryptedArchivePath(path)) return true;
    struct stat st;
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;

    FILE* in = fopen(path.c_str(), "rb");
    if (!in) return false;

    const std::string tmpPath = path + ".enc_tmp";
    FILE* out = fopen(tmpPath.c_str(), "wb");
    if (!out) {
        fclose(in);
        return false;
    }

    uint8_t salt[kSaltSize];
    uint8_t iv[kIvSize];
    EncryptWriter enc;
    if (!EncryptWriterInit(&enc, out, password, salt, iv)) {
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    std::vector<uint8_t> buf(kBufferSize);
    bool ok = true;
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), in)) > 0) {
        if (!EncryptWriterUpdate(&enc, buf.data(), n)) {
            ok = false;
            break;
        }
    }
    if (ok) ok = EncryptWriterFinal(&enc);
    fclose(in);
    fclose(out);
    if (!ok) {
        unlink(tmpPath.c_str());
        return false;
    }
    if (unlink(path.c_str()) != 0 || rename(tmpPath.c_str(), path.c_str()) != 0) {
        unlink(tmpPath.c_str());
        return false;
    }
    chmod(path.c_str(), st.st_mode & 07777);
    return true;
}

bool DecryptToPlainTar(const std::string& encPath, const std::string& outTarPath,
                       const std::string& password) {
    if (encPath.empty() || outTarPath.empty() || password.empty()) return false;

    FILE* in = fopen(encPath.c_str(), "rb");
    if (!in) return false;

    uint8_t salt[kSaltSize];
    uint8_t iv[kIvSize];
    if (!ReadEncHeader(in, salt, iv)) {
        fclose(in);
        return false;
    }

    uint8_t key[kKeySize];
    if (!DeriveKey(password, salt, key)) {
        fclose(in);
        return false;
    }

    EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();
    if (!evp) {
        fclose(in);
        return false;
    }
    if (EVP_DecryptInit_ex(evp, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(evp);
        fclose(in);
        return false;
    }
    OPENSSL_cleanse(key, sizeof(key));

    if (!EnsureDir(Dirname(outTarPath))) {
        EVP_CIPHER_CTX_free(evp);
        fclose(in);
        return false;
    }
    unlink(outTarPath.c_str());
    FILE* out = fopen(outTarPath.c_str(), "wb");
    if (!out) {
        EVP_CIPHER_CTX_free(evp);
        fclose(in);
        return false;
    }

    std::vector<uint8_t> encbuf(kBufferSize);
    unsigned char decbuf[kBufferSize + EVP_MAX_BLOCK_LENGTH];
    bool fail = false;
    while (true) {
        size_t readBytes = fread(encbuf.data(), 1, encbuf.size(), in);
        if (readBytes == 0) {
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(evp, decbuf, &finalLen) != 1) {
                fail = true;
            } else if (finalLen > 0
                       && fwrite(decbuf, 1, static_cast<size_t>(finalLen), out)
                               != static_cast<size_t>(finalLen)) {
                fail = true;
            }
            break;
        }
        int outLen = 0;
        if (EVP_DecryptUpdate(evp, decbuf, &outLen, encbuf.data(), static_cast<int>(readBytes))
                != 1) {
            fail = true;
            break;
        }
        if (outLen > 0
            && fwrite(decbuf, 1, static_cast<size_t>(outLen), out) != static_cast<size_t>(outLen)) {
            fail = true;
            break;
        }
    }

    EVP_CIPHER_CTX_free(evp);
    fclose(in);
    fclose(out);
    if (fail) {
        unlink(outTarPath.c_str());
        return false;
    }
    return true;
}

bool DecryptExtractToDirectory(const std::string& encPath, const std::string& outDir,
                               const std::string& password) {
    const std::string tmpTar = outDir + "/.truebackup_extract.tar.tmp";
    if (!DecryptToPlainTar(encPath, tmpTar, password)) return false;
    const bool ok = UntarToDirectory(tmpTar, outDir);
    unlink(tmpTar.c_str());
    return ok;
}

bool ReEncryptArchiveFile(const std::string& path, const std::string& oldPassword,
                          const std::string& newPassword) {
    if (!android::base::EndsWith(path, ".tbak")) return true;
    if (!IsEncryptedArchivePath(path)) {
        return EncryptTarInPlace(path, newPassword);
    }
    if (oldPassword.empty()) return false;

    const std::string tmpPlain = path + ".rekey_plain";
    if (!DecryptToPlainTar(path, tmpPlain, oldPassword)) {
        unlink(tmpPlain.c_str());
        return false;
    }
    struct stat st;
    mode_t mode = 0644;
    if (stat(path.c_str(), &st) == 0) mode = st.st_mode & 07777;
    if (unlink(path.c_str()) != 0) {
        unlink(tmpPlain.c_str());
        return false;
    }
    if (rename(tmpPlain.c_str(), path.c_str()) != 0) {
        unlink(tmpPlain.c_str());
        return false;
    }
    chmod(path.c_str(), mode);
    return EncryptTarInPlace(path, newPassword);
}

}  // namespace truebackup
