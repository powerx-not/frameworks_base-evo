/*
 * Copyright (C) 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <binder/Binder.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <utils/String16.h>
#include <utils/String8.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/android.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_writer.h>

#include <android-base/unique_fd.h>

namespace {

constexpr const char* kServiceName = "truebackupd";
constexpr uint32_t kInterfaceToken = 0x5452424b;  // 'TRBK'

enum Transaction : uint32_t {
    ZIP_DIR = android::IBinder::FIRST_CALL_TRANSACTION,
    UNZIP_TO_DIR = android::IBinder::FIRST_CALL_TRANSACTION + 1,
    MKDIRS = android::IBinder::FIRST_CALL_TRANSACTION + 2,
    ZIP_SINGLE_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 3,
    ZIP_MULTI_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 4,
    WRITE_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 5,
    /** Recursive chown + selinux_android_restorecon (matches backup tools that fix ownership after extract). */
    CHOWN_AND_RESTORECON = android::IBinder::FIRST_CALL_TRANSACTION + 6,
    /** Recursively delete a directory tree (backup package folder under …/apps/…). */
    DELETE_TREE = android::IBinder::FIRST_CALL_TRANSACTION + 7,
    /** Store TrueBackup registration password (fixed location under /data/system/truebackup). */
    SET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 8,
    /** Read TrueBackup registration password (fixed location under /data/system/truebackup). */
    GET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 9,
    /** Encrypt a plain file in place (TBE1: PBKDF2 + AES-256-GCM, matches TrueBackupService format). */
    ENCRYPT_ZIP_IN_PLACE = android::IBinder::FIRST_CALL_TRANSACTION + 10,
    /** Decrypt TBE1 file to a new path. */
    DECRYPT_ZIP_TO_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 11,
    /** Change registration password (requires old password). */
    CHANGE_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 12,
};

static std::string Dirname(const std::string& path) {
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

static bool EnsureDir(const std::string& path, mode_t mode);
static bool EnsureDir(const std::string& path) { return EnsureDir(path, 0755); }
static bool ZipAddFile(ZipWriter& writer, const std::string& absPath, const std::string& relPath);
static bool ZipDir(const std::string& srcDir, const std::string& outZip);
static bool UnzipToDir(const std::string& zipPath, const std::string& outDir);
static bool IsPathTraversal(const std::string& entryName);
static bool ChownRecursive(const std::string& path, uid_t uid, gid_t gid);
static bool FixupOwnershipAndSelinux(const std::string& path, int32_t uid, int32_t gid);
static bool RemoveTree(const std::string& path);
static bool WriteFileAtomic(const std::string& outPath, const uint8_t* data, size_t dataLen);

static const char* kPasswordPath = "/data/system/truebackup/registration_password.bin";
/** system_server creates temp files here (APK decrypt); must be system-owned, not root-only. */
static const char* kTrueBackupTmpDir = "/data/system/truebackup/tmp";

static bool ReadFileToString(const std::string& path, std::string* out) {
    out->clear();
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) return false;
    std::string res;
    std::vector<uint8_t> buf(4096);
    while (true) {
        ssize_t n = read(fd.get(), buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) break;
        res.append(reinterpret_cast<const char*>(buf.data()), static_cast<size_t>(n));
    }
    *out = std::move(res);
    return true;
}

static bool WritePassword(const std::string& pw) {
    if (!WriteFileAtomic(kPasswordPath, reinterpret_cast<const uint8_t*>(pw.data()), pw.size())) {
        return false;
    }
    chmod(kPasswordPath, 0600);
    return true;
}

static bool ChangePassword(const std::string& oldPw, const std::string& newPw) {
    if (oldPw.empty() || newPw.empty()) return false;
    std::string current;
    if (!ReadFileToString(kPasswordPath, &current)) return false;
    // Match Java behavior: trim stored value before comparisons.
    current = android::base::Trim(current);
    if (current != oldPw) return false;
    return WritePassword(newPw);
}

static bool WriteFileAtomic(const std::string& outPath, const uint8_t* data, size_t dataLen) {
    std::string outParent = Dirname(outPath);
    if (!EnsureDir(outParent)) {
        LOG(ERROR) << "Failed to create parent dir: " << outParent;
        return false;
    }

    android::base::unique_fd fd(open(outPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644));
    if (fd.get() < 0) {
        PLOG(ERROR) << "open out failed: " << outPath;
        return false;
    }

    size_t written = 0;
    while (written < dataLen) {
        ssize_t n = write(fd.get(), data + written, dataLen - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            PLOG(ERROR) << "write failed: " << outPath;
            return false;
        }
        written += static_cast<size_t>(n);
    }

    return true;
}

static bool ZipSingleFileToZip(const std::string& srcFile, const std::string& outZip,
                               const std::string& entryName) {
    struct stat st;
    if (stat(srcFile.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG(ERROR) << "Source not a regular file: " << srcFile;
        return false;
    }

    std::string outParent = Dirname(outZip);
    if (!EnsureDir(outParent)) {
        LOG(ERROR) << "Failed to create parent dir: " << outParent;
        return false;
    }

    FILE* fp = fopen(outZip.c_str(), "wb");
    if (!fp) {
        PLOG(ERROR) << "fopen failed: " << outZip;
        return false;
    }

    ZipWriter writer(fp);
    bool ok = ZipAddFile(writer, srcFile, entryName);
    if (!ok) {
        fclose(fp);
        return false;
    }

    if (writer.Finish() != 0) {
        LOG(ERROR) << "ZipWriter::Finish failed";
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static bool ZipMultiFileToZip(const std::vector<std::pair<std::string, std::string>>& files,
                              const std::string& outZip) {
    if (files.empty()) {
        LOG(ERROR) << "No files to zip";
        return false;
    }

    std::string outParent = Dirname(outZip);
    if (!EnsureDir(outParent)) {
        LOG(ERROR) << "Failed to create parent dir: " << outParent;
        return false;
    }

    FILE* fp = fopen(outZip.c_str(), "wb");
    if (!fp) {
        PLOG(ERROR) << "fopen failed: " << outZip;
        return false;
    }

    ZipWriter writer(fp);
    for (const auto& it : files) {
        const std::string& srcFile = it.first;
        const std::string& entryName = it.second;

        if (entryName.empty()) {
            LOG(ERROR) << "Empty entry name for: " << srcFile;
            fclose(fp);
            return false;
        }

        if (IsPathTraversal(entryName)) {
            LOG(ERROR) << "Rejected entry path: " << entryName;
            fclose(fp);
            return false;
        }

        struct stat st;
        if (stat(srcFile.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            LOG(ERROR) << "Source not a regular file: " << srcFile;
            fclose(fp);
            return false;
        }

        if (!ZipAddFile(writer, srcFile, entryName)) {
            fclose(fp);
            return false;
        }
    }

    if (writer.Finish() != 0) {
        LOG(ERROR) << "ZipWriter::Finish failed";
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static bool EnsureDir(const std::string& path, mode_t mode) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }

    // Create parents first.
    std::string parent = Dirname(path);
    if (parent != path && parent != "." && parent != "/") {
        if (!EnsureDir(parent, mode)) return false;
    }

    if (mkdir(path.c_str(), mode) == 0) return true;
    return errno == EEXIST;
}

/**
 * system_server must traverse parents and create temp files under |path| without DAC overrides.
 * Do not use 0770 for parent dirs (that locks out uid system). Avoid chown here: policy often
 * denies truebackupd CAP_FOWNER.
 */
static bool EnsureSystemWritableTempDir(const std::string& path) {
    const std::string parent = Dirname(path);
    if (!EnsureDir(parent, 0755)) return false;
    if (chmod(parent.c_str(), 0755) != 0) {
        PLOG(WARNING) << "chmod " << parent;
    }
    // root:root, others wx: system_server (not in root group) can create/link temp names here.
    if (!EnsureDir(path, 0773)) return false;
    if (chmod(path.c_str(), 0773) != 0) {
        PLOG(WARNING) << "chmod " << path;
    }
    return true;
}

static bool IsDotOrDotDot(const char* name) {
    return (strcmp(name, ".") == 0) || (strcmp(name, "..") == 0);
}

static bool IsPathTraversal(const std::string& entryName) {
    if (entryName.empty()) return true;
    if (entryName[0] == '/') return true;
    if (entryName.find("..") == std::string::npos) return false;

    // Conservative check: reject any path segment == "..".
    size_t start = 0;
    while (start < entryName.size()) {
        size_t end = entryName.find('/', start);
        if (end == std::string::npos) end = entryName.size();
        std::string seg = entryName.substr(start, end - start);
        if (seg == "..") return true;
        start = end + 1;
    }
    return false;
}

static bool ZipAddFile(ZipWriter& writer, const std::string& absPath, const std::string& relPath) {
    android::base::unique_fd fd(open(absPath.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) {
        PLOG(ERROR) << "open failed: " << absPath;
        return false;
    }

    struct stat st;
    if (fstat(fd.get(), &st) != 0) {
        PLOG(ERROR) << "fstat failed: " << absPath;
        return false;
    }

    if (writer.StartEntry(relPath, ZipWriter::kCompress) != 0) {
        LOG(ERROR) << "StartEntry failed: " << relPath;
        return false;
    }

    std::vector<uint8_t> buf(128 * 1024);
    ssize_t n;
    while ((n = read(fd.get(), buf.data(), buf.size())) > 0) {
        if (writer.WriteBytes(buf.data(), static_cast<size_t>(n)) != 0) {
            LOG(ERROR) << "WriteBytes failed for " << relPath;
            return false;
        }
    }

    if (n < 0) {
        PLOG(ERROR) << "read failed: " << absPath;
        return false;
    }

    if (writer.FinishEntry() != 0) {
        LOG(ERROR) << "FinishEntry failed: " << relPath;
        return false;
    }

    (void)st;
    return true;
}

static bool ZipDirInternal(ZipWriter& writer, const std::string& root, const std::string& current,
                          const std::string& relPrefix) {
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

        // Skip symlinks for safety.
        if (S_ISLNK(st.st_mode)) {
            continue;
        }

        std::string childRel = relPrefix.empty() ? std::string(de->d_name) : (relPrefix + "/" + de->d_name);

        if (S_ISDIR(st.st_mode)) {
            // Create a directory entry in the zip.
            std::string dirEntry = childRel;
            if (!android::base::EndsWith(dirEntry, "/")) dirEntry += "/";
            if (writer.StartEntry(dirEntry, 0) != 0 || writer.FinishEntry() != 0) {
                LOG(ERROR) << "Failed to add dir entry: " << dirEntry;
                closedir(dir);
                return false;
            }

            if (!ZipDirInternal(writer, root, childAbs, childRel)) {
                closedir(dir);
                return false;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (!ZipAddFile(writer, childAbs, childRel)) {
                closedir(dir);
                return false;
            }
        }
    }

    closedir(dir);
    return true;
}

static bool ZipDir(const std::string& srcDir, const std::string& outZip) {
    struct stat st;
    if (stat(srcDir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG(ERROR) << "Source not a directory: " << srcDir;
        return false;
    }

    std::string outParent = Dirname(outZip);
    if (!EnsureDir(outParent)) {
        LOG(ERROR) << "Failed to create parent dir: " << outParent;
        return false;
    }

    FILE* fp = fopen(outZip.c_str(), "wb");
    if (!fp) {
        PLOG(ERROR) << "fopen failed: " << outZip;
        return false;
    }

    ZipWriter writer(fp);

    bool ok = ZipDirInternal(writer, srcDir, srcDir, "");
    if (!ok) {
        fclose(fp);
        return false;
    }

    if (writer.Finish() != 0) {
        LOG(ERROR) << "ZipWriter::Finish failed";
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static bool UnzipToDir(const std::string& zipPath, const std::string& outDir) {
    if (!EnsureDir(outDir)) {
        LOG(ERROR) << "Failed to create output dir: " << outDir;
        return false;
    }

    ZipArchiveHandle handle;
    int32_t openErr = OpenArchive(zipPath.c_str(), &handle);
    if (openErr != 0) {
        LOG(ERROR) << "OpenArchive failed: " << zipPath << " err=" << openErr;
        return false;
    }

    void* cookie = nullptr;
    int32_t itErr = StartIteration(handle, &cookie);
    if (itErr != 0) {
        LOG(ERROR) << "StartIteration failed: " << zipPath << " err=" << itErr;
        CloseArchive(handle);
        return false;
    }

    ZipEntry64 entry;
    std::string name;
    int32_t nextErr;
    while ((nextErr = Next(cookie, &entry, &name)) == 0) {
        if (IsPathTraversal(name)) {
            LOG(ERROR) << "Rejected zip entry path: " << name;
            EndIteration(cookie);
            CloseArchive(handle);
            return false;
        }

        std::string outPath = outDir + "/" + name;

        if (android::base::EndsWith(name, "/")) {
            if (!EnsureDir(outPath)) {
                LOG(ERROR) << "Failed to mkdir: " << outPath;
                EndIteration(cookie);
                CloseArchive(handle);
                return false;
            }
            continue;
        }

        if (!EnsureDir(Dirname(outPath))) {
            LOG(ERROR) << "Failed to mkdir parent: " << outPath;
            EndIteration(cookie);
            CloseArchive(handle);
            return false;
        }

        android::base::unique_fd fd(open(outPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644));
        if (fd.get() < 0) {
            PLOG(ERROR) << "open out failed: " << outPath;
            EndIteration(cookie);
            CloseArchive(handle);
            return false;
        }

        int32_t exErr = ExtractEntryToFile(handle, &entry, fd.get());
        if (exErr != 0) {
            LOG(ERROR) << "ExtractEntryToFile failed entry=" << name << " err=" << exErr;
            EndIteration(cookie);
            CloseArchive(handle);
            return false;
        }
    }

    EndIteration(cookie);
    CloseArchive(handle);

    if (nextErr != -1) {
        LOG(ERROR) << "Iteration ended with err=" << nextErr;
        return false;
    }

    return true;
}

static bool ChownRecursive(const std::string& path, uid_t uid, gid_t gid) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        PLOG(ERROR) << "lstat failed: " << path;
        return false;
    }

    if (lchown(path.c_str(), uid, gid) != 0) {
        PLOG(ERROR) << "lchown failed: " << path;
        return false;
    }

    if (!S_ISDIR(st.st_mode)) {
        return true;
    }

    DIR* dir = opendir(path.c_str());
    if (!dir) {
        PLOG(ERROR) << "opendir failed: " << path;
        return false;
    }

    dirent* de;
    bool ok = true;
    while ((de = readdir(dir)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        std::string child = path + "/" + de->d_name;
        if (!ChownRecursive(child, uid, gid)) {
            ok = false;
        }
    }
    closedir(dir);
    return ok;
}

static bool FixupOwnershipAndSelinux(const std::string& path, int32_t uid32, int32_t gid32) {
    if (path.empty() || path[0] != '/') {
        LOG(ERROR) << "Invalid path for fixup: " << path;
        return false;
    }

    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        LOG(ERROR) << "Fixup path missing: " << path;
        return false;
    }

    uid_t uid = static_cast<uid_t>(uid32);
    gid_t gid = (gid32 < 0) ? uid : static_cast<gid_t>(gid32);

    if (!ChownRecursive(path, uid, gid)) {
        return false;
    }

    unsigned int flags = SELINUX_ANDROID_RESTORECON_RECURSE | SELINUX_ANDROID_RESTORECON_SKIP_SEHASH;
    if (selinux_android_restorecon(path.c_str(), flags) != 0) {
        PLOG(ERROR) << "selinux_android_restorecon failed: " << path;
        return false;
    }

    return true;
}

constexpr uint8_t kEncMagic[] = {'T', 'B', 'E', '1'};
constexpr int kEncVersion = 1;
constexpr size_t kEncSaltLen = 16;
constexpr size_t kEncIvLen = 12;
constexpr int kEncPbkdf2Iters = 120000;
constexpr size_t kGcmTagLen = 16;

static bool DeriveKey(const std::string& password, const uint8_t* salt, size_t saltLen, uint8_t outKey[32]) {
    // Matches Java PBKDF2WithHmacSHA256 (BoringSSL uses PKCS5_PBKDF2_HMAC + EVP_sha256).
    return PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()), password.size(), salt, saltLen,
                             static_cast<uint32_t>(kEncPbkdf2Iters), EVP_sha256(), 32, outKey) == 1;
}

/**
 * Encrypts a regular file in place to TBE1 format (same as Java TrueBackupService).
 * If the file already begins with TBE1 magic, returns true without modifying it.
 */
static bool EncryptZipInPlace(const std::string& path, const std::string& password) {
    if (path.empty() || path[0] != '/' || password.empty()) {
        LOG(ERROR) << "EncryptZipInPlace: bad args";
        return false;
    }

    struct stat st;
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG(ERROR) << "EncryptZipInPlace: not a regular file: " << path;
        return false;
    }

    FILE* in = fopen(path.c_str(), "rb");
    if (!in) {
        PLOG(ERROR) << "EncryptZipInPlace: fopen failed: " << path;
        return false;
    }

    uint8_t magic[4];
    if (fread(magic, 1, 4, in) != 4) {
        fclose(in);
        return false;
    }
    if (memcmp(magic, kEncMagic, 4) == 0) {
        fclose(in);
        return true;
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        fclose(in);
        return false;
    }

    const std::string tmpPath = path + ".enc_tmp";
    FILE* out = fopen(tmpPath.c_str(), "wb");
    if (!out) {
        fclose(in);
        PLOG(ERROR) << "EncryptZipInPlace: fopen tmp failed: " << tmpPath;
        return false;
    }

    uint8_t salt[kEncSaltLen];
    uint8_t iv[kEncIvLen];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    uint8_t key[32];
    if (!DeriveKey(password, salt, sizeof(salt), key)) {
        OPENSSL_cleanse(key, sizeof(key));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    if (fwrite(kEncMagic, 1, 4, out) != 4 || fputc(kEncVersion, out) == EOF ||
        fputc(static_cast<int>(kEncSaltLen), out) == EOF || fputc(static_cast<int>(kEncIvLen), out) == EOF ||
        fwrite(salt, 1, kEncSaltLen, out) != kEncSaltLen || fwrite(iv, 1, kEncIvLen, out) != kEncIvLen) {
        OPENSSL_cleanse(key, sizeof(key));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    int ok = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kEncIvLen), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;

        uint8_t buf[64 * 1024];
        uint8_t outbuf[64 * 1024 + EVP_MAX_BLOCK_LENGTH];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
            int outlen = 0;
            if (EVP_EncryptUpdate(ctx, outbuf, &outlen, buf, static_cast<int>(n)) != 1) {
                ok = -1;
                break;
            }
            if (outlen > 0 &&
                static_cast<size_t>(fwrite(outbuf, 1, static_cast<size_t>(outlen), out)) != static_cast<size_t>(outlen)) {
                ok = -1;
                break;
            }
        }
        if (ok != 0) break;
        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &finalLen) != 1) break;
        if (finalLen > 0 && static_cast<size_t>(fwrite(outbuf, 1, static_cast<size_t>(finalLen), out)) !=
            static_cast<size_t>(finalLen)) {
            ok = -1;
            break;
        }
        uint8_t tag[kGcmTagLen];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(sizeof(tag)), tag) != 1) break;
        if (fwrite(tag, 1, sizeof(tag), out) != sizeof(tag)) break;
        ok = 1;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    fclose(in);
    fclose(out);

    if (ok != 1) {
        unlink(tmpPath.c_str());
        return false;
    }

    if (unlink(path.c_str()) != 0) {
        unlink(tmpPath.c_str());
        return false;
    }
    if (rename(tmpPath.c_str(), path.c_str()) != 0) {
        PLOG(ERROR) << "EncryptZipInPlace: rename failed";
        return false;
    }
    chmod(path.c_str(), st.st_mode & 07777);
    return true;
}

static bool DecryptZipToFile(const std::string& encPath, const std::string& outPath, const std::string& password) {
    if (encPath.empty() || encPath[0] != '/' || outPath.empty() || outPath[0] != '/' || password.empty()) {
        LOG(ERROR) << "DecryptZipToFile: bad args";
        return false;
    }

    FILE* in = fopen(encPath.c_str(), "rb");
    if (!in) {
        PLOG(ERROR) << "DecryptZipToFile: fopen failed: " << encPath;
        return false;
    }

    uint8_t magic[4];
    if (fread(magic, 1, 4, in) != 4) {
        fclose(in);
        return false;
    }
    if (memcmp(magic, kEncMagic, 4) != 0) {
        fclose(in);
        return false;
    }
    int ver = fgetc(in);
    if (ver != kEncVersion) {
        fclose(in);
        return false;
    }
    int saltLen = fgetc(in);
    int ivLen = fgetc(in);
    if (saltLen != static_cast<int>(kEncSaltLen) || ivLen != static_cast<int>(kEncIvLen)) {
        fclose(in);
        return false;
    }
    uint8_t salt[kEncSaltLen];
    uint8_t iv[kEncIvLen];
    if (fread(salt, 1, kEncSaltLen, in) != kEncSaltLen || fread(iv, 1, kEncIvLen, in) != kEncIvLen) {
        fclose(in);
        return false;
    }

    long headerEnd = ftell(in);
    if (headerEnd < 0) {
        fclose(in);
        return false;
    }
    if (fseek(in, 0, SEEK_END) != 0) {
        fclose(in);
        return false;
    }
    long fileSize = ftell(in);
    if (fseek(in, headerEnd, SEEK_SET) != 0) {
        fclose(in);
        return false;
    }

    long ciphertextLen = fileSize - headerEnd - static_cast<long>(kGcmTagLen);
    if (ciphertextLen < 0) {
        fclose(in);
        return false;
    }

    unlink(outPath.c_str());

    FILE* out = fopen(outPath.c_str(), "wb");
    if (!out) {
        fclose(in);
        PLOG(ERROR) << "DecryptZipToFile: fopen out failed: " << outPath;
        return false;
    }

    uint8_t key[32];
    if (!DeriveKey(password, salt, sizeof(salt), key)) {
        OPENSSL_cleanse(key, sizeof(key));
        fclose(in);
        fclose(out);
        unlink(outPath.c_str());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        fclose(in);
        fclose(out);
        unlink(outPath.c_str());
        return false;
    }

    bool fail = true;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kEncIvLen), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;

        uint8_t buf[64 * 1024];
        uint8_t outbuf[64 * 1024 + EVP_MAX_BLOCK_LENGTH];
        long remaining = ciphertextLen;
        while (remaining > 0) {
            const size_t chunk =
                static_cast<size_t>(std::min<long>(remaining, static_cast<long>(sizeof(buf))));
            if (fread(buf, 1, chunk, in) != chunk) goto decrypt_fail;
            int outlen = 0;
            if (EVP_DecryptUpdate(ctx, outbuf, &outlen, buf, static_cast<int>(chunk)) != 1) goto decrypt_fail;
            if (outlen > 0 && fwrite(outbuf, 1, static_cast<size_t>(outlen), out) != static_cast<size_t>(outlen)) {
                goto decrypt_fail;
            }
            remaining -= static_cast<long>(chunk);
        }

        uint8_t tag[kGcmTagLen];
        if (fread(tag, 1, sizeof(tag), in) != sizeof(tag)) goto decrypt_fail;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(sizeof(tag)), tag) != 1) {
            goto decrypt_fail;
        }

        uint8_t finalBuf[256];
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx, finalBuf, &finalLen) != 1) goto decrypt_fail;
        if (finalLen > 0 && fwrite(finalBuf, 1, static_cast<size_t>(finalLen), out) != static_cast<size_t>(finalLen)) {
            goto decrypt_fail;
        }
        fail = false;
    } while (false);

decrypt_fail:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    fclose(in);
    fclose(out);
    if (fail) {
        unlink(outPath.c_str());
        return false;
    }
    {
        const std::string prefix = std::string(kTrueBackupTmpDir) + "/";
        if (outPath.size() > prefix.size() && outPath.compare(0, prefix.size(), prefix) == 0) {
            if (chmod(outPath.c_str(), 0644) != 0) {
                PLOG(WARNING) << "chmod decrypted tmp: " << outPath;
            }
        }
    }
    return true;
}

static bool RemoveTree(const std::string& path) {
    if (path.empty() || path[0] != '/') {
        LOG(ERROR) << "RemoveTree: invalid path: " << path;
        return false;
    }
    if (path == "/" || path == "/data" || path == "/system" || path == "/vendor") {
        LOG(ERROR) << "RemoveTree: refusing dangerous path: " << path;
        return false;
    }
    if (path.find("/apps/") == std::string::npos) {
        LOG(ERROR) << "RemoveTree: path must contain /apps/: " << path;
        return false;
    }

    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) return true;
        PLOG(ERROR) << "RemoveTree lstat: " << path;
        return false;
    }

    if (S_ISLNK(st.st_mode)) {
        return unlink(path.c_str()) == 0 || errno == ENOENT;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.c_str());
        if (!dir) {
            PLOG(ERROR) << "RemoveTree opendir: " << path;
            return false;
        }
        dirent* de;
        bool ok = true;
        while ((de = readdir(dir)) != nullptr) {
            if (IsDotOrDotDot(de->d_name)) continue;
            std::string child = path + "/" + de->d_name;
            if (!RemoveTree(child)) {
                ok = false;
            }
        }
        closedir(dir);
        if (!ok) return false;
        if (rmdir(path.c_str()) != 0 && errno != ENOENT) {
            PLOG(ERROR) << "RemoveTree rmdir: " << path;
            return false;
        }
        return true;
    }

    if (unlink(path.c_str()) != 0 && errno != ENOENT) {
        PLOG(ERROR) << "RemoveTree unlink: " << path;
        return false;
    }
    return true;
}

class TrueBackupDaemonService : public android::BBinder {
  public:
    android::status_t onTransact(uint32_t code, const android::Parcel& data,
                                android::Parcel* reply, uint32_t flags) override {
        (void)flags;

        const uint32_t token = static_cast<uint32_t>(data.readInt32());
        if (token != kInterfaceToken) {
            return android::PERMISSION_DENIED;
        }

        switch (code) {
            case ZIP_DIR: {
                std::string src = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                bool ok = ZipDir(src, out);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case UNZIP_TO_DIR: {
                std::string zip = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                bool ok = UnzipToDir(zip, out);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case MKDIRS: {
                std::string path = std::string(android::String8(data.readString16()).c_str());
                bool ok = (path == kTrueBackupTmpDir) ? EnsureSystemWritableTempDir(path) : EnsureDir(path);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case ZIP_SINGLE_FILE: {
                std::string src = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                std::string entry = std::string(android::String8(data.readString16()).c_str());
                bool ok = ZipSingleFileToZip(src, out, entry);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case ZIP_MULTI_FILE: {
                std::string out = std::string(android::String8(data.readString16()).c_str());
                int32_t count = data.readInt32();
                if (count <= 0 || count > 128) {
                    LOG(ERROR) << "Invalid file count: " << count;
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }

                std::vector<std::pair<std::string, std::string>> files;
                files.reserve(static_cast<size_t>(count));
                for (int32_t i = 0; i < count; i++) {
                    std::string src = std::string(android::String8(data.readString16()).c_str());
                    std::string entry = std::string(android::String8(data.readString16()).c_str());
                    files.emplace_back(std::move(src), std::move(entry));
                }

                bool ok = ZipMultiFileToZip(files, out);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case WRITE_FILE: {
                std::string out = std::string(android::String8(data.readString16()).c_str());
                // Java writes a length-prefixed byte[] via Parcel.writeByteArray.
                int32_t len = data.readInt32();
                if (len < 0) {
                    // Null byte[] is not accepted.
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }

                // Keep the parcel payload bounded to avoid memory abuse.
                constexpr int32_t kMaxBytes = 8 * 1024 * 1024;
                if (len > kMaxBytes) {
                    LOG(ERROR) << "WRITE_FILE payload too large: " << len;
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }

                const void* p = data.readInplace(static_cast<size_t>(len));
                if (len > 0 && p == nullptr) {
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }

                const uint8_t* bytes = reinterpret_cast<const uint8_t*>(p);
                bool ok = WriteFileAtomic(out, bytes, static_cast<size_t>(len));
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case CHOWN_AND_RESTORECON: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                int32_t uid = data.readInt32();
                int32_t gid = data.readInt32();
                if (uid < 0) {
                    LOG(ERROR) << "Invalid uid for CHOWN_AND_RESTORECON";
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }
                bool ok = FixupOwnershipAndSelinux(p, uid, gid);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case DELETE_TREE: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                bool ok = RemoveTree(p);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case SET_PASSWORD: {
                std::string pw = std::string(android::String8(data.readString16()).c_str());
                bool ok = WritePassword(pw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case GET_PASSWORD: {
                std::string pw;
                bool ok = ReadFileToString(kPasswordPath, &pw);
                reply->writeInt32(ok ? 0 : -1);
                if (ok) {
                    reply->writeString16(android::String16(pw.c_str()));
                }
                return android::NO_ERROR;
            }
            case CHANGE_PASSWORD: {
                std::string oldPw = std::string(android::String8(data.readString16()).c_str());
                std::string newPw = std::string(android::String8(data.readString16()).c_str());
                bool ok = ChangePassword(oldPw, newPw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case ENCRYPT_ZIP_IN_PLACE: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                std::string pw = std::string(android::String8(data.readString16()).c_str());
                bool ok = EncryptZipInPlace(p, pw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case DECRYPT_ZIP_TO_FILE: {
                std::string enc = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                std::string pw = std::string(android::String8(data.readString16()).c_str());
                bool ok = DecryptZipToFile(enc, out, pw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            default:
                return android::BBinder::onTransact(code, data, reply, flags);
        }
    }
};

}  // namespace

int main(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    if (sm == nullptr) {
        LOG(FATAL) << "No ServiceManager";
        return 1;
    }

    android::sp<TrueBackupDaemonService> service = new TrueBackupDaemonService();
    android::status_t status = sm->addService(android::String16(kServiceName), service);
    if (status != android::OK) {
        LOG(FATAL) << "Failed to add service " << kServiceName << " status=" << status;
        return 1;
    }

    LOG(INFO) << "truebackupd registered";

    if (!EnsureSystemWritableTempDir(kTrueBackupTmpDir)) {
        LOG(WARNING) << "Could not prepare " << kTrueBackupTmpDir;
    }

    android::sp<android::ProcessState> ps = android::ProcessState::self();
    ps->startThreadPool();
    android::IPCThreadState::self()->joinThreadPool();

    return 0;
}
