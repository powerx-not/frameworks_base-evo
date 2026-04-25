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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <selinux/android.h>
#include <selinux/selinux.h>

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
    /** Recursive chown + recursive setfilecon(context). */
    CHOWN_AND_CHCON = android::IBinder::FIRST_CALL_TRANSACTION + 13,
    /** Recursively delete a directory tree (backup package folder under …/apps/…). */
    DELETE_TREE = android::IBinder::FIRST_CALL_TRANSACTION + 7,
    /** Store TrueBackup registration password (fixed location under /data/system/truebackup). */
    SET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 8,
    /** Read TrueBackup registration password (fixed location under /data/system/truebackup). */
    GET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 9,
    /** Encrypt a plain file in place (TBK1 container with wrapped master key). */
    ENCRYPT_ZIP_IN_PLACE = android::IBinder::FIRST_CALL_TRANSACTION + 10,
    /** Decrypt TBK1 file to a new path. */
    DECRYPT_ZIP_TO_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 11,
    /** Change registration password (requires old password). */
    CHANGE_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 12,
    /** Recursively re-encrypt zip backups under a directory tree. */
    REKEY_BACKUP_TREE = android::IBinder::FIRST_CALL_TRANSACTION + 14,
    /** Append a backup base path to known_paths.txt (daemon-owned; system_server cannot write). */
    APPEND_KNOWN_BACKUP_PATH = android::IBinder::FIRST_CALL_TRANSACTION + 15,
    /** Return contents of known_paths.txt for rekey discovery. */
    LIST_KNOWN_BACKUP_PATHS = android::IBinder::FIRST_CALL_TRANSACTION + 16,
    /** Delete registration password file. */
    CLEAR_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 17,
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
static bool IsDotOrDotDot(const char* name);
static bool IsPathTraversal(const std::string& entryName);
static bool ChownRecursive(const std::string& path, uid_t uid, gid_t gid);
static bool ChmodRecursive(const std::string& path, mode_t mode);
static bool SetfileconRecursive(const std::string& path, const std::string& context);
static bool FixupOwnershipAndContext(const std::string& path, int32_t uid, int32_t gid,
                                     const std::string& context, int32_t mode);
static bool RemoveTree(const std::string& path);
static bool WriteFileAtomic(const std::string& outPath, const uint8_t* data, size_t dataLen);
static bool RekeyBackupTree(const std::string& dir, const std::string& oldPw, const std::string& newPw);
static bool RekeyZipFile(const std::string& zipPath, const std::string& oldPw, const std::string& newPw);
static bool IsEncryptedFilePath(const std::string& path);
static bool HasEncryptedBackupZip(const std::string& dir, std::string* outZipPath);
static bool MakeTempPathInTmpDir(std::string* outPath);
static bool EncryptZipInPlace(const std::string& path, const std::string& password);
static bool DecryptZipToFile(const std::string& encPath, const std::string& outPath, const std::string& password);
static bool CanDecryptAnyKnownEncryptedBackup(const std::string& password);

static const char* kPasswordPath = "/data/system/truebackup/registration_password.bin";
/** One path per line; used to find backup trees for password rekey. */
static const char* kKnownPathsPath = "/data/system/truebackup/known_paths.txt";
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

static bool ClearPassword() {
    if (unlink(kPasswordPath) == 0) return true;
    return errno == ENOENT;
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

static constexpr uid_t kSystemUid = 1000;
static constexpr gid_t kSystemGid = 1000;

static bool AppendKnownBackupPathLine(const std::string& basePath) {
    const std::string trimmed = android::base::Trim(basePath);
    if (trimmed.empty() || trimmed[0] != '/') return false;

    const std::string parent = Dirname(std::string(kKnownPathsPath));
    if (!EnsureDir(parent, 0755)) {
        LOG(ERROR) << "AppendKnownBackupPathLine: mkdir parent failed: " << parent;
        return false;
    }

    std::string cur;
    (void)ReadFileToString(kKnownPathsPath, &cur);

    std::set<std::string> uniq;
    for (const auto& line : android::base::Split(cur, "\n")) {
        const std::string t = android::base::Trim(line);
        if (!t.empty()) uniq.insert(t);
    }
    if (uniq.count(trimmed) != 0) return true;
    uniq.insert(trimmed);

    std::string out;
    bool first = true;
    for (const auto& p : uniq) {
        if (!first) out += "\n";
        first = false;
        out += p;
    }
    out += "\n";

    if (!WriteFileAtomic(kKnownPathsPath, reinterpret_cast<const uint8_t*>(out.data()), out.size())) {
        return false;
    }
    if (chmod(kKnownPathsPath, 0640) != 0) {
        PLOG(WARNING) << "chmod known_paths";
    }
    if (::chown(kKnownPathsPath, kSystemUid, kSystemGid) != 0) {
        PLOG(WARNING) << "chown known_paths";
    }
    return true;
}

static bool IsLikelyBackupAppsDir(const std::string& path) {
    return android::base::EndsWith(path, "/apps") || path == "apps";
}

static bool HasEncryptedBackupZip(const std::string& dir, std::string* outZipPath) {
    struct stat st;
    if (lstat(dir.c_str(), &st) != 0) return false;
    if (S_ISLNK(st.st_mode)) return false;
    if (!S_ISDIR(st.st_mode)) {
        if (!android::base::EndsWith(dir, ".zip")) return false;
        if (!IsEncryptedFilePath(dir)) return false;
        if (outZipPath) *outZipPath = dir;
        return true;
    }

    DIR* d = opendir(dir.c_str());
    if (!d) return false;
    bool found = false;
    dirent* de;
    while (!found && (de = readdir(d)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        const std::string child = dir + "/" + de->d_name;
        if (HasEncryptedBackupZip(child, outZipPath)) {
            found = true;
        }
    }
    closedir(d);
    return found;
}

static bool CanDecryptAnyKnownEncryptedBackup(const std::string& password) {
    if (password.empty()) return false;
    std::string known;
    if (!ReadFileToString(kKnownPathsPath, &known)) return true;  // nothing known => don't block first set

    std::set<std::string> candidates;
    for (const auto& raw : android::base::Split(known, "\n")) {
        std::string p = android::base::Trim(raw);
        if (p.empty() || p[0] != '/') continue;
        candidates.insert(p);
        if (!IsLikelyBackupAppsDir(p)) {
            candidates.insert(p + "/apps");
            candidates.insert(p + "/backup/apps");
        }
    }

    std::string encZip;
    for (const auto& c : candidates) {
        if (HasEncryptedBackupZip(c, &encZip)) {
            std::string tmpOut;
            if (!MakeTempPathInTmpDir(&tmpOut)) return false;
            const bool ok = DecryptZipToFile(encZip, tmpOut, password);
            (void)unlink(tmpOut.c_str());
            return ok;
        }
    }
    return true;  // no encrypted backup found => allow first set
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

static bool MakeTempPathInTmpDir(std::string* outPath) {
    if (!outPath) return false;
    if (!EnsureSystemWritableTempDir(kTrueBackupTmpDir)) return false;

    std::string templ = std::string(kTrueBackupTmpDir) + "/tb_rekey_XXXXXX";
    std::vector<char> buf(templ.begin(), templ.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if (fd < 0) {
        PLOG(ERROR) << "mkstemp failed";
        return false;
    }
    close(fd);
    *outPath = std::string(buf.data());
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

static bool ChmodRecursive(const std::string& path, mode_t mode) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        PLOG(ERROR) << "lstat failed: " << path;
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        return true;
    }
    if (chmod(path.c_str(), mode) != 0) {
        PLOG(ERROR) << "chmod failed: " << path;
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
    bool ok = true;
    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        std::string child = path + "/" + de->d_name;
        if (!ChmodRecursive(child, mode)) {
            ok = false;
        }
    }
    closedir(dir);
    return ok;
}

static bool SetfileconRecursive(const std::string& path, const std::string& context) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        PLOG(ERROR) << "SetfileconRecursive lstat failed: " << path;
        return false;
    }

    if (lsetfilecon(path.c_str(), context.c_str()) != 0) {
        PLOG(ERROR) << "lsetfilecon failed: " << path;
        return false;
    }

    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) return true;

    DIR* dir = opendir(path.c_str());
    if (!dir) {
        PLOG(ERROR) << "SetfileconRecursive opendir failed: " << path;
        return false;
    }
    bool ok = true;
    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        std::string child = path + "/" + de->d_name;
        if (!SetfileconRecursive(child, context)) {
            ok = false;
        }
    }
    closedir(dir);
    return ok;
}

static bool FixupOwnershipAndContext(const std::string& path, int32_t uid32, int32_t gid32,
                                     const std::string& context, int32_t mode32) {
    if (path.empty() || path[0] != '/' || context.empty()) {
        LOG(ERROR) << "Invalid args for FixupOwnershipAndContext";
        return false;
    }

    uid_t uid = static_cast<uid_t>(uid32);
    gid_t gid = (gid32 < 0) ? uid : static_cast<gid_t>(gid32);

    if (!ChownRecursive(path, uid, gid)) return false;
    if (mode32 >= 0) {
        const mode_t m = static_cast<mode_t>(mode32) & 07777u;
        if (!ChmodRecursive(path, m)) return false;
    }
    if (!SetfileconRecursive(path, context)) return false;
    return true;
}

static bool IsEncryptedFilePath(const std::string& path) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) return false;
    uint8_t m[4];
    ssize_t n = read(fd.get(), m, sizeof(m));
    if (n != static_cast<ssize_t>(sizeof(m))) return false;
    static const uint8_t kMagic[4] = {'T', 'B', 'K', '1'};
    return memcmp(m, kMagic, sizeof(kMagic)) == 0;
}

static bool CopyFileContents(const std::string& src, const std::string& dst, mode_t* priorModeOut) {
    if (priorModeOut) {
        struct stat st;
        if (stat(dst.c_str(), &st) == 0) {
            *priorModeOut = st.st_mode & 07777u;
        } else {
            *priorModeOut = 0;
        }
    }

    android::base::unique_fd in(open(src.c_str(), O_RDONLY | O_CLOEXEC));
    if (in.get() < 0) {
        PLOG(ERROR) << "open src failed: " << src;
        return false;
    }

    // Best-effort replace destination (cross-filesystem rename won't work for /data/system/tmp -> /storage).
    (void)unlink(dst.c_str());
    android::base::unique_fd out(open(dst.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644));
    if (out.get() < 0) {
        PLOG(ERROR) << "open dst failed: " << dst;
        return false;
    }

    std::vector<uint8_t> buf(256 * 1024);
    while (true) {
        ssize_t n = read(in.get(), buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            PLOG(ERROR) << "read failed: " << src;
            return false;
        }
        if (n == 0) break;
        size_t written = 0;
        while (written < static_cast<size_t>(n)) {
            ssize_t w = write(out.get(), buf.data() + written, static_cast<size_t>(n) - written);
            if (w < 0) {
                if (errno == EINTR) continue;
                PLOG(ERROR) << "write failed: " << dst;
                return false;
            }
            written += static_cast<size_t>(w);
        }
    }
    return true;
}

static bool RekeyZipFile(const std::string& zipPath, const std::string& oldPw, const std::string& newPw) {
    if (zipPath.empty() || zipPath[0] != '/' || newPw.empty()) return false;
    if (!android::base::EndsWith(zipPath, ".zip")) return true;

    const bool encrypted = IsEncryptedFilePath(zipPath);
    if (!encrypted) {
        return EncryptZipInPlace(zipPath, newPw);
    }
    if (oldPw.empty()) {
        LOG(WARNING) << "RekeyZipFile: old password missing for " << zipPath;
        return false;
    }

    std::string tmpPlain;
    if (!MakeTempPathInTmpDir(&tmpPlain)) return false;

    bool ok = false;
    mode_t priorMode = 0;
    do {
        if (!DecryptZipToFile(zipPath, tmpPlain, oldPw)) break;
        if (!CopyFileContents(tmpPlain, zipPath, &priorMode)) break;
        if (priorMode != 0) (void)chmod(zipPath.c_str(), priorMode);
        if (!EncryptZipInPlace(zipPath, newPw)) break;
        ok = true;
    } while (false);

    (void)unlink(tmpPlain.c_str());
    return ok;
}

static bool RekeyBackupTree(const std::string& dir, const std::string& oldPw, const std::string& newPw) {
    if (dir.empty() || dir[0] != '/' || newPw.empty()) return false;
    struct stat st;
    if (lstat(dir.c_str(), &st) != 0) {
        PLOG(ERROR) << "RekeyBackupTree lstat: " << dir;
        return false;
    }
    if (S_ISLNK(st.st_mode)) return true;
    if (!S_ISDIR(st.st_mode)) return RekeyZipFile(dir, oldPw, newPw);

    DIR* d = opendir(dir.c_str());
    if (!d) {
        PLOG(ERROR) << "RekeyBackupTree opendir: " << dir;
        return false;
    }
    bool ok = true;
    dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        std::string child = dir + "/" + de->d_name;
        if (!RekeyBackupTree(child, oldPw, newPw)) ok = false;
    }
    closedir(d);
    return ok;
}

// TrueBackup container v1: wrapped master key in header + payload encrypted by master key.
constexpr uint8_t kEncMagic[] = {'T', 'B', 'K', '1'};
constexpr int kEncVersion = 1;
constexpr size_t kEncSaltLen = 16;
constexpr size_t kWrapIvLen = 12;
constexpr size_t kPayloadIvLen = 12;
constexpr size_t kMasterKeyLen = 32;
constexpr int kEncPbkdf2Iters = 120000;
constexpr size_t kGcmTagLen = 16;
constexpr size_t kWrappedMasterLen = kMasterKeyLen + kGcmTagLen;

static void WriteU32Be(FILE* out, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>((v >> 24) & 0xff),
        static_cast<uint8_t>((v >> 16) & 0xff),
        static_cast<uint8_t>((v >> 8) & 0xff),
        static_cast<uint8_t>(v & 0xff),
    };
    fwrite(b, 1, sizeof(b), out);
}

static bool ReadU32Be(FILE* in, uint32_t* out) {
    uint8_t b[4];
    if (fread(b, 1, sizeof(b), in) != sizeof(b)) return false;
    *out = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    return true;
}

static bool DeriveKey(const std::string& password, const uint8_t* salt, size_t saltLen, uint8_t outKey[32],
                      uint32_t iterations = static_cast<uint32_t>(kEncPbkdf2Iters)) {
    // Matches Java PBKDF2WithHmacSHA256 (BoringSSL uses PKCS5_PBKDF2_HMAC + EVP_sha256).
    return PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()), password.size(), salt, saltLen,
                             iterations, EVP_sha256(), 32, outKey) == 1;
}

/**
 * Encrypts a regular file in place to TBK1:
 * [magic|version|iterations|salt|wrap_iv|payload_iv|wrapped_master|encrypted_payload|payload_tag]
 * If file already starts with TBK1, returns true.
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
    uint8_t wrapIv[kWrapIvLen];
    uint8_t payloadIv[kPayloadIvLen];
    uint8_t masterKey[kMasterKeyLen];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(wrapIv, sizeof(wrapIv)) != 1 ||
        RAND_bytes(payloadIv, sizeof(payloadIv)) != 1 || RAND_bytes(masterKey, sizeof(masterKey)) != 1) {
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    uint8_t unlockKey[32];
    if (!DeriveKey(password, salt, sizeof(salt), unlockKey)) {
        OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
        OPENSSL_cleanse(masterKey, sizeof(masterKey));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    uint8_t wrappedMaster[kWrappedMasterLen];
    {
        EVP_CIPHER_CTX* wrapCtx = EVP_CIPHER_CTX_new();
        if (!wrapCtx) {
            OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
            OPENSSL_cleanse(masterKey, sizeof(masterKey));
            fclose(in);
            fclose(out);
            unlink(tmpPath.c_str());
            return false;
        }
        bool wrapOk = false;
        do {
            if (EVP_EncryptInit_ex(wrapCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(wrapCtx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kWrapIvLen), nullptr) != 1) {
                break;
            }
            if (EVP_EncryptInit_ex(wrapCtx, nullptr, nullptr, unlockKey, wrapIv) != 1) break;
            int outLen = 0;
            if (EVP_EncryptUpdate(wrapCtx, wrappedMaster, &outLen, masterKey, static_cast<int>(kMasterKeyLen)) != 1) {
                break;
            }
            if (outLen != static_cast<int>(kMasterKeyLen)) break;
            int finalLen = 0;
            if (EVP_EncryptFinal_ex(wrapCtx, wrappedMaster + outLen, &finalLen) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(wrapCtx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kGcmTagLen),
                                    wrappedMaster + kMasterKeyLen) != 1) {
                break;
            }
            wrapOk = true;
        } while (false);
        EVP_CIPHER_CTX_free(wrapCtx);
        if (!wrapOk) {
            OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
            OPENSSL_cleanse(masterKey, sizeof(masterKey));
            fclose(in);
            fclose(out);
            unlink(tmpPath.c_str());
            return false;
        }
    }

    if (fwrite(kEncMagic, 1, 4, out) != 4 || fputc(kEncVersion, out) == EOF) {
        OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
        OPENSSL_cleanse(masterKey, sizeof(masterKey));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }
    WriteU32Be(out, static_cast<uint32_t>(kEncPbkdf2Iters));
    if (fwrite(salt, 1, sizeof(salt), out) != sizeof(salt) || fwrite(wrapIv, 1, sizeof(wrapIv), out) != sizeof(wrapIv) ||
        fwrite(payloadIv, 1, sizeof(payloadIv), out) != sizeof(payloadIv) ||
        fwrite(wrappedMaster, 1, sizeof(wrappedMaster), out) != sizeof(wrappedMaster)) {
        OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
        OPENSSL_cleanse(masterKey, sizeof(masterKey));
        OPENSSL_cleanse(wrappedMaster, sizeof(wrappedMaster));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }
    OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
    OPENSSL_cleanse(wrappedMaster, sizeof(wrappedMaster));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(masterKey, sizeof(masterKey));
        fclose(in);
        fclose(out);
        unlink(tmpPath.c_str());
        return false;
    }

    int ok = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kPayloadIvLen), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, masterKey, payloadIv) != 1) break;

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
    OPENSSL_cleanse(masterKey, sizeof(masterKey));
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
    uint32_t iterations = 0;
    if (!ReadU32Be(in, &iterations) || iterations == 0) {
        fclose(in);
        return false;
    }
    uint8_t salt[kEncSaltLen];
    uint8_t wrapIv[kWrapIvLen];
    uint8_t payloadIv[kPayloadIvLen];
    uint8_t wrappedMaster[kWrappedMasterLen];
    if (fread(salt, 1, sizeof(salt), in) != sizeof(salt) || fread(wrapIv, 1, sizeof(wrapIv), in) != sizeof(wrapIv) ||
        fread(payloadIv, 1, sizeof(payloadIv), in) != sizeof(payloadIv) ||
        fread(wrappedMaster, 1, sizeof(wrappedMaster), in) != sizeof(wrappedMaster)) {
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

    uint8_t unlockKey[32];
    if (!DeriveKey(password, salt, sizeof(salt), unlockKey, iterations)) {
        OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
        fclose(in);
        fclose(out);
        unlink(outPath.c_str());
        return false;
    }

    uint8_t masterKey[kMasterKeyLen];
    {
        EVP_CIPHER_CTX* unwrapCtx = EVP_CIPHER_CTX_new();
        if (!unwrapCtx) {
            OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
            fclose(in);
            fclose(out);
            unlink(outPath.c_str());
            return false;
        }
        bool unwrapOk = false;
        do {
            if (EVP_DecryptInit_ex(unwrapCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(unwrapCtx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kWrapIvLen), nullptr) != 1) {
                break;
            }
            if (EVP_DecryptInit_ex(unwrapCtx, nullptr, nullptr, unlockKey, wrapIv) != 1) break;
            int outLen = 0;
            if (EVP_DecryptUpdate(unwrapCtx, masterKey, &outLen, wrappedMaster, static_cast<int>(kMasterKeyLen)) != 1) {
                break;
            }
            if (outLen != static_cast<int>(kMasterKeyLen)) break;
            if (EVP_CIPHER_CTX_ctrl(unwrapCtx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kGcmTagLen),
                                    wrappedMaster + kMasterKeyLen) != 1) {
                break;
            }
            int finalLen = 0;
            if (EVP_DecryptFinal_ex(unwrapCtx, masterKey + outLen, &finalLen) != 1) break;
            unwrapOk = true;
        } while (false);
        EVP_CIPHER_CTX_free(unwrapCtx);
        OPENSSL_cleanse(unlockKey, sizeof(unlockKey));
        OPENSSL_cleanse(wrappedMaster, sizeof(wrappedMaster));
        if (!unwrapOk) {
            OPENSSL_cleanse(masterKey, sizeof(masterKey));
            fclose(in);
            fclose(out);
            unlink(outPath.c_str());
            return false;
        }
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(masterKey, sizeof(masterKey));
        fclose(in);
        fclose(out);
        unlink(outPath.c_str());
        return false;
    }

    bool fail = true;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kPayloadIvLen), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, masterKey, payloadIv) != 1) break;

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
    OPENSSL_cleanse(masterKey, sizeof(masterKey));
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
            case CHOWN_AND_CHCON: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                int32_t uid = data.readInt32();
                int32_t gid = data.readInt32();
                std::string ctx = std::string(android::String8(data.readString16()).c_str());
                int32_t mode = data.readInt32();
                if (uid < 0 || ctx.empty()) {
                    reply->writeInt32(-1);
                    return android::NO_ERROR;
                }
                bool ok = FixupOwnershipAndContext(p, uid, gid, ctx, mode);
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
                std::string storedPwBlob = std::string(android::String8(data.readString16()).c_str());
                std::string plainPw = std::string(android::String8(data.readString16()).c_str());

                // First registration after reset: if encrypted backups exist, only allow registration
                // with the same password that can decrypt the existing backup set.
                std::string current;
                const bool hasCurrentStored = ReadFileToString(kPasswordPath, &current) && !android::base::Trim(current).empty();
                if (!hasCurrentStored && !plainPw.empty() && !CanDecryptAnyKnownEncryptedBackup(plainPw)) {
                    reply->writeInt32(-2);  // existing backup detected but password mismatch
                    return android::NO_ERROR;
                }

                bool ok = WritePassword(storedPwBlob);
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
            case CLEAR_PASSWORD: {
                bool ok = ClearPassword();
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case REKEY_BACKUP_TREE: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                std::string oldPw = std::string(android::String8(data.readString16()).c_str());
                std::string newPw = std::string(android::String8(data.readString16()).c_str());
                bool ok = RekeyBackupTree(p, oldPw, newPw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case APPEND_KNOWN_BACKUP_PATH: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                bool ok = AppendKnownBackupPathLine(p);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case LIST_KNOWN_BACKUP_PATHS: {
                std::string content;
                (void)ReadFileToString(kKnownPathsPath, &content);
                reply->writeInt32(0);
                reply->writeString16(android::String16(content.c_str()));
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
