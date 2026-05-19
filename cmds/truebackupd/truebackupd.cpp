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

#include <android-base/unique_fd.h>

#include "truebackup_archive.h"

namespace {

constexpr const char* kServiceName = "truebackupd";
constexpr uint32_t kInterfaceToken = 0x5452424b;  // 'TRBK'

enum Transaction : uint32_t {
    TAR_DIR = android::IBinder::FIRST_CALL_TRANSACTION,
    UNTAR_TO_DIR = android::IBinder::FIRST_CALL_TRANSACTION + 1,
    MKDIRS = android::IBinder::FIRST_CALL_TRANSACTION + 2,
    TAR_SINGLE_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 3,
    TAR_MULTI_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 4,
    WRITE_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 5,
    /** Recursive chown + recursive setfilecon(context). */
    CHOWN_AND_CHCON = android::IBinder::FIRST_CALL_TRANSACTION + 13,
    /** Recursively delete a directory tree (backup package folder under …/apps/…). */
    DELETE_TREE = android::IBinder::FIRST_CALL_TRANSACTION + 7,
    /** Store TrueBackup registration password (fixed location under /data/system/truebackup). */
    SET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 8,
    /** Read TrueBackup registration password (fixed location under /data/system/truebackup). */
    GET_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 9,
    /** Encrypt a plain tar archive in place (TBK2: salt + iv + AES-256-CBC). */
    ENCRYPT_ARCHIVE_IN_PLACE = android::IBinder::FIRST_CALL_TRANSACTION + 10,
    /** Decrypt TBK2 archive to a plain tar file. */
    DECRYPT_ARCHIVE_TO_FILE = android::IBinder::FIRST_CALL_TRANSACTION + 11,
    /** Change registration password (requires old password). */
    CHANGE_PASSWORD = android::IBinder::FIRST_CALL_TRANSACTION + 12,
    /** Recursively re-encrypt backup archives under a directory tree. */
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
static bool TarDir(const std::string& srcDir, const std::string& outPath);
static bool UntarToDir(const std::string& archivePath, const std::string& outDir);
static bool IsDotOrDotDot(const char* name);
static bool ChownRecursive(const std::string& path, uid_t uid, gid_t gid);
static bool ChmodRecursive(const std::string& path, mode_t mode);
static bool SetfileconRecursive(const std::string& path, const std::string& context);
static bool FixupOwnershipAndContext(const std::string& path, int32_t uid, int32_t gid,
                                     const std::string& context, int32_t mode);
static bool RemoveTree(const std::string& path);
static bool WriteFileAtomic(const std::string& outPath, const uint8_t* data, size_t dataLen);
static bool RekeyBackupTree(const std::string& dir, const std::string& oldPw, const std::string& newPw);
static bool RekeyArchiveFile(const std::string& path, const std::string& oldPw, const std::string& newPw);
static bool IsEncryptedFilePath(const std::string& path);
static bool HasEncryptedBackupArchive(const std::string& dir, std::string* outPath);
static bool MakeTempPathInTmpDir(std::string* outPath);
static bool EncryptArchiveInPlace(const std::string& path, const std::string& password);
static bool DecryptArchiveToFile(const std::string& encPath, const std::string& outPath,
                                 const std::string& password);
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

static bool HasEncryptedBackupArchive(const std::string& dir, std::string* outPath) {
    struct stat st;
    if (lstat(dir.c_str(), &st) != 0) return false;
    if (S_ISLNK(st.st_mode)) return false;
    if (!S_ISDIR(st.st_mode)) {
        if (!android::base::EndsWith(dir, ".tbak")) return false;
        if (!IsEncryptedFilePath(dir)) return false;
        if (outPath) *outPath = dir;
        return true;
    }

    DIR* d = opendir(dir.c_str());
    if (!d) return false;
    bool found = false;
    dirent* de;
    while (!found && (de = readdir(d)) != nullptr) {
        if (IsDotOrDotDot(de->d_name)) continue;
        const std::string child = dir + "/" + de->d_name;
        if (HasEncryptedBackupArchive(child, outPath)) {
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

    std::string encPath;
    for (const auto& c : candidates) {
        if (HasEncryptedBackupArchive(c, &encPath)) {
            std::string tmpOut;
            if (!MakeTempPathInTmpDir(&tmpOut)) return false;
            const bool ok = DecryptArchiveToFile(encPath, tmpOut, password);
            (void)unlink(tmpOut.c_str());
            return ok;
        }
    }
    return true;  // no encrypted backup found => allow first set
}

static bool TarSingleFile(const std::string& srcFile, const std::string& outPath,
                          const std::string& entryName) {
    std::vector<std::pair<std::string, std::string>> files;
    files.emplace_back(srcFile, entryName);
    return truebackup::TarFiles(files, outPath);
}

static bool TarMultiFile(const std::vector<std::pair<std::string, std::string>>& files,
                         const std::string& outPath) {
    return truebackup::TarFiles(files, outPath);
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

static bool TarDir(const std::string& srcDir, const std::string& outPath) {
    return truebackup::TarDirectory(srcDir, outPath, truebackup::ClassifyBackupSource(srcDir));
}

static bool UntarToDir(const std::string& archivePath, const std::string& outDir) {
    if (truebackup::IsEncryptedArchivePath(archivePath)) {
        LOG(ERROR) << "UntarToDir: encrypted archive must be decrypted first: " << archivePath;
        return false;
    }
    return truebackup::UntarToDirectory(archivePath, outDir);
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

/** User-visible backup root under /data/media/<user>/<folder> (not …/backup/… itself). */
static std::string SharedStorageBackupRoot(const std::string& path) {
    if (!android::base::StartsWith(path, "/data/media/")) return {};
    const size_t backup = path.find("/backup");
    if (backup != std::string::npos && backup > 0) {
        return path.substr(0, backup);
    }
    const size_t apps = path.find("/apps");
    if (apps != std::string::npos && apps > 0) {
        return path.substr(0, apps);
    }
    return path;
}

/** media_rw uid/gid so file managers can list backups on emulated storage. */
static void FixupSharedStorageBackupOwnership(const std::string& path) {
    const std::string root = SharedStorageBackupRoot(path);
    if (root.empty()) return;
    constexpr uid_t kMediaRwUid = 1023;
    constexpr gid_t kMediaRwGid = 1023;
    if (!ChownRecursive(root, kMediaRwUid, kMediaRwGid)) {
        PLOG(WARNING) << "ChownRecursive failed for " << root;
    }
    if (!ChmodRecursive(root, 0775)) {
        PLOG(WARNING) << "ChmodRecursive failed for " << root;
    }
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
    return truebackup::IsEncryptedArchivePath(path);
}

static bool RekeyArchiveFile(const std::string& path, const std::string& oldPw, const std::string& newPw) {
    return truebackup::ReEncryptArchiveFile(path, oldPw, newPw);
}

static bool EncryptArchiveInPlace(const std::string& path, const std::string& password) {
    return truebackup::EncryptTarInPlace(path, password);
}

static bool DecryptArchiveToFile(const std::string& encPath, const std::string& outPath,
                                 const std::string& password) {
    if (!truebackup::DecryptToPlainTar(encPath, outPath, password)) {
        return false;
    }
    const std::string prefix = std::string(kTrueBackupTmpDir) + "/";
    if (outPath.size() > prefix.size() && outPath.compare(0, prefix.size(), prefix) == 0) {
        if (chmod(outPath.c_str(), 0644) != 0) {
            PLOG(WARNING) << "chmod decrypted tmp: " << outPath;
        }
    }
    return true;
}

static bool RekeyBackupTree(const std::string& dir, const std::string& oldPw, const std::string& newPw) {
    if (dir.empty() || dir[0] != '/' || newPw.empty()) return false;
    struct stat st;
    if (lstat(dir.c_str(), &st) != 0) {
        PLOG(ERROR) << "RekeyBackupTree lstat: " << dir;
        return false;
    }
    if (S_ISLNK(st.st_mode)) return true;
    if (!S_ISDIR(st.st_mode)) return RekeyArchiveFile(dir, oldPw, newPw);

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
            case TAR_DIR: {
                std::string src = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                bool ok = TarDir(src, out);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case UNTAR_TO_DIR: {
                std::string archive = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                bool ok = UntarToDir(archive, out);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case MKDIRS: {
                std::string path = std::string(android::String8(data.readString16()).c_str());
                bool ok = (path == kTrueBackupTmpDir) ? EnsureSystemWritableTempDir(path)
                                                        : EnsureDir(path);
                if (ok && path != kTrueBackupTmpDir) {
                    FixupSharedStorageBackupOwnership(path);
                }
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case TAR_SINGLE_FILE: {
                std::string src = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                std::string entry = std::string(android::String8(data.readString16()).c_str());
                bool ok = TarSingleFile(src, out, entry);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case TAR_MULTI_FILE: {
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

                bool ok = TarMultiFile(files, out);
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
            case ENCRYPT_ARCHIVE_IN_PLACE: {
                std::string p = std::string(android::String8(data.readString16()).c_str());
                std::string pw = std::string(android::String8(data.readString16()).c_str());
                bool ok = EncryptArchiveInPlace(p, pw);
                reply->writeInt32(ok ? 0 : -1);
                return android::NO_ERROR;
            }
            case DECRYPT_ARCHIVE_TO_FILE: {
                std::string enc = std::string(android::String8(data.readString16()).c_str());
                std::string out = std::string(android::String8(data.readString16()).c_str());
                std::string pw = std::string(android::String8(data.readString16()).c_str());
                bool ok = DecryptArchiveToFile(enc, out, pw);
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
