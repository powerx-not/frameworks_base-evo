/*
 * Copyright (C) 2026
 *
 * Licensed under the Apache License, Version 2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace truebackup {

enum class BackupPathClass {
    kOther = 0,
    kUserData,
    kSharedAndroid,
};

/** Classify a source directory for backup exclusion rules (user CE/DE vs shared Android). */
BackupPathClass ClassifyBackupSource(const std::string& srcDir);

/** TrueBackup encrypted archive: [TBK2 magic][salt 8][iv 16][AES-256-CBC encrypted ustar tar]. */
bool IsEncryptedArchivePath(const std::string& path);

bool TarDirectory(const std::string& srcDir, const std::string& outTarPath, BackupPathClass pathClass);
bool TarFiles(const std::vector<std::pair<std::string, std::string>>& files,
              const std::string& outTarPath);
bool UntarToDirectory(const std::string& tarPath, const std::string& outDir);

bool EncryptTarInPlace(const std::string& path, const std::string& password);
bool DecryptToPlainTar(const std::string& encPath, const std::string& outTarPath,
                       const std::string& password);
bool DecryptExtractToDirectory(const std::string& encPath, const std::string& outDir,
                               const std::string& password);
bool ReEncryptArchiveFile(const std::string& path, const std::string& oldPassword,
                          const std::string& newPassword);

}  // namespace truebackup
