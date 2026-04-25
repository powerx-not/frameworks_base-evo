package android.os;

/** @hide */
interface ITrueBackupService {
    /** Record the backup base path for future re-encryption. */
    void recordBackupBasePath(String basePath);

    void backupPackage(String packageName, String destPath);
    void restorePackage(String packageName, String sourcePath);

    /** Queue deleting one app backup (same worker as backup/restore). */
    void enqueueDeleteBackupPackage(String basePath, String packageName);

    /** Returns true if a registration password is set. */
    boolean isRegistrationPasswordSet();

    /** Sets (or replaces) the registration password and re-encrypts existing backups. */
    boolean setRegistrationPassword(String newPassword);

    /** Changes the registration password (requires old password) and re-encrypts existing backups. */
    boolean changeRegistrationPassword(String oldPassword, String newPassword);

    /** Resets the registration password and re-encrypts existing backups. */
    boolean resetRegistrationPassword(String newPassword);

    /** Deletes the current registration password. */
    boolean clearRegistrationPassword();
    String[] listBackedUpApps(String basePath);
    boolean isOperationInProgress();

    /** {@code "backup"}, {@code "restore"}, {@code "delete"}, or {@code "rekey"} while a job runs; null when idle. */
    String getActiveOperationKind();

    /** Package name of the job currently executing; null when idle. */
    String getActiveOperationPackage();

    /** 0..100 while active, or -1 when unknown/idle. */
    int getActiveOperationProgressPercent();

    /** Jobs waiting in the queue (not including the one currently running). */
    int getQueuedOperationCount();

    /** Absolute path to the per-package backup dir containing package_restore_config.json, or null. */
    String resolveBackupPackageDir(String basePath, String packageName);

    /** Contents of package_restore_config.json for that package, or null. */
    String readBackupMetadataJson(String basePath, String packageName);

    /** Remove one app backup folder (uses truebackupd when available). */
    boolean deleteBackupPackage(String basePath, String packageName);

    /**
     * Remove backup at an absolute path; must be under the {@code basePath} …/apps/ tree.
     * Use when metadata provides {@code backupConfig.storagePath}.
     */
    boolean deleteBackupPackageAtPath(String basePath, String absolutePackageDir);
}
