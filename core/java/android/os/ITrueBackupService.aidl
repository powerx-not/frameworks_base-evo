package android.os;

/** @hide */
interface ITrueBackupService {
    void backupPackage(String packageName, String destPath);
    void restorePackage(String packageName, String sourcePath);

    /** Queue deleting one app backup (same worker as backup/restore). */
    void enqueueDeleteBackupPackage(String basePath, String packageName);
    String[] listBackedUpApps(String basePath);
    boolean isOperationInProgress();

    /** {@code "backup"}, {@code "restore"}, or {@code "delete"} while a job runs; null when idle. */
    String getActiveOperationKind();

    /** Package name of the job currently executing; null when idle. */
    String getActiveOperationPackage();

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
