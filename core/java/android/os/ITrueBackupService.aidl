package android.os;

/** @hide */
interface ITrueBackupService {
    void backupPackage(String packageName, String destPath);
    void restorePackage(String packageName, String sourcePath);
    String[] listBackedUpApps(String basePath);
    boolean isOperationInProgress();
}
