package com.android.server;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.net.Uri;
import android.os.Binder;
import android.os.Environment;
import android.os.IBinder;
import android.os.ITrueBackupService;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.SELinux;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.os.UserManager;
import android.system.ErrnoException;
import android.system.Os;
import android.provider.DocumentsContract;
import android.util.Slog;
import android.util.Xml;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.android.internal.app.IAppOpsService;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;

import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Base64;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import android.os.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyStore;

/**
 * Service to handle TrueBackup operations with system privileges.
 * Allows backup and restore of app data without root.
 * @hide
 */
public class TrueBackupService extends ITrueBackupService.Stub {
    private static final String TAG = "TrueBackupService";
    private final Context mContext;

    private static final int OP_BACKUP = 0;
    private static final int OP_RESTORE = 1;
    private static final int OP_DELETE = 2;
    private static final int OP_REKEY = 3;

    private static final class QueuedOperation {
        final int type;
        final String packageName;
        final String path;
        final String arg1;
        final String arg2;
        /** Android user id for backup/restore paths (clone/work profile); 0 for delete/rekey. */
        final int userId;

        QueuedOperation(int type, String packageName, String path, int userId) {
            this.type = type;
            this.packageName = packageName;
            this.path = path;
            this.userId = userId;
            this.arg1 = null;
            this.arg2 = null;
        }

        QueuedOperation(int type, String packageName, String path, String arg1, String arg2) {
            this.type = type;
            this.packageName = packageName;
            this.path = path;
            this.userId = 0;
            this.arg1 = arg1;
            this.arg2 = arg2;
        }
    }

    private final LinkedBlockingQueue<QueuedOperation> mOperationQueue = new LinkedBlockingQueue<>();
    private final AtomicInteger mWorkInFlight = new AtomicInteger(0);
    private volatile boolean mWorkerRunning = false;
    private String mActiveOperationKind = null;
    private String mActiveOperationPackage = null;
    private int mActiveOperationProgressPercent = -1;

    private static final String TRUEBACKUPD_SERVICE = "truebackupd";
    private static final int TRUEBACKUPD_TOKEN = 0x5452424b; // 'TRBK'
    private static final int TRUEBACKUPD_TAR_DIR = IBinder.FIRST_CALL_TRANSACTION;
    private static final int TRUEBACKUPD_UNTAR_TO_DIR = IBinder.FIRST_CALL_TRANSACTION + 1;
    private static final int TRUEBACKUPD_MKDIRS = IBinder.FIRST_CALL_TRANSACTION + 2;
    private static final int TRUEBACKUPD_TAR_MULTI_FILE = IBinder.FIRST_CALL_TRANSACTION + 4;
    private static final int TRUEBACKUPD_WRITE_FILE = IBinder.FIRST_CALL_TRANSACTION + 5;
    private static final int TRUEBACKUPD_CHOWN_AND_CHCON = IBinder.FIRST_CALL_TRANSACTION + 13;
    private static final int TRUEBACKUPD_DELETE_TREE = IBinder.FIRST_CALL_TRANSACTION + 7;
    private static final int TRUEBACKUPD_SET_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 8;
    private static final int TRUEBACKUPD_GET_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 9;
    private static final int TRUEBACKUPD_ENCRYPT_ARCHIVE_IN_PLACE = IBinder.FIRST_CALL_TRANSACTION + 10;
    private static final int TRUEBACKUPD_DECRYPT_ARCHIVE_TO_FILE = IBinder.FIRST_CALL_TRANSACTION + 11;
    private static final int TRUEBACKUPD_CHANGE_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 12;
    private static final int TRUEBACKUPD_REKEY_BACKUP_TREE = IBinder.FIRST_CALL_TRANSACTION + 14;
    private static final int TRUEBACKUPD_APPEND_KNOWN_BACKUP_PATH = IBinder.FIRST_CALL_TRANSACTION + 15;
    private static final int TRUEBACKUPD_LIST_KNOWN_BACKUP_PATHS = IBinder.FIRST_CALL_TRANSACTION + 16;
    private static final int TRUEBACKUPD_CLEAR_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 17;

    /** rwxrw----: package dir under {@code /Android/data/} after restore. */
    private static final int MODE_ANDROID_DATA_DIR = 0760;
    /** rwxrwx---: package dir under {@code /Android/media/} and {@code /Android/obb/}. */
    private static final int MODE_ANDROID_SHARED_PKG_DIR = 0770;

    private static final String FILE_CONFIG = "package_restore_config.json";

    private static final String DIR_APK = "apk";
    private static final String DIR_INT_DATA = "int_data";
    private static final String DIR_EXT_DATA = "ext_data";
    private static final String DIR_ADDL_DATA = "addl_data";

    private static final String ARCH_APK = "apk.tbak";
    private static final String ARCH_USER = "user.tbak";
    private static final String ARCH_USER_DE = "user_de.tbak";
    private static final String ARCH_DATA = "data.tbak";
    private static final String ARCH_OBB = "obb.tbak";
    private static final String ARCH_MEDIA = "media.tbak";


    private static final String SETTINGS_FILE_SSAID = "settings_ssaid.xml";

    private static String ceBase(int userId) {
        return "/data/user/" + userId + "/";
    }

    private static String deBase(int userId) {
        return "/data/user_de/" + userId + "/";
    }

    private static String extDataBase(int userId) {
        return "/data/media/" + userId + "/Android/data/";
    }

    private static String obbBase(int userId) {
        return "/data/media/" + userId + "/Android/obb/";
    }

    private static String mediaBase(int userId) {
        return "/data/media/" + userId + "/Android/media/";
    }

    private static String extDataGidRef(int userId) {
        return "/data/media/" + userId + "/Android/data";
    }

    private static String obbGidRef(int userId) {
        return "/data/media/" + userId + "/Android/obb";
    }

    private static String mediaGidRef(int userId) {
        return "/data/media/" + userId + "/Android/media";
    }

    /** TBK2 magic: [TBK2][salt 8][iv 16][AES-256-CBC encrypted ustar tar] (truebackupd). */
    private static final byte[] ENC_MAGIC = new byte[] { 'T', 'B', 'K', '2' };
    private static final String REG_PW_KEYSTORE = "AndroidKeyStore";
    private static final String REG_PW_KEY_ALIAS = "truebackup_registration_password_v1";
    private static final String REG_PW_BLOB_PREFIX = "tbpw1:";

    public TrueBackupService(Context context) {
        mContext = context;
        Slog.i(TAG, "TrueBackupService Initialized");
    }

    @Override
    public void recordBackupBasePath(String basePath) {
        checkPermission();
        recordKnownBackupPath(basePath);
    }

    @Override
    public void backupPackage(String packageName, String destPath, int userId) throws RemoteException {
        checkPermission();
        if (readRegistrationPassword() == null) {
            Slog.w(TAG, "backupPackage: no registration password set");
            return;
        }
        if (packageName == null || packageName.isEmpty() || destPath == null || destPath.isEmpty()) {
            Slog.w(TAG, "backupPackage: invalid args");
            return;
        }
        final int resolvedUser = resolveBackupUserId(userId);
        if (!isUserAlive(resolvedUser)) {
            Slog.w(TAG, "backupPackage: user not running: " + resolvedUser);
            return;
        }
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_BACKUP, packageName, destPath, resolvedUser));
        } catch (InterruptedException e) {
            mWorkInFlight.decrementAndGet();
            Thread.currentThread().interrupt();
            throw new RemoteException("Interrupted while queueing backup");
        }
        ensureWorker();
    }

    @Override
    public void restorePackage(String packageName, String sourcePath, int userId) throws RemoteException {
        checkPermission();
        if (readRegistrationPassword() == null) {
            Slog.w(TAG, "restorePackage: no registration password set");
            return;
        }
        if (packageName == null || packageName.isEmpty() || sourcePath == null || sourcePath.isEmpty()) {
            Slog.w(TAG, "restorePackage: invalid args");
            return;
        }
        // Remember this tree so future password changes can rekey existing backups there too.
        recordKnownBackupPath(sourcePath);
        final int resolvedUser = resolveRestoreUserId(userId, packageName, sourcePath);
        if (!isUserAlive(resolvedUser)) {
            Slog.w(TAG, "restorePackage: user not running: " + resolvedUser);
            return;
        }
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_RESTORE, packageName, sourcePath, resolvedUser));
        } catch (InterruptedException e) {
            mWorkInFlight.decrementAndGet();
            Thread.currentThread().interrupt();
            throw new RemoteException("Interrupted while queueing restore");
        }
        ensureWorker();
    }

    @Override
    public void enqueueDeleteBackupPackage(String basePath, String packageName) throws RemoteException {
        checkPermission();
        if (basePath == null || basePath.isEmpty() || packageName == null || packageName.isEmpty()) {
            Slog.w(TAG, "enqueueDeleteBackupPackage: invalid args");
            return;
        }
        recordKnownBackupPath(basePath);
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_DELETE, packageName, basePath, 0));
        } catch (InterruptedException e) {
            mWorkInFlight.decrementAndGet();
            Thread.currentThread().interrupt();
            throw new RemoteException("Interrupted while queueing delete");
        }
        ensureWorker();
    }

    @Override
    public boolean isRegistrationPasswordSet() {
        checkPermission();
        return readRegistrationPassword() != null;
    }

    @Override
    public boolean setRegistrationPassword(String newPassword) throws RemoteException {
        checkPermission();
        if (newPassword == null || newPassword.isEmpty()) {
            Slog.w(TAG, "setRegistrationPassword: empty");
            return false;
        }
        final String old = readRegistrationPassword();
        if (!writeRegistrationPassword(newPassword)) {
            return false;
        }
        // Verify persisted.
        final String check = readRegistrationPassword();
        if (check == null || !check.equals(newPassword)) {
            Slog.w(TAG, "setRegistrationPassword: verification failed");
            return false;
        }
        enqueueRekey(old, newPassword);
        return true;
    }

    @Override
    public boolean resetRegistrationPassword(String newPassword) throws RemoteException {
        checkPermission();
        if (newPassword == null || newPassword.isEmpty()) {
            Slog.w(TAG, "resetRegistrationPassword: empty");
            return false;
        }
        final String old = readRegistrationPassword();
        if (old == null || old.isEmpty()) {
            // Treat as first set.
            if (!writeRegistrationPassword(newPassword)) {
                return false;
            }
            enqueueRekey(null, newPassword);
            return true;
        }
        if (!writeRegistrationPassword(newPassword)) {
            return false;
        }
        final String check = readRegistrationPassword();
        if (check == null || !check.equals(newPassword)) {
            Slog.w(TAG, "resetRegistrationPassword: verification failed");
            return false;
        }
        enqueueRekey(old, newPassword);
        return true;
    }

    @Override
    public boolean clearRegistrationPassword() throws RemoteException {
        checkPermission();
        if (!daemonClearRegistrationPassword()) {
            Slog.w(TAG, "clearRegistrationPassword: daemon clear failed");
            return false;
        }
        return readRegistrationPassword() == null;
    }

    @Override
    public boolean changeRegistrationPassword(String oldPassword, String newPassword) throws RemoteException {
        checkPermission();
        if (newPassword == null || newPassword.isEmpty()) {
            Slog.w(TAG, "changeRegistrationPassword: empty new");
            return false;
        }
        if (oldPassword == null || oldPassword.isEmpty()) {
            Slog.w(TAG, "changeRegistrationPassword: empty old");
            return false;
        }
        final String currentPlain = readRegistrationPassword();
        if (currentPlain == null || !currentPlain.equals(oldPassword)) {
            Slog.w(TAG, "changeRegistrationPassword: old password mismatch");
            return false;
        }
        final String currentStored = readRegistrationPasswordStored();
        if (currentStored == null || currentStored.isEmpty()) {
            Slog.w(TAG, "changeRegistrationPassword: missing stored password");
            return false;
        }
        final String newStored = encryptRegisteredPassword(newPassword);
        if (newStored == null || newStored.isEmpty()) {
            Slog.w(TAG, "changeRegistrationPassword: encrypt new failed");
            return false;
        }
        if (!daemonChangeRegistrationPassword(currentStored, newStored)) {
            Slog.w(TAG, "changeRegistrationPassword: daemon change failed");
            return false;
        }
        // Verify persisted.
        final String check = readRegistrationPassword();
        if (check == null || !check.equals(newPassword)) {
            Slog.w(TAG, "changeRegistrationPassword: verification failed");
            return false;
        }
        enqueueRekey(oldPassword, newPassword);
        return true;
    }

    private void enqueueRekey(String oldPassword, String newPassword) throws RemoteException {
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_REKEY, "", "", oldPassword, newPassword));
        } catch (InterruptedException e) {
            mWorkInFlight.decrementAndGet();
            Thread.currentThread().interrupt();
            throw new RemoteException("Interrupted while queueing rekey");
        }
        ensureWorker();
    }

    private synchronized void ensureWorker() {
        if (mWorkerRunning) {
            return;
        }
        mWorkerRunning = true;
        new Thread(this::runOperationWorker, "TrueBackupWorker").start();
    }

    private void setActiveOperationProgressPercent(int percent) {
        final int p = Math.max(0, Math.min(100, percent));
        synchronized (this) {
            mActiveOperationProgressPercent = p;
        }
    }

    private void setActiveProgressStep(int done, int total) {
        if (total <= 0) {
            setActiveOperationProgressPercent(0);
            return;
        }
        setActiveOperationProgressPercent((done * 100) / total);
    }

    private void runOperationWorker() {
        while (true) {
            QueuedOperation op;
            try {
                op = mOperationQueue.take();
            } catch (InterruptedException e) {
                Slog.w(TAG, "operation worker interrupted", e);
                synchronized (this) {
                    mWorkerRunning = false;
                }
                break;
            }
            synchronized (this) {
                switch (op.type) {
                    case OP_RESTORE:
                        mActiveOperationKind = "restore";
                        break;
                    case OP_DELETE:
                        mActiveOperationKind = "delete";
                        break;
                    case OP_REKEY:
                        mActiveOperationKind = "rekey";
                        break;
                    default:
                        mActiveOperationKind = "backup";
                        break;
                }
                mActiveOperationPackage = op.packageName;
                mActiveOperationProgressPercent = 0;
            }
            try {
                switch (op.type) {
                    case OP_RESTORE:
                        executeRestore(op.packageName, op.path, op.userId);
                        break;
                    case OP_DELETE:
                        executeDeleteBackup(op.path, op.packageName);
                        break;
                    case OP_REKEY:
                        executeRekeyAllKnownBackups(op.arg1, op.arg2);
                        break;
                    default:
                        executeBackup(op.packageName, op.path, op.userId);
                        break;
                }
            } catch (Exception e) {
                Slog.e(TAG, "Queued operation failed", e);
            } finally {
                synchronized (this) {
                    mActiveOperationKind = null;
                    mActiveOperationPackage = null;
                    mActiveOperationProgressPercent = -1;
                }
                mWorkInFlight.decrementAndGet();
            }
        }
    }

    private void executeBackup(String packageName, String destPath, int userId) {
        try {
            Slog.d(TAG, "Starting backup for " + packageName + " user " + userId + " to " + destPath);
            recordKnownBackupPath(destPath);
            final int totalSteps = 7;
            int done = 0;
            File pkgDir = resolvePackageBackupDir(destPath, packageName);
            if (!ensureDirs(pkgDir)) {
                Slog.e(TAG, "Could not create backup directory: " + pkgDir);
                return;
            }
            setActiveProgressStep(++done, totalSteps);

            BackupParts parts = new BackupParts();

            // APK
            File apkArch = new File(new File(pkgDir, DIR_APK), ARCH_APK);
            parts.apk = tarApk(packageName, userId, apkArch);
            maybeEncryptInPlace(apkArch);
            setActiveProgressStep(++done, totalSteps);

            // Internal data
            File ceArch = new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER);
            parts.userCe = tarDirIfExists(new File(ceBase(userId), packageName), ceArch);
            maybeEncryptInPlace(ceArch);
            setActiveProgressStep(++done, totalSteps);

            File deArch = new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER_DE);
            parts.userDe = tarDirIfExists(new File(deBase(userId), packageName), deArch);
            maybeEncryptInPlace(deArch);
            setActiveProgressStep(++done, totalSteps);

            // External data
            File extArch = new File(new File(pkgDir, DIR_EXT_DATA), ARCH_DATA);
            parts.extData = tarDirIfExists(new File(extDataBase(userId), packageName), extArch);
            maybeEncryptInPlace(extArch);
            setActiveProgressStep(++done, totalSteps);

            // Additional
            File obbArch = new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_OBB);
            parts.obb = tarDirIfExists(new File(obbBase(userId), packageName), obbArch);
            maybeEncryptInPlace(obbArch);

            File mediaArch = new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_MEDIA);
            parts.media = tarDirIfExists(new File(mediaBase(userId), packageName), mediaArch);
            maybeEncryptInPlace(mediaArch);
            setActiveProgressStep(++done, totalSteps);

            writeConfig(new File(pkgDir, FILE_CONFIG), packageName, userId, parts);
            setActiveProgressStep(++done, totalSteps);

            Slog.i(TAG, "Backup finished successfully for " + packageName);
        } catch (Exception e) {
            Slog.e(TAG, "Backup failed for " + packageName, e);
        }
    }

    private void executeRestore(String packageName, String sourcePath, int userId) {
        try {
            Slog.d(TAG, "Starting restore for " + packageName + " user " + userId + " from " + sourcePath);
            setActiveOperationProgressPercent(5);
            File pkgDir = resolvePackageBackupDir(sourcePath, packageName);
            if (pkgDir.exists()) {
                restoreFromPackageDir(packageName, pkgDir, userId);
            } else {
                Slog.e(TAG, "Source data not found at " + sourcePath);
                return;
            }

            Slog.i(TAG, "Restore finished successfully for " + packageName);
        } catch (Exception e) {
            Slog.e(TAG, "Restore failed for " + packageName, e);
        }
    }

    private void executeDeleteBackup(String basePath, String packageName) {
        try {
            Slog.d(TAG, "Starting delete backup for " + packageName);
            setActiveOperationProgressPercent(10);
            if (deleteBackupPackageInternal(basePath, packageName)) {
                setActiveOperationProgressPercent(100);
                Slog.i(TAG, "Delete finished (primary) for " + packageName);
                return;
            }
            setActiveOperationProgressPercent(40);
            String json = readBackupMetadataJsonInternal(basePath, packageName);
            if (json != null && !json.isEmpty()) {
                try {
                    JSONObject root = new JSONObject(json);
                    JSONObject bc = root.optJSONObject("backupConfig");
                    String sp = bc != null ? bc.optString("storagePath", null) : null;
                    if (sp != null) {
                        String tsp = sp.trim();
                        if (!tsp.isEmpty() && deleteBackupPackageAtPathInternal(basePath, tsp)) {
                            setActiveOperationProgressPercent(100);
                            Slog.i(TAG, "Delete finished (storagePath) for " + packageName);
                            return;
                        }
                    }
                } catch (Exception e) {
                    Slog.w(TAG, "delete metadata path", e);
                }
            }
            if (deleteBackupPackageInternal(basePath, packageName)) {
                setActiveOperationProgressPercent(100);
                Slog.i(TAG, "Delete finished (retry) for " + packageName);
            } else {
                setActiveOperationProgressPercent(100);
                Slog.w(TAG, "Delete failed for " + packageName);
            }
        } catch (Exception e) {
            Slog.e(TAG, "executeDeleteBackup", e);
        }
    }

    private String readBackupMetadataJsonInternal(String basePath, String packageName) {
        File dir = findBackupDirWithMetadata(basePath, packageName);
        if (dir == null) {
            return null;
        }
        File config = new File(dir, FILE_CONFIG);
        try {
            return new String(readFully(config), StandardCharsets.UTF_8);
        } catch (IOException e) {
            Slog.w(TAG, "readBackupMetadataJsonInternal", e);
            return null;
        }
    }

    private boolean deleteBackupPackageInternal(String basePath, String packageName) {
        if (basePath == null || packageName == null || packageName.isEmpty()) {
            return false;
        }
        File dir = findBackupDirWithMetadata(basePath, packageName);
        if (dir == null || !dir.isDirectory()) {
            return false;
        }
        return deletePackageDirInternal(dir);
    }

    private boolean deleteBackupPackageAtPathInternal(String basePath, String absolutePackageDir) {
        if (basePath == null || absolutePackageDir == null || absolutePackageDir.isEmpty()) {
            return false;
        }
        if (!absolutePackageDir.startsWith("/") || !absolutePackageDir.contains("/apps/")) {
            return false;
        }
        try {
            File target = new File(absolutePackageDir).getCanonicalFile();
            if (!target.isDirectory()) {
                return false;
            }
            String tp = target.getPath();
            File appsRoot = resolveAppsDir(basePath);
            if (appsRoot != null) {
                File root = appsRoot.getCanonicalFile();
                String rp = root.getPath();
                if (tp.equals(rp)) {
                    Slog.w(TAG, "deleteBackupPackageAtPathInternal: refusing apps root");
                    return false;
                }
                if (!tp.startsWith(rp + File.separator)) {
                    Slog.w(TAG, "deleteBackupPackageAtPathInternal: path outside apps root");
                    return false;
                }
            } else {
                File base = new File(basePath).getCanonicalFile();
                String bp = base.getPath();
                if (!tp.startsWith(bp + File.separator) && !tp.equals(bp)) {
                    Slog.w(TAG, "deleteBackupPackageAtPathInternal: path outside backup base");
                    return false;
                }
            }
            return deletePackageDirInternal(target);
        } catch (IOException e) {
            Slog.w(TAG, "deleteBackupPackageAtPathInternal", e);
            return false;
        }
    }

    @Override
    public boolean isOperationInProgress() {
        return mWorkInFlight.get() > 0;
    }

    @Override
    public String getActiveOperationKind() {
        checkPermission();
                synchronized (this) {
            return mActiveOperationKind;
        }
    }

    @Override
    public String getActiveOperationPackage() {
        checkPermission();
        synchronized (this) {
            return mActiveOperationPackage;
        }
    }

    @Override
    public int getActiveOperationProgressPercent() {
        checkPermission();
        synchronized (this) {
            return mActiveOperationProgressPercent;
        }
    }

    @Override
    public int getQueuedOperationCount() {
        checkPermission();
        return mOperationQueue.size();
    }

    @Override
    public String[] listBackedUpApps(String basePath) {
        checkPermission();
        File appsDir = resolveAppsDir(basePath);
        if (appsDir == null) return new String[0];

        File[] pkgDirs = appsDir.listFiles();
        if (pkgDirs == null) return new String[0];

        ArrayList<String> out = new ArrayList<>();
        for (File pkgDir : pkgDirs) {
            if (pkgDir == null || !pkgDir.isDirectory()) continue;

            File config = new File(pkgDir, FILE_CONFIG);
            if (!config.exists() || !config.isFile()) continue;

            String pkg = pkgDir.getName();
            String label = "";
            try {
                String json = new String(readFully(config), StandardCharsets.UTF_8);
                JSONObject root = new JSONObject(json);
                JSONObject pkgInfo = root.optJSONObject("packageInfo");
                if (pkgInfo != null) {
                    String pkgFromJson = pkgInfo.optString("packageName", null);
                    if (pkgFromJson != null && !pkgFromJson.isEmpty()) {
                        pkg = pkgFromJson;
                    }
                    String lbl = pkgInfo.optString("appLabel", null);
                    if (lbl == null || lbl.isEmpty()) {
                        lbl = pkgInfo.optString("label", null);
                    }
                    if (lbl != null && !lbl.isEmpty()) {
                        label = lbl;
                    }
                }
            } catch (Exception ignored) {
            }

            out.add(pkg + "|" + label);
        }

        return out.toArray(new String[0]);
    }

    /**
     * Finds an existing per-app backup directory under {@code basePath} that contains
     * {@link #FILE_CONFIG} and matches {@code packageName} (folder name or packageName in JSON).
     */
    private File findBackupDirWithMetadata(String basePath, String packageName) {
        if (basePath == null || packageName == null || packageName.isEmpty()) {
            return null;
        }
        File appsDir = resolveAppsDir(basePath);
        if (appsDir == null) {
            return null;
        }
        File direct = new File(appsDir, packageName);
        if (new File(direct, FILE_CONFIG).isFile()) {
            return direct;
        }
        File[] pkgDirs = appsDir.listFiles();
        if (pkgDirs == null) {
            return null;
        }
        for (File pkgDir : pkgDirs) {
            if (pkgDir == null || !pkgDir.isDirectory()) {
                continue;
            }
            File config = new File(pkgDir, FILE_CONFIG);
            if (!config.isFile()) {
                continue;
            }
            String pkg = pkgDir.getName();
            try {
                String json = new String(readFully(config), StandardCharsets.UTF_8);
                JSONObject root = new JSONObject(json);
                JSONObject pkgInfo = root.optJSONObject("packageInfo");
                if (pkgInfo != null) {
                    String pkgFromJson = pkgInfo.optString("packageName", null);
                    if (pkgFromJson != null && !pkgFromJson.isEmpty()) {
                        pkg = pkgFromJson;
                    }
                }
            } catch (Exception ignored) {
            }
            if (packageName.equals(pkg)) {
                return pkgDir;
            }
        }
        return null;
    }

    @Override
    public String resolveBackupPackageDir(String basePath, String packageName) throws RemoteException {
        checkPermission();
        File d = findBackupDirWithMetadata(basePath, packageName);
        return d != null ? d.getAbsolutePath() : null;
    }

    @Override
    public String readBackupMetadataJson(String basePath, String packageName) throws RemoteException {
        checkPermission();
        return readBackupMetadataJsonInternal(basePath, packageName);
    }

    @Override
    public boolean deleteBackupPackage(String basePath, String packageName) throws RemoteException {
        checkPermission();
        if (basePath == null || packageName == null || packageName.isEmpty()) {
            return false;
        }
        File dir = findBackupDirWithMetadata(basePath, packageName);
        if (dir == null || !dir.isDirectory()) {
            Slog.w(TAG, "deleteBackupPackage: no directory for " + packageName);
            return false;
        }
        return deleteBackupPackageInternal(basePath, packageName);
    }

    @Override
    public boolean deleteBackupPackageAtPath(String basePath, String absolutePackageDir)
            throws RemoteException {
        checkPermission();
        return deleteBackupPackageAtPathInternal(basePath, absolutePackageDir);
    }

    private boolean deletePackageDirInternal(File dir) {
        if (dir == null) {
            return false;
        }
        String abs = dir.getAbsolutePath();
        return deleteTreeWithDaemon(abs);
    }

    private boolean deleteTreeWithDaemon(String absPath) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(absPath);
            boolean ok = daemon.transact(TRUEBACKUPD_DELETE_TREE, data, reply, 0);
            if (!ok) {
                return false;
            }
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "deleteTreeWithDaemon", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void checkPermission() {
        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.BACKUP, "TrueBackup");
    }

    private static boolean isPrivilegedCallingUid() {
        final int appId = UserHandle.getAppId(Binder.getCallingUid());
        return appId == Process.SYSTEM_UID || appId == Process.ROOT_UID;
    }

    /**
     * Resolves backup profile: {@code userId >= 0} uses that id when allowed; {@code userId < 0}
     * uses the calling user's profile (clone/work profile).
     */
    private int resolveBackupUserId(int userId) {
        final int callingUser = UserHandle.getUserId(Binder.getCallingUid());
        if (userId < 0) {
            return callingUser;
        }
        if (userId != callingUser && !isPrivilegedCallingUid()) {
            return callingUser;
        }
        return userId;
    }

    /**
     * Restore target profile: explicit {@code userId >= 0} when allowed; {@code userId < 0} uses
     * {@code backupConfig.userId} from metadata (Android-DataBackup style), else calling user.
     */
    private int resolveRestoreUserId(int userId, String packageName, String sourcePath) {
        if (userId >= 0) {
            return resolveBackupUserId(userId);
        }
        String json = readBackupMetadataJsonInternal(sourcePath, packageName);
        if (json != null && !json.isEmpty()) {
            try {
                JSONObject root = new JSONObject(json);
                JSONObject bc = root.optJSONObject("backupConfig");
                if (bc != null && !bc.isNull("userId")) {
                    int fromMeta = bc.optInt("userId", -1);
                    if (fromMeta >= 0) {
                        return fromMeta;
                    }
                }
            } catch (Exception e) {
                Slog.w(TAG, "resolveRestoreUserId: metadata", e);
            }
        }
        return UserHandle.getUserId(Binder.getCallingUid());
    }

    private boolean isUserAlive(int userId) {
        UserManager um = mContext.getSystemService(UserManager.class);
        if (um == null) {
            return userId == UserHandle.USER_SYSTEM;
        }
        return um.isUserRunning(userId);
    }

    private Context getContextForUser(int userId) {
        if (userId == UserHandle.getUserId(Process.myUid())) {
            return mContext;
        }
        try {
            return mContext.createContextAsUser(UserHandle.of(userId), 0);
        } catch (Exception e) {
            Slog.w(TAG, "createContextAsUser failed for " + userId, e);
            return mContext;
        }
    }

    private File getTrueBackupSystemDir() {
        File base = Environment.getDataSystemDirectory();
        return new File(base, "truebackup");
    }

    /**
     * Scratch space under {@code /data/system/truebackup/tmp} (not next to backup archives on removable
     * storage). Created by truebackupd with DAC that allows system_server to use it.
     */
    private File getTrueBackupTempDir() throws IOException {
        File dir = new File(getTrueBackupSystemDir(), "tmp");
        if (dir.isDirectory()) {
            return dir;
        }
        if (!mkdirsMaybeDaemon(dir)) {
            throw new IOException("Could not create TrueBackup temp dir: " + dir);
        }
        if (!dir.isDirectory()) {
            throw new IOException("TrueBackup temp dir missing after mkdir: " + dir);
        }
        return dir;
    }

    private File createTrueBackupWorkFile(String prefix, String suffix) throws IOException {
        return File.createTempFile(prefix, suffix, getTrueBackupTempDir());
    }

    private File createTrueBackupWorkDir(String prefix) throws IOException {
        File dir = File.createTempFile(prefix, "", getTrueBackupTempDir());
        //noinspection ResultOfMethodCallIgnored
        dir.delete();
        if (!dir.mkdir() && !dir.isDirectory()) {
            throw new IOException("Could not create work dir: " + dir);
        }
        // Allow truebackupd (root) to write extracted tar entries; fixupRestoredTree reassigns to system.
        if (!dir.setReadable(true, false) || !dir.setWritable(true, false) || !dir.setExecutable(true, false)) {
            Slog.w(TAG, "Could not chmod work dir for daemon extract: " + dir);
        }
        return dir;
    }

    private static List<File> collectApkFiles(File root) {
        List<File> out = new ArrayList<>();
        collectApkFilesRecursive(root, out);
        return out;
    }

    private static void collectApkFilesRecursive(File dir, List<File> out) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File f : children) {
            if (f.isDirectory()) {
                collectApkFilesRecursive(f, out);
            } else if (f.isFile() && f.getName().endsWith(".apk")) {
                out.add(f);
            }
        }
    }

    private synchronized String readRegistrationPasswordStored() {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return null;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            boolean ok = daemon.transact(TRUEBACKUPD_GET_PASSWORD, data, reply, 0);
            if (!ok) return null;
            if (reply.readInt() != 0) return null;
            String stored = reply.readString16();
            if (stored == null) return null;
            stored = stored.trim();
            return stored.isEmpty() ? null : stored;
        } catch (RemoteException e) {
            Slog.w(TAG, "readRegistrationPasswordStored", e);
            return null;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private synchronized String readRegistrationPassword() {
        String stored = readRegistrationPasswordStored();
        if (stored == null) return null;
        String plain = decryptRegisteredPassword(stored);
        return plain != null ? plain : stored;
    }

    private synchronized boolean writeRegistrationPassword(String pw) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;
        String stored = encryptRegisteredPassword(pw);
        if (stored == null) {
            Slog.w(TAG, "writeRegistrationPassword: encrypt failed");
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(stored);
            data.writeString16(pw);
            boolean ok = daemon.transact(TRUEBACKUPD_SET_PASSWORD, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "writeRegistrationPassword", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean daemonChangeRegistrationPassword(String oldPassword, String newPassword) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(oldPassword);
            data.writeString16(newPassword);
            boolean ok = daemon.transact(TRUEBACKUPD_CHANGE_PASSWORD, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonChangeRegistrationPassword", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean daemonClearRegistrationPassword() {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            boolean ok = daemon.transact(TRUEBACKUPD_CLEAR_PASSWORD, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonClearRegistrationPassword", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private SecretKey getOrCreateRegPasswordKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(REG_PW_KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(REG_PW_KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, REG_PW_KEYSTORE);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                REG_PW_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build();
        kg.init(spec);
        return kg.generateKey();
    }

    private String encryptRegisteredPassword(String plain) {
        try {
            SecretKey key = getOrCreateRegPasswordKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV();
            byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] blob = new byte[1 + iv.length + ct.length];
            blob[0] = (byte) iv.length;
            System.arraycopy(iv, 0, blob, 1, iv.length);
            System.arraycopy(ct, 0, blob, 1 + iv.length, ct.length);
            return REG_PW_BLOB_PREFIX + Base64.getEncoder().encodeToString(blob);
        } catch (Exception e) {
            Slog.w(TAG, "encryptRegisteredPassword", e);
            return null;
        }
    }

    private String decryptRegisteredPassword(String stored) {
        if (!stored.startsWith(REG_PW_BLOB_PREFIX)) {
            return null;
        }
        try {
            String b64 = stored.substring(REG_PW_BLOB_PREFIX.length());
            byte[] blob = Base64.getDecoder().decode(b64);
            if (blob.length < 2) return null;
            int ivLen = blob[0] & 0xFF;
            if (ivLen <= 0 || 1 + ivLen >= blob.length) return null;
            byte[] iv = new byte[ivLen];
            System.arraycopy(blob, 1, iv, 0, ivLen);
            int ctLen = blob.length - 1 - ivLen;
            byte[] ct = new byte[ctLen];
            System.arraycopy(blob, 1 + ivLen, ct, 0, ctLen);
            SecretKey key = getOrCreateRegPasswordKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] plain = cipher.doFinal(ct);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Slog.w(TAG, "decryptRegisteredPassword", e);
            return null;
        }
    }

    private synchronized void recordKnownBackupPath(String basePath) {
        if (basePath == null || basePath.isEmpty()) return;
        final String p = normalizeBasePath(basePath);
        if (p.isEmpty()) return;
        if (!daemonAppendKnownBackupPath(p)) {
            Slog.w(TAG, "recordKnownBackupPath: daemon append failed for " + p);
        }
    }

    private synchronized HashSet<String> readKnownBackupPaths() {
        HashSet<String> out = new HashSet<>();
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return out;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            boolean ok = daemon.transact(TRUEBACKUPD_LIST_KNOWN_BACKUP_PATHS, data, reply, 0);
            if (!ok) return out;
            if (reply.readInt() != 0) return out;
            String s = reply.readString16();
            if (s == null || s.isEmpty()) return out;
            for (String line : s.split("\n")) {
                String tp = line.trim();
                if (!tp.isEmpty()) out.add(tp);
            }
        } catch (RemoteException e) {
            Slog.w(TAG, "readKnownBackupPaths", e);
        } finally {
            reply.recycle();
            data.recycle();
        }
        return out;
    }

    private boolean daemonAppendKnownBackupPath(String basePath) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || basePath == null || basePath.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(basePath);
            boolean ok = daemon.transact(TRUEBACKUPD_APPEND_KNOWN_BACKUP_PATH, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonAppendKnownBackupPath", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static byte[] readFully(FileInputStream in) throws IOException {
        byte[] buf = new byte[16 * 1024];
        int n;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private void maybeEncryptInPlace(File archiveFile) {
        if (archiveFile == null || !archiveFile.exists() || !archiveFile.isFile()) return;
        if (isEncryptedFile(archiveFile)) return;
        String pw = readRegistrationPassword();
        if (pw == null) return;
        if (!daemonEncryptArchiveInPlace(archiveFile, pw)) {
            Slog.w(TAG, "daemonEncryptArchiveInPlace failed for " + archiveFile);
        }
    }

    private boolean isEncryptedFile(File f) {
        if (f == null || !f.isFile()) return false;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(f)))) {
            byte[] m = new byte[4];
            if (in.read(m) != 4) return false;
            return m[0] == ENC_MAGIC[0] && m[1] == ENC_MAGIC[1] && m[2] == ENC_MAGIC[2] && m[3] == ENC_MAGIC[3];
        } catch (IOException e) {
            return false;
        }
    }

    private void executeRekeyAllKnownBackups(String oldPassword, String newPassword) {
        if (newPassword == null || newPassword.isEmpty()) return;
        HashSet<String> paths = readKnownBackupPaths();
        if (paths.isEmpty()) {
            Slog.w(TAG, "rekey skipped: no known backup paths");
            return;
        }
        int total = 0;
        for (String basePath : paths) {
            if (basePath == null || basePath.isEmpty()) continue;
            File appsDir = resolveAppsDir(basePath);
            if (appsDir == null || !appsDir.isDirectory()) continue;
            total++;
        }
        if (total <= 0) return;
        int done = 0;
        for (String basePath : paths) {
            if (basePath == null || basePath.isEmpty()) continue;
            File appsDir = resolveAppsDir(basePath);
            if (appsDir == null || !appsDir.isDirectory()) continue;
            if (!daemonRekeyBackupTree(appsDir, oldPassword, newPassword)) {
                Slog.w(TAG, "daemonRekeyBackupTree failed for " + appsDir);
            }
            done++;
            setActiveProgressStep(done, total);
        }
    }

    private boolean daemonRekeyBackupTree(File dir, String oldPassword, String newPassword) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || dir == null || !dir.isDirectory() || newPassword == null || newPassword.isEmpty()) {
            return false;
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(dir.getAbsolutePath());
            data.writeString16(oldPassword != null ? oldPassword : "");
            data.writeString16(newPassword);
            boolean ok = daemon.transact(TRUEBACKUPD_REKEY_BACKUP_TREE, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonRekeyBackupTree", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static File resolveAppsDir(String basePath) {
        final String normalized = normalizeBasePath(basePath);
        if (normalized == null || normalized.isEmpty()) return null;
        File base = new File(normalized);

        if (base.isDirectory() && "apps".equals(base.getName())) {
            return base;
        }

        if (base.isDirectory() && "backup".equals(base.getName())) {
            File candidate = new File(base, "apps");
            if (candidate.isDirectory()) return candidate;
        }

        File candidate1 = new File(new File(base, "backup"), "apps");
        if (candidate1.isDirectory()) return candidate1;

        File candidate2 = new File(base, "apps");
        if (candidate2.isDirectory()) return candidate2;

        return null;
    }

    private static byte[] readFully(File f) throws IOException {
        try (FileInputStream in = new FileInputStream(f)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[16 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private boolean isPackageInstalledAsUser(String packageName, int userId) {
        try {
            mContext.getPackageManager().getPackageInfoAsUser(packageName, 0, userId);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static final class LocalIntentReceiver {
        private final LinkedBlockingQueue<Intent> mResult = new LinkedBlockingQueue<>();

        private final android.content.IIntentSender.Stub mLocalSender = new android.content.IIntentSender.Stub() {
            @Override
            public void send(int code, Intent intent, String resolvedType,
                    android.os.IBinder whitelistToken,
                    android.content.IIntentReceiver finishedReceiver,
                    String requiredPermission, android.os.Bundle options) {
                mResult.offer(intent);
            }
        };

        android.content.IntentSender getIntentSender() {
            return new android.content.IntentSender((android.content.IIntentSender) mLocalSender);
        }

        Intent getResult(long timeoutMs) throws InterruptedException {
            return mResult.poll(timeoutMs, TimeUnit.MILLISECONDS);
        }
    }

    private void installApksFromBackupIfNeeded(String packageName, File pkgDir, int userId)
            throws IOException {
        if (isPackageInstalledAsUser(packageName, userId)) {
            return;
        }

        File apkArch = new File(new File(pkgDir, DIR_APK), ARCH_APK);
        if (!apkArch.exists()) {
            throw new IOException("App not installed and apk.tbak missing: " + apkArch);
        }

        File apkExtractDir = createTrueBackupWorkDir("truebackup_apk_");
        try {
            untarToDirMaybeDaemon(apkArch, apkExtractDir);
            // Extracted entries are owned by truebackupd (root); hand off to system_server for install.
            fixupRestoredTree(apkExtractDir, Process.SYSTEM_UID, Process.SYSTEM_UID);
            List<File> apkFiles = collectApkFiles(apkExtractDir);
            if (apkFiles.isEmpty()) {
                throw new IOException("No APK entries found inside: " + apkArch);
            }

            // Install via PackageInstaller session for the target profile (clone / work user).
            Context userCtx = getContextForUser(userId);
            PackageManager pm = userCtx.getPackageManager();
            PackageInstaller installer = pm.getPackageInstaller();
            PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                    PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            params.setAppPackageName(packageName);

            int sessionId = installer.createSession(params);
            PackageInstaller.Session session = installer.openSession(sessionId);
            try {
                byte[] buffer = new byte[128 * 1024];
                for (File apkFile : apkFiles) {
                    String apkName = apkFile.getName();
                    if (apkName.isEmpty()) continue;
                    try (java.io.FileInputStream in = new java.io.FileInputStream(apkFile);
                            java.io.OutputStream out = session.openWrite(apkName, 0, apkFile.length())) {
                        int n;
                        while ((n = in.read(buffer)) > 0) {
                            out.write(buffer, 0, n);
                        }
                        session.fsync(out);
                    }
                }

                LocalIntentReceiver receiver = new LocalIntentReceiver();
                session.commit(receiver.getIntentSender());
                Intent result = receiver.getResult(120_000);
                if (result == null) {
                    throw new IOException("Timed out waiting for install result for: " + packageName);
                }
                int status = result.getIntExtra(PackageInstaller.EXTRA_STATUS,
                        PackageInstaller.STATUS_FAILURE);
                if (status != PackageInstaller.STATUS_SUCCESS) {
                    String msg = result.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
                    throw new IOException("Install failed for " + packageName + ": status=" + status
                            + " msg=" + msg);
                }
            } finally {
                session.close();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted waiting for install result for: " + packageName, e);
        } finally {
            if (!FileUtils.deleteContentsAndDir(apkExtractDir)) {
                Slog.w(TAG, "cleanup apk extract dir failed: " + apkExtractDir);
            }
        }

        if (!isPackageInstalledAsUser(packageName, userId)) {
            throw new IOException("Install reported success but package not installed for user "
                    + userId + ": " + packageName);
        }
    }


    private static final class BackupParts {
        boolean apk;
        boolean userCe;
        boolean userDe;
        boolean extData;
        boolean obb;
        boolean media;
    }

    /**
     * Only runtime (dangerous) permissions — the ones {@link PackageManager#grantRuntimePermission}
     * can change. Omitting install-time / signature permissions keeps the config small and avoids
     * restore-time noise for permissions that cannot be toggled.
     */
    private static JSONArray buildPermissionsJson(PackageManager pm, PackageInfo pi)
            throws JSONException {
        JSONArray perms = new JSONArray();
        if (pi == null || pi.requestedPermissions == null) return perms;

        for (int i = 0; i < pi.requestedPermissions.length; i++) {
            String name = pi.requestedPermissions[i];
            if (name == null || name.isEmpty()) continue;
            try {
                PermissionInfo permInfo = pm.getPermissionInfo(name, 0);
                if (!permInfo.isRuntime()) {
                    continue;
                }
            } catch (PackageManager.NameNotFoundException e) {
                continue;
            }
            boolean granted = false;
            if (pi.requestedPermissionsFlags != null && i < pi.requestedPermissionsFlags.length) {
                granted = (pi.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED)
                        != 0;
            }
            JSONObject p = new JSONObject();
            p.put("name", name);
            p.put("granted", granted);
            perms.put(p);
        }
        return perms;
    }

    private static boolean isRuntimePermission(PackageManager pm, String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        try {
            return pm.getPermissionInfo(name, 0).isRuntime();
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static long fileBytesIfExists(File f) {
        if (f == null || !f.exists() || !f.isFile()) return 0;
        return f.length();
    }

    private File resolvePackageBackupDir(String basePath, String packageName) {
        final String normalized = normalizeBasePath(basePath);
        File base = new File(normalized != null ? normalized : basePath);

        // If caller already passed the per-package directory.
        if (base.isDirectory() && packageName.equals(base.getName()) && looksLikePackageDir(base)) {
            return base;
        }

        // If caller passed .../apps or .../backup.
        if (base.isDirectory() && "apps".equals(base.getName())) {
            File candidate = new File(base, packageName);
            if (looksLikePackageDir(candidate)) return candidate;
        }

        if (base.isDirectory() && "backup".equals(base.getName())) {
            File candidate = new File(new File(base, "apps"), packageName);
            if (looksLikePackageDir(candidate)) return candidate;
        }

        // If caller passed the backup root.
        File candidate1 = new File(base, packageName);
        if (looksLikePackageDir(candidate1)) return candidate1;

        File candidate2 = new File(new File(base, "apps"), packageName);
        if (looksLikePackageDir(candidate2)) return candidate2;

        File candidate3 = new File(new File(new File(base, "backup"), "apps"), packageName);
        if (looksLikePackageDir(candidate3)) return candidate3;

        // Default: create/use <base>/backup/apps/<pkg>
        return candidate3;
    }

    /**
     * Normalizes user-selected backup roots to filesystem paths expected by truebackupd.
     *
     * Accepts plain paths and common SAF tree formats:
     * - content://.../tree/primary:Download
     * - /tree/primary:Download
     * - primary:Download
     */
    private static String normalizeBasePath(String basePath) {
        if (basePath == null) return null;
        String in = basePath.trim();
        if (in.isEmpty()) return null;
        if (in.startsWith("/")) {
            return in;
        }

        String docId = null;
        try {
            if (in.startsWith("content://")) {
                Uri uri = Uri.parse(in);
                if (DocumentsContract.isTreeUri(uri)) {
                    docId = DocumentsContract.getTreeDocumentId(uri);
                }
            } else if (in.startsWith("/tree/")) {
                String tail = in.substring("/tree/".length());
                int slash = tail.indexOf('/');
                docId = slash >= 0 ? tail.substring(0, slash) : tail;
            } else if (in.contains(":")) {
                docId = in;
            }
        } catch (Exception e) {
            Slog.w(TAG, "normalizeBasePath: failed to parse " + in, e);
        }

        if (docId == null || docId.isEmpty()) {
            return in;
        }

        docId = Uri.decode(docId);
        int sep = docId.indexOf(':');
        if (sep < 0) {
            if ("primary".equals(docId)) {
                return "/data/media/0";
            }
            return in;
        }

        String volume = docId.substring(0, sep);
        String relative = docId.substring(sep + 1);
        if (relative.startsWith("/")) {
            relative = relative.substring(1);
        }

        if ("primary".equals(volume)) {
            if (relative.isEmpty()) return "/data/media/0";
            return "/data/media/0/" + relative;
        }

        // Non-primary removable/adopted storage volume IDs.
        if (relative.isEmpty()) return "/storage/" + volume;
        return "/storage/" + volume + "/" + relative;
    }

    private boolean looksLikePackageDir(File pkgDir) {
        if (pkgDir == null || !pkgDir.isDirectory()) return false;
        if (new File(pkgDir, FILE_CONFIG).exists()) return true;
        return new File(pkgDir, DIR_APK).isDirectory()
                || new File(pkgDir, DIR_INT_DATA).isDirectory()
                || new File(pkgDir, DIR_EXT_DATA).isDirectory()
                || new File(pkgDir, DIR_ADDL_DATA).isDirectory();
    }

    private boolean ensureDirs(File pkgDir) {
        File apkDir = new File(pkgDir, DIR_APK);
        File intDir = new File(pkgDir, DIR_INT_DATA);
        File extDir = new File(pkgDir, DIR_EXT_DATA);
        File addlDir = new File(pkgDir, DIR_ADDL_DATA);
        return (apkDir.exists() || mkdirsMaybeDaemon(apkDir))
                && (intDir.exists() || mkdirsMaybeDaemon(intDir))
                && (extDir.exists() || mkdirsMaybeDaemon(extDir))
                && (addlDir.exists() || mkdirsMaybeDaemon(addlDir));
    }

    private boolean mkdirsMaybeDaemon(File dir) {
        return mkdirsWithDaemon(dir);
    }

    private boolean mkdirsWithDaemon(File dir) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(dir.getAbsolutePath());
            boolean ok = daemon.transact(TRUEBACKUPD_MKDIRS, data, reply, 0);
            if (!ok) return false;
            int rc = reply.readInt();
            return rc == 0;
        } catch (RemoteException e) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean tarMultiFileWithDaemon(File[] sourceFiles, String[] entryNames, File outArchive) {
        if (sourceFiles == null || entryNames == null) return false;
        if (sourceFiles.length != entryNames.length) return false;

        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(outArchive.getAbsolutePath());
            data.writeInt(sourceFiles.length);
            for (int i = 0; i < sourceFiles.length; i++) {
                data.writeString16(sourceFiles[i].getAbsolutePath());
                data.writeString16(entryNames[i]);
            }

            boolean ok = daemon.transact(TRUEBACKUPD_TAR_MULTI_FILE, data, reply, 0);
            if (!ok) return false;
            int rc = reply.readInt();
            return rc == 0;
        } catch (RemoteException e) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean tarApk(String packageName, int userId, File outArchive) throws IOException {
        PackageManager pm = mContext.getPackageManager();
        ApplicationInfo ai;
        try {
            ai = pm.getApplicationInfoAsUser(packageName, 0, UserHandle.of(userId));
        } catch (PackageManager.NameNotFoundException e) {
            Slog.e(TAG, "Package not found: " + packageName + " user " + userId);
            return false;
        }

        if (ai.sourceDir == null) {
            Slog.e(TAG, "No sourceDir for: " + packageName);
            return false;
        }

        File baseApk = new File(ai.sourceDir);
        if (!baseApk.exists()) {
            Slog.e(TAG, "APK not found at: " + ai.sourceDir);
            return false;
        }

        String[] splitPaths = ai.splitSourceDirs;
        int splitCount = (splitPaths == null) ? 0 : splitPaths.length;

        File[] files = new File[1 + splitCount];
        String[] entries = new String[1 + splitCount];
        files[0] = baseApk;
        entries[0] = "base.apk";
        for (int i = 0; i < splitCount; i++) {
            File f = new File(splitPaths[i]);
            files[1 + i] = f;
            entries[1 + i] = f.getName();
        }

        return tarMultiFileWithDaemon(files, entries, outArchive);
    }

    private boolean tarDirIfExists(File sourceDir, File outArchive) throws IOException {
        if (!sourceDir.exists()) {
            return false;
        }

        return tarDirectoryWithDaemon(sourceDir, outArchive);
    }

    private void restoreFromPackageDir(String packageName, File pkgDir, int userId) throws IOException {
        final int totalSteps = 7;
        int done = 0;
        // If the app is not installed, install it first from apk.tbak so /data_mirror targets exist.
        installApksFromBackupIfNeeded(packageName, pkgDir, userId);
        setActiveProgressStep(++done, totalSteps);

        final int appUid = getApplicationUidOrThrow(packageName, userId);

        File ceArch = new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER);
        if (ceArch.exists()) {
            File target = new File(ceBase(userId), packageName);
            untarToDirMaybeDaemon(ceArch, target);
            fixupRestoredTree(target, appUid, appUid, -1);
        }
        setActiveProgressStep(++done, totalSteps);

        File deArch = new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER_DE);
        if (deArch.exists()) {
            File target = new File(deBase(userId), packageName);
            untarToDirMaybeDaemon(deArch, target);
            fixupRestoredTree(target, appUid, appUid, -1);
        }
        setActiveProgressStep(++done, totalSteps);

        File extArch = new File(new File(pkgDir, DIR_EXT_DATA), ARCH_DATA);
        if (extArch.exists()) {
            File target = new File(extDataBase(userId), packageName);
            untarToDirMaybeDaemon(extArch, target);
            int extGid = statDirGidOrUid(extDataGidRef(userId), appUid);
            fixupRestoredTree(target, appUid, extGid, MODE_ANDROID_DATA_DIR);
        }
        setActiveProgressStep(++done, totalSteps);

        File obbArch = new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_OBB);
        if (obbArch.exists()) {
            File target = new File(obbBase(userId), packageName);
            untarToDirMaybeDaemon(obbArch, target);
            int obbGid = statDirGidOrUid(obbGidRef(userId), appUid);
            fixupRestoredTree(target, appUid, obbGid, MODE_ANDROID_SHARED_PKG_DIR);
        }
        setActiveProgressStep(++done, totalSteps);

        File mediaArch = new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_MEDIA);
        if (mediaArch.exists()) {
            File target = new File(mediaBase(userId), packageName);
            untarToDirMaybeDaemon(mediaArch, target);
            int mediaGid = statDirGidOrUid(mediaGidRef(userId), appUid);
            fixupRestoredTree(target, appUid, mediaGid, MODE_ANDROID_SHARED_PKG_DIR);
        }
        setActiveProgressStep(++done, totalSteps);

        applySecurityRestoreFromConfig(packageName, pkgDir, userId);
        setActiveProgressStep(++done, totalSteps);
    }

    private int getApplicationUidOrThrow(String packageName, int userId) throws IOException {
        try {
            ApplicationInfo ai = mContext.getPackageManager().getApplicationInfoAsUser(
                    packageName, 0, UserHandle.of(userId));
            return ai.uid;
        } catch (PackageManager.NameNotFoundException e) {
            throw new IOException("Package not installed: " + packageName + " user " + userId, e);
        }
    }

    private static int statDirGidOrUid(String dirPath, int uidFallback) {
        try {
            return (int) Os.stat(dirPath).st_gid;
        } catch (ErrnoException e) {
            Slog.w(TAG, "stat failed for " + dirPath + "; using app uid as gid", e);
            return uidFallback;
        }
    }

    /**
     * Extracted files are owned by root; relabel and chown so the app can run (same idea as
     * {@code PackagesRestoreUtil.restoreData} in Android-DataBackup).
     *
     * @param mode octal perms to apply under {@code truebackupd} (e.g. 0760 for
     *             {@code Android/data} package dirs, 0770 for media/obb), or {@code -1} to skip {@code chmod}.
     */
    private void fixupRestoredTree(File path, int uid, int gid, int mode) {
        if (path == null || !path.exists()) {
            return;
        }
        String abs;
        try {
            abs = path.getCanonicalPath();
        } catch (IOException e) {
            Slog.e(TAG, "fixup: bad path " + path, e);
            return;
        }
        String ctx = SELinux.getFileContext(abs);
        if (ctx != null && !ctx.isEmpty() && chownAndChconWithDaemon(abs, uid, gid, ctx, mode)) {
            return;
        }
        Slog.e(TAG, "truebackupd chown/chcon failed for " + abs);
    }

    private void fixupRestoredTree(File path, int uid, int gid) {
        fixupRestoredTree(path, uid, gid, -1);
    }

    private boolean chownAndChconWithDaemon(String absolutePath, int uid, int gid, String context,
            int mode) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || context == null || context.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(absolutePath);
            data.writeInt(uid);
            data.writeInt(gid);
            data.writeString16(context);
            data.writeInt(mode);
            boolean ok = daemon.transact(TRUEBACKUPD_CHOWN_AND_CHCON, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "chown/chcon transact failed", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean tarDirectoryWithDaemon(File sourceDir, File outArchive) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(sourceDir.getAbsolutePath());
            data.writeString16(outArchive.getAbsolutePath());
            boolean ok = daemon.transact(TRUEBACKUPD_TAR_DIR, data, reply, 0);
            if (!ok) return false;
            int rc = reply.readInt();
            return rc == 0;
        } catch (RemoteException e) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean daemonEncryptArchiveInPlace(File archiveFile, String password) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || password == null || password.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(archiveFile.getAbsolutePath());
            data.writeString16(password);
            boolean ok = daemon.transact(TRUEBACKUPD_ENCRYPT_ARCHIVE_IN_PLACE, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonEncryptArchiveInPlace", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean daemonDecryptArchiveToFile(File encFile, File outPlainTar, String password) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || password == null || password.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(encFile.getAbsolutePath());
            data.writeString16(outPlainTar.getAbsolutePath());
            data.writeString16(password);
            boolean ok = daemon.transact(TRUEBACKUPD_DECRYPT_ARCHIVE_TO_FILE, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonDecryptArchiveToFile", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void untarToDirMaybeDaemon(File archiveFile, File targetDir) throws IOException {
        File toUntar = archiveFile;
        File tmp = null;
        try {
            if (isEncryptedFile(archiveFile)) {
                tmp = createTrueBackupWorkFile("tb_untar_", ".tar");
                String pw = readRegistrationPassword();
                if (pw == null) {
                    throw new IOException("No registration password for " + archiveFile);
                }
                if (!daemonDecryptArchiveToFile(archiveFile, tmp, pw)) {
                    throw new IOException("Could not decrypt backup archive: " + archiveFile);
                }
                toUntar = tmp;
            }
            if (!untarToDirWithDaemon(toUntar, targetDir)) {
                throw new IOException("Untar failed via daemon for " + toUntar);
            }
        } finally {
            if (tmp != null) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }
    }

    private boolean untarToDirWithDaemon(File archiveFile, File targetDir) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(archiveFile.getAbsolutePath());
            data.writeString16(targetDir.getAbsolutePath());
            boolean ok = daemon.transact(TRUEBACKUPD_UNTAR_TO_DIR, data, reply, 0);
            if (!ok) return false;
            int rc = reply.readInt();
            return rc == 0;
        } catch (RemoteException e) {
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void writeConfig(File outConfig, String packageName, int userId, BackupParts parts)
            throws IOException, JSONException {
        final long now = System.currentTimeMillis();
        final PackageManager pm = mContext.getPackageManager();

        PackageInfo pi = null;
        ApplicationInfo ai = null;
        try {
            pi = pm.getPackageInfoAsUser(packageName, PackageManager.GET_PERMISSIONS, userId);
            ai = pi.applicationInfo;
        } catch (PackageManager.NameNotFoundException e) {
            // Keep config generation best-effort.
        }

        String label = null;
        if (ai != null) {
            CharSequence cs = pm.getApplicationLabel(ai);
            if (cs != null) label = cs.toString();
        }

        JSONObject obj = new JSONObject();
        obj.put("version", 2);
        obj.put("package", packageName);
        obj.put("apk", parts.apk);
        obj.put("user_ce", parts.userCe);
        obj.put("user_de", parts.userDe);
        obj.put("ext_data", parts.extData);
        obj.put("obb", parts.obb);
        obj.put("media", parts.media);

        JSONObject pkgInfo = new JSONObject();
        pkgInfo.put("label", label);
        if (pi != null) {
            pkgInfo.put("versionName", pi.versionName);
            pkgInfo.put("versionCode", pi.getLongVersionCode());
            pkgInfo.put("firstInstallTime", pi.firstInstallTime);
            pkgInfo.put("lastUpdateTime", pi.lastUpdateTime);
        }
        if (ai != null) {
            pkgInfo.put("flags", ai.flags);
            pkgInfo.put("uid", ai.uid);
            pkgInfo.put("sourceDir", ai.sourceDir);
        }
        obj.put("packageInfo", pkgInfo);

        JSONObject backupConfig = new JSONObject();
        backupConfig.put("packageName", packageName);
        backupConfig.put("userId", userId);
        backupConfig.put("compression", "tar+aes");
        backupConfig.put("preserveId", now);
        File pkgDir = outConfig.getParentFile();
        backupConfig.put("storagePath", pkgDir != null ? pkgDir.getAbsolutePath() : null);
        backupConfig.put("createdAt", now);
        obj.put("backupConfig", backupConfig);

        JSONObject dataStates = new JSONObject();
        dataStates.put("apk", parts.apk);
        dataStates.put("userCe", parts.userCe);
        dataStates.put("userDe", parts.userDe);
        dataStates.put("externalData", parts.extData);
        dataStates.put("obb", parts.obb);
        dataStates.put("media", parts.media);
        obj.put("dataStates", dataStates);

        JSONObject dataStats = new JSONObject();
        if (pkgDir != null) {
            dataStats.put("apkBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_APK), ARCH_APK)));
            dataStats.put("userBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER)));
            dataStats.put("userDeBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_INT_DATA), ARCH_USER_DE)));
            dataStats.put("dataBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_EXT_DATA), ARCH_DATA)));
            dataStats.put("obbBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_OBB)));
            dataStats.put("mediaBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_ADDL_DATA), ARCH_MEDIA)));
        }
        obj.put("dataStats", dataStats);

        JSONObject security = new JSONObject();
        if (ai != null) security.put("uid", ai.uid);
        String ssaidHex = (ai != null) ? readSsaidHexFromDisk(userId, ai.uid) : null;
        if (ssaidHex != null && !ssaidHex.isEmpty()) {
            security.put("ssaid", ssaidHex);
        } else {
        security.put("ssaid", JSONObject.NULL);
        }
        security.put("keystore", "unknown");
        security.put("appops", buildAppOpsJson(packageName, ai != null ? ai.uid : -1));
        security.put("permissions", buildPermissionsJson(pm, pi));
        obj.put("security", security);

        byte[] data = obj.toString(2).getBytes(StandardCharsets.UTF_8);

        if (!writeFileWithDaemon(outConfig, data)) {
            throw new IOException("Daemon write failed for " + outConfig);
        }
    }

    private boolean writeFileWithDaemon(File outFile, byte[] data) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel parcel = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            parcel.writeInt(TRUEBACKUPD_TOKEN);
            parcel.writeString16(outFile.getAbsolutePath());
            parcel.writeByteArray(data);
            boolean ok = daemon.transact(TRUEBACKUPD_WRITE_FILE, parcel, reply, 0);
            if (!ok) return false;
            int rc = reply.readInt();
            return rc == 0;
        } catch (RemoteException e) {
            return false;
        } finally {
            reply.recycle();
            parcel.recycle();
        }
    }

    /**
     * Reads per-app SSAID from {@code settings_ssaid.xml} (same backing store as
     * {@link android.provider.Settings.Secure#ANDROID_ID} for apps). Keys are app UIDs as strings.
     */
    private static String readSsaidHexFromDisk(int userId, int appUid) {
        File base = Environment.getUserSystemDirectory(userId);
        File f = new File(base, SETTINGS_FILE_SSAID);
        if (!f.isFile() || !f.canRead()) {
            return null;
        }
        final String uidKey = Integer.toString(appUid);
        try (FileInputStream in = new FileInputStream(f)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(in, StandardCharsets.UTF_8.name());
            int event;
            while ((event = parser.next()) != XmlPullParser.END_DOCUMENT) {
                if (event != XmlPullParser.START_TAG) continue;
                if (!"setting".equals(parser.getName())) continue;
                String name = parser.getAttributeValue(null, "name");
                if (!uidKey.equals(name)) continue;
                return parser.getAttributeValue(null, "value");
            }
        } catch (Exception e) {
            Slog.w(TAG, "readSsaidHexFromDisk: failed for uid " + appUid, e);
        }
        return null;
    }

    private JSONArray buildAppOpsJson(String packageName, int uid) {
        JSONArray arr = new JSONArray();
        if (uid < 0 || packageName == null) {
            return arr;
        }
        AppOpsManager aom = mContext.getSystemService(AppOpsManager.class);
        if (aom == null) {
            return arr;
        }
        try {
            List<AppOpsManager.PackageOps> pkgOps =
                    aom.getOpsForPackage(uid, packageName, (String[]) null);
            if (pkgOps == null) {
                return arr;
            }
            for (AppOpsManager.PackageOps po : pkgOps) {
                List<AppOpsManager.OpEntry> entries = po.getOps();
                if (entries == null) continue;
                for (AppOpsManager.OpEntry oe : entries) {
                    JSONObject o = new JSONObject();
                    o.put("op", oe.getOp());
                    o.put("mode", oe.getMode());
                    arr.put(o);
                }
            }
        } catch (Exception e) {
            Slog.w(TAG, "buildAppOpsJson failed for " + packageName, e);
        }
        return arr;
    }

    private void applySecurityRestoreFromConfig(String packageName, File pkgDir, int userId) {
        File cfg = new File(pkgDir, FILE_CONFIG);
        if (!cfg.isFile()) {
            return;
        }
        try {
            String json = new String(readFully(cfg), StandardCharsets.UTF_8);
            JSONObject root = new JSONObject(json);
            applySecurityFromJson(packageName, root.optJSONObject("security"), userId);
        } catch (Exception e) {
            Slog.w(TAG, "Security restore skipped for " + packageName, e);
        }
    }

    /**
     * Re-apply runtime permissions and AppOp modes from backup metadata (DataBackup-style).
     * SSAID is stored in backups when readable from disk but cannot be written back safely from
     * system_server without a dedicated Settings API.
     */
    private void applySecurityFromJson(String packageName, JSONObject security, int userId) {
        if (security == null) {
            return;
        }
        if (security.has("ssaid") && !security.isNull("ssaid")) {
            String ssaid = security.optString("ssaid", "");
            if (!ssaid.isEmpty()) {
                Slog.i(TAG, "Backup contains SSAID for " + packageName
                        + "; restore not implemented (requires SettingsProvider support).");
            }
        }

        int uid;
        try {
            uid = getApplicationUidOrThrow(packageName, userId);
        } catch (IOException e) {
            Slog.w(TAG, "Security restore: package not installed " + packageName);
            return;
        }

        try {
            resetAppOpsForPackage(userId, packageName);
        } catch (RemoteException e) {
            Slog.w(TAG, "reset app ops failed for " + packageName, e);
        }

        PackageManager pm = mContext.getPackageManager();
        UserHandle user = UserHandle.of(userId);
        JSONArray perms = security.optJSONArray("permissions");
        if (perms != null) {
            for (int i = 0; i < perms.length(); i++) {
                JSONObject p = perms.optJSONObject(i);
                if (p == null) continue;
                String perm = p.optString("name", null);
                if (perm == null || perm.isEmpty()) continue;
                if (!isRuntimePermission(pm, perm)) {
                    continue;
                }
                boolean wantGrant = p.optBoolean("granted", false);
                try {
                    if (wantGrant) {
                        pm.grantRuntimePermission(packageName, perm, user);
                    } else {
                        pm.revokeRuntimePermission(packageName, perm, user);
                    }
                } catch (Exception e) {
                    Slog.w(TAG, "permission " + perm + " for " + packageName + ": " + e);
                }
            }
        }

        JSONArray ops = security.optJSONArray("appops");
        if (ops != null) {
            AppOpsManager aom = mContext.getSystemService(AppOpsManager.class);
            if (aom != null) {
                for (int i = 0; i < ops.length(); i++) {
                    JSONObject o = ops.optJSONObject(i);
                    if (o == null) continue;
                    int op = o.optInt("op", -1);
                    int mode = o.optInt("mode", AppOpsManager.MODE_DEFAULT);
                    if (op < 0) continue;
                    try {
                        aom.setMode(op, uid, packageName, mode);
                    } catch (Exception e) {
                        Slog.w(TAG, "appop op=" + op + " pkg=" + packageName + ": " + e);
                    }
                }
            }
        }
    }

    private static void resetAppOpsForPackage(int userId, String packageName)
            throws RemoteException {
        IBinder b = ServiceManager.getService(Context.APP_OPS_SERVICE);
        if (b == null) {
            return;
        }
        IAppOpsService svc = IAppOpsService.Stub.asInterface(b);
        svc.resetAllModes(userId, packageName);
    }
}
