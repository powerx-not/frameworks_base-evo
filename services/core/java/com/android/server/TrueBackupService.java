package com.android.server;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.os.Environment;
import android.os.IBinder;
import android.os.ITrueBackupService;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SELinux;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.system.ErrnoException;
import android.system.Os;
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
import java.io.FileOutputStream;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

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

        QueuedOperation(int type, String packageName, String path) {
            this.type = type;
            this.packageName = packageName;
            this.path = path;
            this.arg1 = null;
            this.arg2 = null;
        }

        QueuedOperation(int type, String packageName, String path, String arg1, String arg2) {
            this.type = type;
            this.packageName = packageName;
            this.path = path;
            this.arg1 = arg1;
            this.arg2 = arg2;
        }
    }

    private final LinkedBlockingQueue<QueuedOperation> mOperationQueue = new LinkedBlockingQueue<>();
    private final AtomicInteger mWorkInFlight = new AtomicInteger(0);
    private volatile boolean mWorkerRunning = false;
    private String mActiveOperationKind = null;
    private String mActiveOperationPackage = null;

    private static final String TRUEBACKUPD_SERVICE = "truebackupd";
    private static final int TRUEBACKUPD_TOKEN = 0x5452424b; // 'TRBK'
    private static final int TRUEBACKUPD_ZIP_DIR = IBinder.FIRST_CALL_TRANSACTION;
    private static final int TRUEBACKUPD_UNZIP_TO_DIR = IBinder.FIRST_CALL_TRANSACTION + 1;
    private static final int TRUEBACKUPD_MKDIRS = IBinder.FIRST_CALL_TRANSACTION + 2;
    private static final int TRUEBACKUPD_ZIP_SINGLE_FILE = IBinder.FIRST_CALL_TRANSACTION + 3;
    private static final int TRUEBACKUPD_ZIP_MULTI_FILE = IBinder.FIRST_CALL_TRANSACTION + 4;
    private static final int TRUEBACKUPD_WRITE_FILE = IBinder.FIRST_CALL_TRANSACTION + 5;
    private static final int TRUEBACKUPD_CHOWN_AND_RESTORECON = IBinder.FIRST_CALL_TRANSACTION + 6;
    private static final int TRUEBACKUPD_DELETE_TREE = IBinder.FIRST_CALL_TRANSACTION + 7;
    private static final int TRUEBACKUPD_SET_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 8;
    private static final int TRUEBACKUPD_GET_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 9;
    private static final int TRUEBACKUPD_ENCRYPT_ZIP_IN_PLACE = IBinder.FIRST_CALL_TRANSACTION + 10;
    private static final int TRUEBACKUPD_DECRYPT_ZIP_TO_FILE = IBinder.FIRST_CALL_TRANSACTION + 11;
    private static final int TRUEBACKUPD_CHANGE_PASSWORD = IBinder.FIRST_CALL_TRANSACTION + 12;

    private static final String FILE_CONFIG = "package_restore_config.json";

    private static final String DIR_APK = "apk";
    private static final String DIR_INT_DATA = "int_data";
    private static final String DIR_EXT_DATA = "ext_data";
    private static final String DIR_ADDL_DATA = "addl_data";

    private static final String ZIP_APK = "apk.zip";
    private static final String ZIP_USER = "user.zip";
    private static final String ZIP_USER_DE = "user_de.zip";
    private static final String ZIP_DATA = "data.zip";
    private static final String ZIP_OBB = "obb.zip";
    private static final String ZIP_MEDIA = "media.zip";

    private static final String ZIP_USER_CE_LEGACY = "user_ce.zip";
    private static final String ZIP_EXT_DATA_LEGACY = "external_data.zip";

    private static final String CE_BASE = "/data/user/0/";
    private static final String DE_BASE = "/data/user_de/0/";
    private static final String EXT_DATA_BASE = "/data/media/0/Android/data/";
    private static final String OBB_BASE = "/data/media/0/Android/obb/";
    private static final String MEDIA_BASE = "/data/media/0/Android/media/";

    /** Parent dirs whose GID external/OBB/media trees inherit (see DataBackup restoreData). */
    private static final String EXT_DATA_GID_REF = "/data/media/0/Android/data";
    private static final String OBB_GID_REF = "/data/media/0/Android/obb";
    private static final String MEDIA_GID_REF = "/data/media/0/Android/media";

    private static final String SETTINGS_FILE_SSAID = "settings_ssaid.xml";

    /** User id for CE/DE paths and permission restore (matches fixed CE_BASE user). */
    private static final int BACKUP_RESTORE_USER_ID = UserHandle.USER_SYSTEM;

    /** TBK1 magic (format implemented in truebackupd with wrapped master key header). */
    private static final byte[] ENC_MAGIC = new byte[] { 'T', 'B', 'K', '1' };
    private static final String REG_PW_KEYSTORE = "AndroidKeyStore";
    private static final String REG_PW_KEY_ALIAS = "truebackup_registration_password_v1";
    private static final String REG_PW_BLOB_PREFIX = "tbpw1:";

    public TrueBackupService(Context context) {
        mContext = context;
        Slog.i(TAG, "TrueBackupService Initialized");
    }

    @Override
    public void backupPackage(String packageName, String destPath) throws RemoteException {
        checkPermission();
        if (readRegistrationPassword() == null) {
            Slog.w(TAG, "backupPackage: no registration password set");
            return;
        }
        if (packageName == null || packageName.isEmpty() || destPath == null || destPath.isEmpty()) {
            Slog.w(TAG, "backupPackage: invalid args");
            return;
        }
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_BACKUP, packageName, destPath));
        } catch (InterruptedException e) {
            mWorkInFlight.decrementAndGet();
            Thread.currentThread().interrupt();
            throw new RemoteException("Interrupted while queueing backup");
        }
        ensureWorker();
    }

    @Override
    public void restorePackage(String packageName, String sourcePath) throws RemoteException {
        checkPermission();
        if (readRegistrationPassword() == null) {
            Slog.w(TAG, "restorePackage: no registration password set");
            return;
        }
        if (packageName == null || packageName.isEmpty() || sourcePath == null || sourcePath.isEmpty()) {
            Slog.w(TAG, "restorePackage: invalid args");
            return;
        }
        mWorkInFlight.incrementAndGet();
        try {
            mOperationQueue.put(new QueuedOperation(OP_RESTORE, packageName, sourcePath));
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
            mOperationQueue.put(new QueuedOperation(OP_DELETE, packageName, basePath));
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
        if (!daemonChangeRegistrationPassword(oldPassword, newPassword)) {
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
            }
            try {
                switch (op.type) {
                    case OP_RESTORE:
                        executeRestore(op.packageName, op.path);
                        break;
                    case OP_DELETE:
                        executeDeleteBackup(op.path, op.packageName);
                        break;
                    case OP_REKEY:
                        executeRekeyAllKnownBackups(op.arg1, op.arg2);
                        break;
                    default:
                        executeBackup(op.packageName, op.path);
                        break;
                }
            } catch (Exception e) {
                Slog.e(TAG, "Queued operation failed", e);
            } finally {
                synchronized (this) {
                    mActiveOperationKind = null;
                    mActiveOperationPackage = null;
                }
                mWorkInFlight.decrementAndGet();
            }
        }
    }

    private void executeBackup(String packageName, String destPath) {
        try {
            Slog.d(TAG, "Starting backup for " + packageName + " to " + destPath);
            recordKnownBackupPath(destPath);
            File pkgDir = resolvePackageBackupDir(destPath, packageName);
            if (!ensureDirs(pkgDir)) {
                Slog.e(TAG, "Could not create backup directory: " + pkgDir);
                return;
            }

            BackupParts parts = new BackupParts();

            // APK
            File apkZip = new File(new File(pkgDir, DIR_APK), ZIP_APK);
            parts.apk = zipApk(packageName, apkZip);
            maybeEncryptInPlace(apkZip);

            // Internal data
            File ceZip = new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER);
            parts.userCe = zipDirIfExists(new File(CE_BASE, packageName), ceZip);
            maybeEncryptInPlace(ceZip);

            File deZip = new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER_DE);
            parts.userDe = zipDirIfExists(new File(DE_BASE, packageName), deZip);
            maybeEncryptInPlace(deZip);

            // External data
            File extZip = new File(new File(pkgDir, DIR_EXT_DATA), ZIP_DATA);
            parts.extData = zipDirIfExists(new File(EXT_DATA_BASE, packageName), extZip);
            maybeEncryptInPlace(extZip);

            // Additional
            File obbZip = new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_OBB);
            parts.obb = zipDirIfExists(new File(OBB_BASE, packageName), obbZip);
            maybeEncryptInPlace(obbZip);

            File mediaZip = new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_MEDIA);
            parts.media = zipDirIfExists(new File(MEDIA_BASE, packageName), mediaZip);
            maybeEncryptInPlace(mediaZip);

            writeConfig(new File(pkgDir, FILE_CONFIG), packageName, parts);

            Slog.i(TAG, "Backup finished successfully for " + packageName);
        } catch (Exception e) {
            Slog.e(TAG, "Backup failed for " + packageName, e);
        }
    }

    private void executeRestore(String packageName, String sourcePath) {
        try {
            Slog.d(TAG, "Starting restore for " + packageName + " from " + sourcePath);
            File pkgDir = resolvePackageBackupDir(sourcePath, packageName);
            File legacyDir = new File(sourcePath, packageName + "_data");

            if (pkgDir.exists()) {
                restoreFromPackageDir(packageName, pkgDir);
            } else if (legacyDir.exists()) {
                File dataDir = new File("/data/data/" + packageName);
                recursiveCopy(legacyDir, dataDir);
                if (isPackageInstalled(packageName)) {
                    try {
                        int appUid = getApplicationUidOrThrow(packageName);
                        fixupRestoredTree(dataDir, appUid, appUid);
                    } catch (IOException e) {
                        Slog.w(TAG, "Legacy restore: could not fix ownership for " + packageName, e);
                    }
                }
                File cfgDir = resolvePackageBackupDir(sourcePath, packageName);
                if (cfgDir != null && new File(cfgDir, FILE_CONFIG).isFile()) {
                    applySecurityRestoreFromConfig(packageName, cfgDir);
                }
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
            if (deleteBackupPackageInternal(basePath, packageName)) {
                Slog.i(TAG, "Delete finished (primary) for " + packageName);
                return;
            }
            String json = readBackupMetadataJsonInternal(basePath, packageName);
            if (json != null && !json.isEmpty()) {
                try {
                    JSONObject root = new JSONObject(json);
                    JSONObject bc = root.optJSONObject("backupConfig");
                    String sp = bc != null ? bc.optString("storagePath", null) : null;
                    if (sp != null) {
                        String tsp = sp.trim();
                        if (!tsp.isEmpty() && deleteBackupPackageAtPathInternal(basePath, tsp)) {
                            Slog.i(TAG, "Delete finished (storagePath) for " + packageName);
                            return;
                        }
                    }
                } catch (Exception e) {
                    Slog.w(TAG, "delete metadata path", e);
                }
            }
            if (deleteBackupPackageInternal(basePath, packageName)) {
                Slog.i(TAG, "Delete finished (retry) for " + packageName);
            } else {
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
                    if (lbl != null) {
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
        if (deleteTreeWithDaemon(abs)) {
            return true;
        }
        Slog.w(TAG, "deleteTreeWithDaemon failed; fallback recursiveDelete for " + abs);
        recursiveDelete(dir);
        return !dir.exists();
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

    private File getTrueBackupSystemDir() {
        File base = Environment.getDataSystemDirectory();
        return new File(base, "truebackup");
    }

    /**
     * Scratch space under {@code /data/system/truebackup/tmp} (not next to backup zips on removable
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

    private synchronized String readRegistrationPassword() {
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
            if (stored.isEmpty()) return null;
            String plain = decryptRegisteredPassword(stored);
            return plain != null ? plain : stored;
        } catch (RemoteException e) {
            Slog.w(TAG, "readRegistrationPassword", e);
            return null;
        } finally {
            reply.recycle();
            data.recycle();
        }
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

    private File getKnownPathsFile() {
        return new File(getTrueBackupSystemDir(), "known_paths.txt");
    }

    private synchronized void recordKnownBackupPath(String basePath) {
        if (basePath == null || basePath.isEmpty()) return;
        File dir = getTrueBackupSystemDir();
        if (!dir.exists() && !dir.mkdirs()) return;
        // De-dup on read; keep file append-only to avoid complex locking.
        try (FileOutputStream out = new FileOutputStream(getKnownPathsFile(), true)) {
            out.write((basePath + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            try {
                Os.chmod(getKnownPathsFile().getAbsolutePath(), 0600);
            } catch (Exception ignored) {
            }
        } catch (IOException ignored) {
        }
    }

    private synchronized HashSet<String> readKnownBackupPaths() {
        HashSet<String> out = new HashSet<>();
        File f = getKnownPathsFile();
        if (!f.isFile()) return out;
        try (FileInputStream in = new FileInputStream(f)) {
            String s = new String(readFully(in), StandardCharsets.UTF_8);
            for (String line : s.split("\n")) {
                String p = line.trim();
                if (!p.isEmpty()) out.add(p);
            }
        } catch (IOException ignored) {
        }
        return out;
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

    private void maybeEncryptInPlace(File zipFile) {
        if (zipFile == null || !zipFile.exists() || !zipFile.isFile()) return;
        if (isEncryptedFile(zipFile)) return;
        String pw = readRegistrationPassword();
        if (pw == null) return;
        if (!daemonEncryptZipInPlace(zipFile, pw)) {
            Slog.w(TAG, "daemonEncryptZipInPlace failed for " + zipFile);
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
        if (paths.isEmpty()) return;
        for (String basePath : paths) {
            if (basePath == null || basePath.isEmpty()) continue;
            File appsDir = resolveAppsDir(basePath);
            if (appsDir == null || !appsDir.isDirectory()) continue;
            File[] pkgs = appsDir.listFiles();
            if (pkgs == null) continue;
            for (File pkgDir : pkgs) {
                if (pkgDir == null || !pkgDir.isDirectory()) continue;
                rekeyZipFilesUnder(pkgDir, oldPassword, newPassword);
            }
        }
    }

    private void rekeyZipFilesUnder(File pkgDir, String oldPassword, String newPassword) {
        File[] files = pkgDir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f == null) continue;
            if (f.isDirectory()) {
                rekeyZipFilesUnder(f, oldPassword, newPassword);
                continue;
            }
            if (!f.isFile()) continue;
            if (!f.getName().endsWith(".zip")) continue;
            try {
                if (isEncryptedFile(f)) {
                    File plainTmp = null;
                    try {
                        plainTmp = createTrueBackupWorkFile("tb_rekey_", ".zip");
                        if (!daemonDecryptZipToFile(f, plainTmp, oldPassword)) {
                            Slog.w(TAG, "rekey decrypt failed: " + f);
                            continue;
                        }
                        if (!f.delete()) {
                            Slog.w(TAG, "rekey could not delete encrypted file: " + f);
                            continue;
                        }
                        Files.copy(plainTmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        if (!daemonEncryptZipInPlace(f, newPassword)) {
                            Slog.w(TAG, "rekey encrypt failed: " + f);
                        }
                    } finally {
                        if (plainTmp != null) {
                            //noinspection ResultOfMethodCallIgnored
                            plainTmp.delete();
                        }
                    }
                } else {
                    if (!daemonEncryptZipInPlace(f, newPassword)) {
                        Slog.w(TAG, "rekey encrypt plain failed: " + f);
                    }
                }
            } catch (Exception e) {
                Slog.w(TAG, "rekey failed: " + f, e);
            }
        }
    }

    private static File resolveAppsDir(String basePath) {
        if (basePath == null) return null;
        File base = new File(basePath);

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

    private boolean isPackageInstalled(String packageName) {
        try {
            mContext.getPackageManager().getPackageInfo(packageName, 0);
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

    private void installApksFromBackupIfNeeded(String packageName, File pkgDir) throws IOException {
        if (isPackageInstalled(packageName)) {
            return;
        }

        File apkZip = new File(new File(pkgDir, DIR_APK), ZIP_APK);
        if (!apkZip.exists()) {
            throw new IOException("App not installed and apk.zip missing: " + apkZip);
        }

        // Encrypted backups store TBK1-wrapped bytes; decrypt via truebackupd before parsing as ZIP.
        // Decrypted copy lives under /data/system/truebackup/tmp (system_server has no app cache dir).
        File zipToRead = apkZip;
        File tmpDecrypted = null;
        if (isEncryptedFile(apkZip)) {
            tmpDecrypted = createTrueBackupWorkFile("truebackup_apk_", ".zip");
            String pw = readRegistrationPassword();
            if (pw == null) {
                //noinspection ResultOfMethodCallIgnored
                tmpDecrypted.delete();
                throw new IOException("No registration password for apk.zip");
            }
            if (!daemonDecryptZipToFile(apkZip, tmpDecrypted, pw)) {
                //noinspection ResultOfMethodCallIgnored
                tmpDecrypted.delete();
                throw new IOException("Could not decrypt apk.zip: " + apkZip);
            }
            zipToRead = tmpDecrypted;
        }

        // Install via PackageInstaller session (supports splits).
        PackageManager pm = mContext.getPackageManager();
        PackageInstaller installer = pm.getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(packageName);

        int sessionId = installer.createSession(params);
        PackageInstaller.Session session = installer.openSession(sessionId);
        try {
            byte[] buffer = new byte[128 * 1024];

            boolean wroteAny = false;
            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipToRead))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory()) continue;
                    String name = entry.getName();
                    if (name == null || !name.endsWith(".apk")) continue;

                    String apkName = new File(name).getName();
                    if (apkName.isEmpty()) continue;

                    try (java.io.OutputStream out = session.openWrite(apkName, 0, entry.getSize())) {
                        int n;
                        while ((n = zis.read(buffer)) > 0) {
                            out.write(buffer, 0, n);
                        }
                        session.fsync(out);
                    }
                    wroteAny = true;
                }
            }

            if (!wroteAny) {
                throw new IOException("No APK entries found inside: " + apkZip);
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
                throw new IOException("Install failed for " + packageName + ": status=" + status + " msg=" + msg);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted waiting for install result for: " + packageName, e);
        } finally {
            session.close();
            if (tmpDecrypted != null) {
                //noinspection ResultOfMethodCallIgnored
                tmpDecrypted.delete();
            }
        }

        // Verify installed.
        if (!isPackageInstalled(packageName)) {
            throw new IOException("Install reported success but package not installed: " + packageName);
        }
    }

    private static void recursiveDelete(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) {
                    recursiveDelete(c);
                }
            }
        }
        // Best-effort.
        //noinspection ResultOfMethodCallIgnored
        f.delete();
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
        File base = new File(basePath);

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
        if (mkdirsWithDaemon(dir)) {
            return true;
        }
        return dir.mkdirs();
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

    private boolean zipMultiFileWithDaemon(File[] sourceFiles, String[] entryNames, File outZip) {
        if (sourceFiles == null || entryNames == null) return false;
        if (sourceFiles.length != entryNames.length) return false;

        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(outZip.getAbsolutePath());
            data.writeInt(sourceFiles.length);
            for (int i = 0; i < sourceFiles.length; i++) {
                data.writeString16(sourceFiles[i].getAbsolutePath());
                data.writeString16(entryNames[i]);
            }

            boolean ok = daemon.transact(TRUEBACKUPD_ZIP_MULTI_FILE, data, reply, 0);
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

    private boolean zipSingleFileWithDaemon(File sourceFile, File outZip, String entryName) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(sourceFile.getAbsolutePath());
            data.writeString16(outZip.getAbsolutePath());
            data.writeString16(entryName);
            boolean ok = daemon.transact(TRUEBACKUPD_ZIP_SINGLE_FILE, data, reply, 0);
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

    private boolean zipApk(String packageName, File outZip) throws IOException {
        PackageManager pm = mContext.getPackageManager();
        ApplicationInfo ai;
        try {
            ai = pm.getApplicationInfo(packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            Slog.e(TAG, "Package not found: " + packageName);
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

        // Prefer daemon (system_server may not be allowed to read split APKs under /data/app).
        if (zipMultiFileWithDaemon(files, entries, outZip)) {
            return true;
        }

        // Fallback: create zip in Java (may fail under SELinux, but keeps behavior consistent).
        File parent = outZip.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Could not create directory: " + parent);
        }

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip))) {
            for (int i = 0; i < files.length; i++) {
                File f = files[i];
                if (f == null || !f.exists() || !f.isFile()) {
                    continue;
                }
                zos.putNextEntry(new ZipEntry(entries[i]));
                try (FileInputStream in = new FileInputStream(f)) {
                    copy(in, zos);
                }
                zos.closeEntry();
            }
        }

        return true;
    }

    private boolean zipDirIfExists(File sourceDir, File outZip) throws IOException {
        // Try daemon first: system_server may not be able to stat /data_mirror paths due to SELinux.
        if (zipDirectoryWithDaemon(sourceDir, outZip)) {
            return true;
        }

        if (!sourceDir.exists()) {
            return false;
        }

        zipDirectory(sourceDir, outZip);
        return true;
    }

    private void zipSingleFile(File sourceFile, File outZip, String entryName) throws IOException {
        if (zipSingleFileWithDaemon(sourceFile, outZip, entryName)) {
            return;
        }

        File parent = outZip.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Could not create directory: " + parent);
        }

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip))) {
            ZipEntry entry = new ZipEntry(entryName);
            zos.putNextEntry(entry);
            try (FileInputStream in = new FileInputStream(sourceFile)) {
                copy(in, zos);
            }
            zos.closeEntry();
        }
    }

    private void zipDirectory(File sourceDir, File outZip) throws IOException {
        File parent = outZip.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Could not create directory: " + parent);
        }

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip))) {
            zipDirectoryInternal(sourceDir, sourceDir, zos);
        }
    }

    private void zipDirectoryInternal(File rootDir, File current, ZipOutputStream zos) throws IOException {
        File[] children = current.listFiles();
        if (children == null) return;

        for (File child : children) {
            String entryName = rootDir.toURI().relativize(child.toURI()).getPath();
            if (child.isDirectory()) {
                if (!entryName.endsWith("/")) entryName = entryName + "/";
                zos.putNextEntry(new ZipEntry(entryName));
                zos.closeEntry();
                zipDirectoryInternal(rootDir, child, zos);
            } else {
                zos.putNextEntry(new ZipEntry(entryName));
                try (FileInputStream in = new FileInputStream(child)) {
                    copy(in, zos);
                }
                zos.closeEntry();
            }
        }
    }

    private void restoreFromPackageDir(String packageName, File pkgDir) throws IOException {
        // If the app is not installed, install it first from apk.zip so /data_mirror targets exist.
        installApksFromBackupIfNeeded(packageName, pkgDir);

        final int appUid = getApplicationUidOrThrow(packageName);

        File ceZip = firstExisting(
                new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER),
                new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER_CE_LEGACY));
        if (ceZip != null) {
            File target = new File(CE_BASE, packageName);
            unzipToDirMaybeDaemon(ceZip, target);
            fixupRestoredTree(target, appUid, appUid);
        }

        File deZip = new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER_DE);
        if (deZip.exists()) {
            File target = new File(DE_BASE, packageName);
            unzipToDirMaybeDaemon(deZip, target);
            fixupRestoredTree(target, appUid, appUid);
        }

        File extZip = firstExisting(
                new File(new File(pkgDir, DIR_EXT_DATA), ZIP_DATA),
                new File(new File(pkgDir, DIR_EXT_DATA), ZIP_EXT_DATA_LEGACY));
        if (extZip != null) {
            File target = new File(EXT_DATA_BASE, packageName);
            unzipToDirMaybeDaemon(extZip, target);
            int extUid = statDirUidOrFallback(EXT_DATA_GID_REF, appUid, "uid");
            int extGid = statDirGidOrUid(EXT_DATA_GID_REF, appUid);
            fixupRestoredTree(target, extUid, extGid);
        }

        File obbZip = new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_OBB);
        if (obbZip.exists()) {
            File target = new File(OBB_BASE, packageName);
            unzipToDirMaybeDaemon(obbZip, target);
            int obbUid = statDirUidOrFallback(OBB_GID_REF, appUid, "uid");
            int obbGid = statDirGidOrUid(OBB_GID_REF, appUid);
            fixupRestoredTree(target, obbUid, obbGid);
        }

        File mediaZip = new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_MEDIA);
        if (mediaZip.exists()) {
            File target = new File(MEDIA_BASE, packageName);
            unzipToDirMaybeDaemon(mediaZip, target);
            int mediaUid = statDirUidOrFallback(MEDIA_GID_REF, appUid, "uid");
            int mediaGid = statDirGidOrUid(MEDIA_GID_REF, appUid);
            fixupRestoredTree(target, mediaUid, mediaGid);
        }

        applySecurityRestoreFromConfig(packageName, pkgDir);
    }

    private int getApplicationUidOrThrow(String packageName) throws IOException {
        try {
            ApplicationInfo ai = mContext.getPackageManager().getApplicationInfo(packageName, 0);
            return ai.uid;
        } catch (PackageManager.NameNotFoundException e) {
            throw new IOException("Package not installed: " + packageName, e);
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

    private static int statDirUidOrFallback(String dirPath, int fallback, String label) {
        try {
            return (int) Os.stat(dirPath).st_uid;
        } catch (ErrnoException e) {
            Slog.w(TAG, "stat failed for " + dirPath + "; using fallback as " + label, e);
            return fallback;
        }
    }

    /**
     * Extracted files are owned by root; relabel and chown so the app can run (same idea as
     * {@code PackagesRestoreUtil.restoreData} in Android-DataBackup).
     */
    private void fixupRestoredTree(File path, int uid, int gid) {
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
        if (chownAndRestoreconWithDaemon(abs, uid, gid)) {
            return;
        }
        Slog.w(TAG, "truebackupd fixup failed for " + abs + "; trying SELinux.restoreconRecursive only");
        if (!SELinux.restoreconRecursive(path)) {
            Slog.e(TAG, "SELinux.restoreconRecursive failed for " + abs);
        }
    }

    private boolean chownAndRestoreconWithDaemon(String absolutePath, int uid, int gid) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) {
            return false;
        }
        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(absolutePath);
            data.writeInt(uid);
            data.writeInt(gid);
            boolean ok = daemon.transact(TRUEBACKUPD_CHOWN_AND_RESTORECON, data, reply, 0);
            if (!ok) {
                return false;
            }
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "chown/restorecon transact failed", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean zipDirectoryWithDaemon(File sourceDir, File outZip) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(sourceDir.getAbsolutePath());
            data.writeString16(outZip.getAbsolutePath());
            boolean ok = daemon.transact(TRUEBACKUPD_ZIP_DIR, data, reply, 0);
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

    private boolean daemonEncryptZipInPlace(File zipFile, String password) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || password == null || password.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(zipFile.getAbsolutePath());
            data.writeString16(password);
            boolean ok = daemon.transact(TRUEBACKUPD_ENCRYPT_ZIP_IN_PLACE, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonEncryptZipInPlace", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private boolean daemonDecryptZipToFile(File encFile, File outPlain, String password) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null || password == null || password.isEmpty()) return false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(encFile.getAbsolutePath());
            data.writeString16(outPlain.getAbsolutePath());
            data.writeString16(password);
            boolean ok = daemon.transact(TRUEBACKUPD_DECRYPT_ZIP_TO_FILE, data, reply, 0);
            if (!ok) return false;
            return reply.readInt() == 0;
        } catch (RemoteException e) {
            Slog.w(TAG, "daemonDecryptZipToFile", e);
            return false;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private void unzipToDirMaybeDaemon(File zipFile, File targetDir) throws IOException {
        File toUnzip = zipFile;
        File tmp = null;
        try {
            if (isEncryptedFile(zipFile)) {
                tmp = createTrueBackupWorkFile("tb_unzip_", ".zip");
                String pw = readRegistrationPassword();
                if (pw == null) {
                    throw new IOException("No registration password for " + zipFile);
                }
                if (!daemonDecryptZipToFile(zipFile, tmp, pw)) {
                    throw new IOException("Could not decrypt backup zip: " + zipFile);
                }
                toUnzip = tmp;
            }
            if (unzipToDirWithDaemon(toUnzip, targetDir)) {
                return;
            }
            unzipToDir(toUnzip, targetDir);
        } finally {
            if (tmp != null) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }
    }

    private boolean unzipToDirWithDaemon(File zipFile, File targetDir) {
        IBinder daemon = ServiceManager.getService(TRUEBACKUPD_SERVICE);
        if (daemon == null) return false;

        android.os.Parcel data = android.os.Parcel.obtain();
        android.os.Parcel reply = android.os.Parcel.obtain();
        try {
            data.writeInt(TRUEBACKUPD_TOKEN);
            data.writeString16(zipFile.getAbsolutePath());
            data.writeString16(targetDir.getAbsolutePath());
            boolean ok = daemon.transact(TRUEBACKUPD_UNZIP_TO_DIR, data, reply, 0);
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

    private File firstExisting(File a, File b) {
        if (a.exists()) return a;
        if (b.exists()) return b;
        return null;
    }

    private void unzipToDir(File zipFile, File targetDir) throws IOException {
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            throw new IOException("Could not create directory: " + targetDir);
        }

        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(targetDir, entry.getName());
                if (!isSubPath(targetDir, out)) {
                    throw new IOException("Zip entry path traversal: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    if (!out.exists() && !out.mkdirs()) {
                        throw new IOException("Could not create directory: " + out);
                    }
                } else {
                    File parent = out.getParentFile();
                    if (parent != null && !parent.exists() && !parent.mkdirs()) {
                        throw new IOException("Could not create directory: " + parent);
                    }
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        copy(zis, fos);
                    }
                }
                zis.closeEntry();
            }
        }
    }

    private boolean isSubPath(File base, File child) throws IOException {
        String basePath = base.getCanonicalPath();
        String childPath = child.getCanonicalPath();
        return childPath.equals(basePath) || childPath.startsWith(basePath + File.separator);
    }

    private void writeConfig(File outConfig, String packageName, BackupParts parts)
            throws IOException, JSONException {
        final long now = System.currentTimeMillis();
        final PackageManager pm = mContext.getPackageManager();

        PackageInfo pi = null;
        ApplicationInfo ai = null;
        try {
            pi = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS);
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
        backupConfig.put("userId", 0);
        backupConfig.put("compression", "zip");
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
            dataStats.put("apkBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_APK), ZIP_APK)));
            dataStats.put("userBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER)));
            dataStats.put("userDeBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_INT_DATA), ZIP_USER_DE)));
            dataStats.put("dataBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_EXT_DATA), ZIP_DATA)));
            dataStats.put("obbBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_OBB)));
            dataStats.put("mediaBytes", fileBytesIfExists(new File(new File(pkgDir, DIR_ADDL_DATA), ZIP_MEDIA)));
        }
        obj.put("dataStats", dataStats);

        JSONObject security = new JSONObject();
        if (ai != null) security.put("uid", ai.uid);
        String ssaidHex = (ai != null) ? readSsaidHexFromDisk(BACKUP_RESTORE_USER_ID, ai.uid) : null;
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

        if (writeFileWithDaemon(outConfig, data)) {
            return;
        }

        File parent = outConfig.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("Could not create directory: " + parent);
        }

        try (FileOutputStream fos = new FileOutputStream(outConfig)) {
            fos.write(data);
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

    private void recursiveCopy(File source, File destination) throws IOException {
        if (source.isDirectory()) {
            if (!destination.exists() && !destination.mkdirs()) {
                throw new IOException("Could not create directory: " + destination);
            }
            String[] children = source.list();
            if (children != null) {
                for (String child : children) {
                    recursiveCopy(new File(source, child), new File(destination, child));
                }
            }
        } else {
            try (FileInputStream in = new FileInputStream(source);
                 FileOutputStream out = new FileOutputStream(destination)) {
                byte[] buf = new byte[1024 * 16];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
            }
        }
    }

    private void copy(FileInputStream in, FileOutputStream out) throws IOException {
        byte[] buf = new byte[1024 * 16];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
    }

    private void copy(FileInputStream in, ZipOutputStream out) throws IOException {
        byte[] buf = new byte[1024 * 16];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
    }

    private void copy(ZipInputStream in, FileOutputStream out) throws IOException {
        byte[] buf = new byte[1024 * 16];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
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

    private void applySecurityRestoreFromConfig(String packageName, File pkgDir) {
        File cfg = new File(pkgDir, FILE_CONFIG);
        if (!cfg.isFile()) {
            return;
        }
        try {
            String json = new String(readFully(cfg), StandardCharsets.UTF_8);
            JSONObject root = new JSONObject(json);
            applySecurityFromJson(packageName, root.optJSONObject("security"));
        } catch (Exception e) {
            Slog.w(TAG, "Security restore skipped for " + packageName, e);
        }
    }

    /**
     * Re-apply runtime permissions and AppOp modes from backup metadata (DataBackup-style).
     * SSAID is stored in backups when readable from disk but cannot be written back safely from
     * system_server without a dedicated Settings API.
     */
    private void applySecurityFromJson(String packageName, JSONObject security) {
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
            uid = getApplicationUidOrThrow(packageName);
        } catch (IOException e) {
            Slog.w(TAG, "Security restore: package not installed " + packageName);
            return;
        }

        try {
            resetAppOpsForPackage(BACKUP_RESTORE_USER_ID, packageName);
        } catch (RemoteException e) {
            Slog.w(TAG, "reset app ops failed for " + packageName, e);
        }

        PackageManager pm = mContext.getPackageManager();
        UserHandle user = UserHandle.of(BACKUP_RESTORE_USER_ID);
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
