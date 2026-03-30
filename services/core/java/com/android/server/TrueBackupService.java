package com.android.server;

import android.content.Context;
import android.os.ITrueBackupService;
import android.os.RemoteException;
import android.util.Slog;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Service to handle TrueBackup operations with system privileges.
 * Allows backup and restore of app data without root.
 * @hide
 */
public class TrueBackupService extends ITrueBackupService.Stub {
    private static final String TAG = "TrueBackupService";
    private final Context mContext;
    private boolean mInProgress = false;

    public TrueBackupService(Context context) {
        mContext = context;
        Slog.i(TAG, "TrueBackupService Initialized");
    }

    @Override
    public synchronized void backupPackage(String packageName, String destPath) throws RemoteException {
        checkPermission();
        if (mInProgress) {
            Slog.w(TAG, "Operation already in progress");
            return;
        }
        mInProgress = true;
        
        new Thread(() -> {
            try {
                Slog.d(TAG, "Starting backup for " + packageName + " to " + destPath);
                File dataDir = new File("/data/data/" + packageName);
                File destFile = new File(destPath, packageName + ".data");
                
                if (!dataDir.exists()) {
                    Slog.e(TAG, "Data directory not found for " + packageName);
                    return;
                }

                // In a real implementation, we would use tar or a zip library.
                // For this demonstration, we'll simulate a recursive copy or 
                // perform a basic directory walk to show the capability.
                recursiveCopy(dataDir, new File(destPath, packageName + "_data"));
                
                Slog.i(TAG, "Backup finished successfully for " + packageName);
            } catch (Exception e) {
                Slog.e(TAG, "Backup failed for " + packageName, e);
            } finally {
                synchronized (this) {
                    mInProgress = false;
                }
            }
        }).start();
    }

    @Override
    public synchronized void restorePackage(String packageName, String sourcePath) throws RemoteException {
        checkPermission();
        if (mInProgress) {
            Slog.w(TAG, "Operation already in progress");
            return;
        }
        mInProgress = true;

        new Thread(() -> {
            try {
                Slog.d(TAG, "Starting restore for " + packageName + " from " + sourcePath);
                File sourceDir = new File(sourcePath, packageName + "_data");
                File dataDir = new File("/data/data/" + packageName);

                if (!sourceDir.exists()) {
                    Slog.e(TAG, "Source data not found at " + sourcePath);
                    return;
                }

                // Restore logic: copy back and fix permissions if necessary.
                // system_server can write to /data/data but needs to ensure
                // the app's UID is preserved for the files.
                recursiveCopy(sourceDir, dataDir);
                
                Slog.i(TAG, "Restore finished successfully for " + packageName);
            } catch (Exception e) {
                Slog.e(TAG, "Restore failed for " + packageName, e);
            } finally {
                synchronized (this) {
                    mInProgress = false;
                }
            }
        }).start();
    }

    @Override
    public synchronized boolean isOperationInProgress() {
        return mInProgress;
    }

    private void checkPermission() {
        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.BACKUP, "TrueBackup");
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
}
