/*
 * SPDX-License-Identifier: Apache-2.0
 */
package android.app;

import android.annotation.NonNull;
import android.annotation.SystemService;
import android.content.Context;
import android.os.RemoteException;

import com.android.internal.app.IAppLockStateListener;
import com.android.internal.app.IAppLockManager;
import com.android.internal.app.IAppSessionListener;

import java.util.Collections;
import java.util.List;

/**
 * System-level App Lock API for {@code com.android.applock} and other privileged clients.
 *
 * @hide
 */
@SystemService(Context.APP_LOCK_SERVICE)
public class AppLockManager {

    /** @hide */
    public static final int LOCK_BEHAVIOR_ON_LEAVE = 0;
    /** @hide */
    public static final int LOCK_BEHAVIOR_TIMEOUT = 1;
    /** @hide */
    public static final int LOCK_BEHAVIOR_ON_SCREEN_OFF = 2;
    /** @hide */
    public static final int LOCK_BEHAVIOR_ON_KILL = 3;

    /** @hide */
    public static final String SETTING_ENABLED = "applock_enabled";
    /** @hide */
    public static final String SETTING_LOCK_BEHAVIOR = "applock_locked_app_behavior";
    /** @hide */
    public static final String SETTING_LOCK_TIMEOUT = "applock_locked_app_timeout";
    /** @hide */
    public static final String SETTING_CONFIG = "applock_config";

    /** @hide */
    public static final String EXTRA_LOCKED_PACKAGE = "LOCKED_PACKAGE";
    /** @hide */
    public static final String EXTRA_LOCKED_UID = "LOCKED_UID";
    /** @hide */
    public static final String EXTRA_LOCKED_COMPONENT = "LOCKED_COMPONENT";
    /** @hide */
    public static final String EXTRA_NOTIFICATION_APP_LOCKED = "android.app.extra.APP_LOCK_LOCKED";

    /** @hide */
    public static final int DEFAULT_LOCK_TIMEOUT = 30;

    /** @hide */
    public enum AppLockState {
        NONE,
        UNLOCKED,
        LOCKED;

        public boolean hasAppLock() {
            return this != NONE;
        }

        public boolean needsAuth() {
            return this == LOCKED;
        }

        public static AppLockState fromOrdinal(int ordinal) {
            AppLockState[] values = values();
            if (ordinal < 0 || ordinal >= values.length) return NONE;
            return values[ordinal];
        }
    }

    private final Context mContext;
    private final IAppLockManager mService;

    /** @hide */
    public AppLockManager(@NonNull Context context, @NonNull IAppLockManager service) {
        mContext = context;
        mService = service;
    }

    /** @hide */
    public boolean isEnabled() {
        try {
            return mService.isEnabled();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void setEnabled(boolean enabled) {
        try {
            mService.setEnabled(enabled);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public AppLockState getAppLockState(@NonNull String packageName) {
        try {
            return AppLockState.fromOrdinal(mService.getAppLockState(packageName));
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void addLockedApp(@NonNull String packageName) {
        try {
            mService.addLockedApp(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void removeLockedApp(@NonNull String packageName) {
        try {
            mService.removeLockedApp(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    @NonNull
    public List<String> getLockedPackages() {
        try {
            List<String> result = mService.getLockedPackages();
            return result != null ? result : Collections.emptyList();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    @NonNull
    public List<String> getLockablePackages() {
        try {
            List<String> result = mService.getLockablePackages();
            return result != null ? result : Collections.emptyList();
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public boolean isPackageLockable(@NonNull String packageName) {
        try {
            return mService.isPackageLockable(packageName);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void unlockApp(@NonNull String packageName, int userId) {
        try {
            mService.unlockApp(packageName, userId);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void promptUnlock(@NonNull String packageName, int userId) {
        try {
            mService.promptUnlock(packageName, userId);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void registerAppLockStateListener(IAppLockStateListener listener) {
        try {
            mService.registerAppLockStateListener(listener);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void unregisterAppLockStateListener(IAppLockStateListener listener) {
        try {
            mService.unregisterAppLockStateListener(listener);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void registerAppSessionListener(IAppSessionListener listener) {
        try {
            mService.registerAppSessionListener(listener);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** @hide */
    public void unregisterAppSessionListener(IAppSessionListener listener) {
        try {
            mService.unregisterAppSessionListener(listener);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }
}
