package com.android.internal.app;

import com.android.internal.app.IAppLockStateListener;
import com.android.internal.app.IAppSessionListener;

/**
 * System App Lock service ({@code applock}).
 * @hide
 */
interface IAppLockManager {
    boolean isEnabled();
    void setEnabled(boolean enabled);

    int getAppLockState(String packageName);

    void addLockedApp(String packageName);
    void removeLockedApp(String packageName);

    List<String> getLockedPackages();
    List<String> getLockablePackages();
    boolean isPackageLockable(String packageName);

    void unlockApp(String packageName, int userId);
    void promptUnlock(String packageName, int userId);

    void registerAppLockStateListener(IAppLockStateListener listener);
    void unregisterAppLockStateListener(IAppLockStateListener listener);
    void registerAppSessionListener(IAppSessionListener listener);
    void unregisterAppSessionListener(IAppSessionListener listener);
}
