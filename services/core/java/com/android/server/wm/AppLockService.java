/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.wm;

import static android.app.AppLockManager.AppLockState.LOCKED;
import static android.app.AppLockManager.AppLockState.NONE;
import static android.app.AppLockManager.AppLockState.UNLOCKED;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AppLockManager;
import android.app.AppLockManager.AppLockState;
import android.app.IApplicationThread;
import android.app.WindowConfiguration;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Binder;
import android.os.Handler;
import android.os.Process;
import android.os.IBinder;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.UserHandle;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Slog;

import com.android.internal.app.IAppLockManager;
import com.android.internal.app.IAppLockStateListener;
import com.android.internal.app.IAppSessionListener;
import com.android.server.applock.AppLockController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * System App Lock service: locked-app policy, session unlock, and launch interception.
 *
 * @hide
 */
public class AppLockService extends IAppLockManager.Stub implements IAppLockService {
    private static final String TAG = "AppLockService";

    /** System auth overlay (PIN/pattern/biometric). */
    private static final String AUTH_PACKAGE = "com.android.applocker";
    private static final String AUTH_ACTIVITY = "com.android.applocker.AuthenticateActivity";
    /** Intent action understood by {@link #AUTH_PACKAGE} auth overlay. */
    private static final String ACTION_AUTH_UNLOCK = "com.android.applocker.action.SYSTEM_UNLOCK";

    private static final String EXTRA_LOCKED_UID = AppLockManager.EXTRA_LOCKED_UID;
    private static final String EXTRA_LOCKED_PACKAGE = AppLockManager.EXTRA_LOCKED_PACKAGE;
    private static final String EXTRA_LOCKED_COMPONENT = AppLockManager.EXTRA_LOCKED_COMPONENT;
    private static final String EXTRA_APP_LABEL = "app_label";

    private static final String SETTING_LOCK_BEHAVIOR = AppLockManager.SETTING_LOCK_BEHAVIOR;
    private static final String SETTING_LOCK_TIMEOUT = AppLockManager.SETTING_LOCK_TIMEOUT;

    private static final int LOCK_BEHAVIOR_ON_LEAVE = AppLockManager.LOCK_BEHAVIOR_ON_LEAVE;
    private static final int LOCK_BEHAVIOR_TIMEOUT = AppLockManager.LOCK_BEHAVIOR_TIMEOUT;
    private static final int LOCK_BEHAVIOR_ON_SCREEN_OFF = AppLockManager.LOCK_BEHAVIOR_ON_SCREEN_OFF;
    private static final int LOCK_BEHAVIOR_ON_KILL = AppLockManager.LOCK_BEHAVIOR_ON_KILL;

    /** Packages that must never be subject to app lock. */
    private static final Set<String> PROTECTED_PACKAGES = Set.of(
            "android",
            AUTH_PACKAGE,
            "com.android.applock",
            "com.android.settings"
    );

    private ActivityTaskManagerService mAtms;
    private Context mContext;
    private AppLockController mController;
    private SettingsObserver mSettingsObserver;
    private ResolveInfo mAuthResolveInfo;
    private Intent mConfirmIntent;
    private int mRequestCode;

    private final RemoteCallbackList<IAppLockStateListener> mAppLockStateListeners =
            new RemoteCallbackList<>();
    private final RemoteCallbackList<IAppSessionListener> mAppSessionListeners =
            new RemoteCallbackList<>();

    private final Set<String> mUnlockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> mPendingUnlocks = new HashSet<>();
    private final Map<String, Long> mUnlockTimestamps = new HashMap<>();
    private final Map<String, Runnable> mTimeoutRunnables = new HashMap<>();
    private String mLastFocusedAppKey;
    private int mLockBehavior = LOCK_BEHAVIOR_ON_LEAVE;
    private int mLockTimeout = AppLockManager.DEFAULT_LOCK_TIMEOUT;
    private boolean mKeyguardDone = true;
    private boolean mCheckRecentTasks;
    private int mCurrentUserId;

    private static final class Holder {
        private static final AppLockService INSTANCE = new AppLockService();
    }

    public static AppLockService get() {
        return Holder.INSTANCE;
    }

    private AppLockService() {
    }

    public static void systemReady(Context context, ActivityTaskManagerService atms) {
        AppLockService instance = get();
        instance.onSystemReady(context, atms);
        ServiceManager.addService(Context.APP_LOCK_SERVICE, instance);
        Slog.i(TAG, "registered " + Context.APP_LOCK_SERVICE);
    }

    private void onSystemReady(Context context, ActivityTaskManagerService atms) {
        mContext = context;
        mAtms = atms;

        try {
            mAuthResolveInfo = context.getPackageManager().resolveActivity(
                    getConfirmIntent(), PackageManager.MATCH_DEFAULT_ONLY);
        } catch (Exception e) {
            Slog.w(TAG, "Could not resolve auth activity", e);
        }

        mRequestCode = getConfirmIntent().toString().hashCode() & 0x0FFFFFFF;
        mSettingsObserver = new SettingsObserver(atms.mH);
        mSettingsObserver.onChange(true);

        mController = new AppLockController(context, PROTECTED_PACKAGES);
        mController.init();

        IntentFilter filter = new IntentFilter(Intent.ACTION_PACKAGE_FULLY_REMOVED);
        filter.addDataScheme("package");
        context.registerReceiverAsUser(mPackageRemovedReceiver, UserHandle.ALL, filter,
                null, atms.mH);
    }

    private final BroadcastReceiver mPackageRemovedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || intent.getData() == null) return;
            String packageName = intent.getData().getSchemeSpecificPart();
            if (TextUtils.isEmpty(packageName)) return;
            if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return;
            cleanupPackage(packageName);
        }
    };

    private void cleanupPackage(String packageName) {
        if (mController == null) return;
        mController.cleanupPackage(packageName);
        notifyAppLockStateChanged(packageName, false);

        for (String key : new ArrayList<>(mUnlockedApps)) {
            if (key.endsWith(":" + packageName)) {
                mUnlockedApps.remove(key);
                mUnlockTimestamps.remove(key);
                cancelTimeoutLock(key);
            }
        }
        synchronized (mPendingUnlocks) {
            mPendingUnlocks.removeIf(key -> key.endsWith(":" + packageName));
        }
    }

    private final class SettingsObserver extends ContentObserver {
        SettingsObserver(Handler handler) {
            super(handler);
            ContentResolver resolver = mContext.getContentResolver();
            resolver.registerContentObserver(
                    Settings.Secure.getUriFor(SETTING_LOCK_BEHAVIOR), false, this, -1);
            resolver.registerContentObserver(
                    Settings.Secure.getUriFor(SETTING_LOCK_TIMEOUT), false, this, -1);
        }

        @Override
        public void onChange(boolean selfChange) {
            ContentResolver resolver = mContext.getContentResolver();
            mLockBehavior = Settings.Secure.getIntForUser(resolver, SETTING_LOCK_BEHAVIOR,
                    LOCK_BEHAVIOR_ON_LEAVE, UserHandle.USER_SYSTEM);
            mLockTimeout = Settings.Secure.getIntForUser(resolver, SETTING_LOCK_TIMEOUT,
                    AppLockManager.DEFAULT_LOCK_TIMEOUT, UserHandle.USER_SYSTEM);
        }
    }

    private Intent getConfirmIntent() {
        if (mConfirmIntent == null) {
            mConfirmIntent = new Intent(ACTION_AUTH_UNLOCK);
            mConfirmIntent.setClassName(AUTH_PACKAGE, AUTH_ACTIVITY);
            mConfirmIntent.addFlags(Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS
                    | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        }
        return mConfirmIntent;
    }

    // --- IAppLockManager ---

    @Override
    public boolean isEnabled() {
        return mController != null && mController.isEnabled();
    }

    @Override
    public void setEnabled(boolean enabled) {
        enforceSettingsManager();
        if (mController == null) return;
        mController.setEnabled(enabled);
        if (!enabled) {
            lockAllSessionsAndNotify();
        }
    }

    @Override
    public int getLockBehavior() {
        return mLockBehavior;
    }

    @Override
    public void setLockBehavior(int behavior) {
        enforceSettingsManager();
        putSecureIntSetting(SETTING_LOCK_BEHAVIOR, behavior);
        mLockBehavior = behavior;
    }

    @Override
    public int getLockTimeout() {
        return mLockTimeout;
    }

    @Override
    public void setLockTimeout(int timeoutSeconds) {
        enforceSettingsManager();
        putSecureIntSetting(SETTING_LOCK_TIMEOUT, timeoutSeconds);
        mLockTimeout = timeoutSeconds;
    }

    @Override
    public int getAppLockState(String packageName) {
        return computeAppLockState(packageName).ordinal();
    }

    public boolean hasAppLock(String packageName) {
        return computeAppLockState(packageName).hasAppLock();
    }

    @Override
    public void addLockedApp(String packageName) {
        enforceSettingsManager();
        if (mController == null) return;
        mController.addLockedApp(packageName);
        notifyAppLockStateChanged(packageName, true);
    }

    @Override
    public void removeLockedApp(String packageName) {
        enforceSettingsManager();
        if (mController == null) return;
        mController.removeLockedApp(packageName);
        int uid = getPackageUid(packageName);
        if (uid >= 0) {
            markSessionLocked(packageName, UserHandle.getUserId(uid));
        }
        notifyAppLockStateChanged(packageName, false);
    }

    @Override
    public List<String> getLockedPackages() {
        return mController != null ? mController.getLockedPackages() : List.of();
    }

    @Override
    public List<String> getLockablePackages() {
        return mController != null ? mController.getLockablePackages() : List.of();
    }

    @Override
    public boolean isPackageLockable(String packageName) {
        return mController != null && mController.isPackageLockable(packageName);
    }

    @Override
    public void unlockApp(String packageName, int userId) {
        if (TextUtils.isEmpty(packageName)) return;
        markSessionUnlocked(packageName, userId);
        synchronized (mPendingUnlocks) {
            mPendingUnlocks.remove(sessionKey(userId, packageName));
        }
    }

    @Override
    public void promptUnlock(String packageName, int userId) {
        if (TextUtils.isEmpty(packageName) || mAtms == null) return;

        Intent intent = new Intent(getConfirmIntent());
        intent.putExtra(EXTRA_LOCKED_PACKAGE, packageName);
        intent.putExtra(EXTRA_LOCKED_UID, userId);
        intent.putExtra(EXTRA_APP_LABEL, resolveAppLabel(packageName, userId));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);

        long identity = Binder.clearCallingIdentity();
        try {
            mAtms.getActivityStartController()
                    .obtainStarter(intent, "AppLock.promptUnlock")
                    .setCallingUid(0)
                    .setActivityInfo(mAuthResolveInfo != null ? mAuthResolveInfo.activityInfo : null)
                    .execute();
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    @Override
    public void registerAppLockStateListener(IAppLockStateListener listener) {
        mAppLockStateListeners.register(listener);
    }

    @Override
    public void unregisterAppLockStateListener(IAppLockStateListener listener) {
        mAppLockStateListeners.unregister(listener);
    }

    @Override
    public void registerAppSessionListener(IAppSessionListener listener) {
        mAppSessionListeners.register(listener);
    }

    @Override
    public void unregisterAppSessionListener(IAppSessionListener listener) {
        mAppSessionListeners.unregister(listener);
    }

    // --- IAppLockService (WM hooks) ---

    @Override
    public boolean isAppLocked(ActivityRecord r) {
        if (r == null || !hasLockedPackages() || r.isNoDisplay()
                || r.isActivityTypeHomeOrRecents()) {
            return false;
        }

        int userId = r.mUserId;
        if (mAuthResolveInfo == null || mCurrentUserId != userId) {
            refreshAuthResolveInfo(userId);
            mSettingsObserver.onChange(true);
        }
        return isAppLocked(r.packageName, r.getUid(), r.mActivityComponent);
    }

    @Override
    public boolean isAppLocked(String packageName, int uid, ComponentName component) {
        if (mController == null || !mController.isEnabled()) return false;
        if (PROTECTED_PACKAGES.contains(packageName)) return false;
        if (!mController.isAppLocked(packageName)) return false;

        int userId = UserHandle.getUserId(uid);
        String key = sessionKey(userId, packageName);
        boolean sessionUnlocked = mUnlockedApps.contains(key);

        if (sessionUnlocked && mLockBehavior == LOCK_BEHAVIOR_TIMEOUT) {
            Long lastUsed = mUnlockTimestamps.get(key);
            if (lastUsed != null
                    && (SystemClock.elapsedRealtime() - lastUsed) > (mLockTimeout * 1000L)) {
                sessionUnlocked = false;
            }
        }

        return mKeyguardDone && !sessionUnlocked;
    }

    @Override
    public void lockTopApp(Task task, String reason) {
        if (task == null || !hasLockedPackages()) return;
        ActivityRecord r = task.topRunningActivityLocked();
        if (!isAppLocked(r)) return;
        if (mUnlockedApps.contains(sessionKey(r))) return;
        startAuthPrompt(r, reason);
    }

    @Override
    public boolean checkLockApp(ActivityRecord prev, ActivityRecord next) {
        if (next == null) return false;
        clearUnlockedApp(next);
        if (!isAppLocked(next)) return false;
        if (!startAuthPrompt(next, "AppLock.checkLockApp")) return false;
        if (prev != null && prev.finishing) {
            prev.setVisibility(false);
        }
        next.mRootWindowContainer.ensureActivitiesVisible();
        return true;
    }

    @Override
    public boolean checkUnlockApp(ActivityRecord r, int resultCode, Intent data) {
        if (r.requestCode != mRequestCode) return false;
        if (data == null) return true;
        try {
            int userId = UserHandle.getUserId(data.getIntExtra(EXTRA_LOCKED_UID, 0));
            String packageName = data.getStringExtra(EXTRA_LOCKED_PACKAGE);
            String pendingKey = sessionKey(userId, packageName);
            synchronized (mPendingUnlocks) {
                mPendingUnlocks.remove(pendingKey);
            }
            if (resultCode == Activity.RESULT_OK && packageName != null) {
                markSessionUnlocked(packageName, userId);
            } else if (r.resultTo != null) {
                r.resultTo.finishIfPossible("applock-canceled", false);
            }
            return true;
        } catch (Exception e) {
            Slog.w(TAG, "checkUnlockApp failed", e);
            return false;
        }
    }

    @Override
    public boolean isAuthActivity(ComponentName component) {
        return component != null
                && AUTH_PACKAGE.equals(component.getPackageName())
                && AUTH_ACTIVITY.equals(component.getClassName());
    }

    @Override
    public boolean isTopAppLocked(ActivityManager.RecentTaskInfo rti, int topUserId) {
        rti.isTopAppLocked = false;
        if (!mCheckRecentTasks || mController == null || !mController.isEnabled()) {
            return false;
        }
        ComponentName component = rti.baseIntent.getComponent();
        String packageName = component != null ? component.getPackageName() : "";
        long identity = Binder.clearCallingIdentity();
        try {
            int userId = UserHandle.getUserId(topUserId);
            if (isAuthActivity(component)) {
                rti.isTopAppLocked = true;
            } else if (mController.isAppLocked(packageName)) {
                String key = sessionKey(userId, packageName);
                rti.isTopAppLocked = !(mLockBehavior == LOCK_BEHAVIOR_ON_LEAVE
                        && mUnlockedApps.contains(key));
            }
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
        return rti.isTopAppLocked;
    }

    @Override
    public void getRecentTasksCheck(int callingUid, int userId) {
        mCheckRecentTasks = callingUid != Process.SYSTEM_UID
                && mAtms.mWindowManager.isKeyguardSecure(userId);
    }

    @Override
    public void setKeyguardDoneLocked(boolean done) {
        try {
            if (done) {
                mKeyguardDone = true;
                mAtms.mWindowManager.getDefaultDisplayContentLocked()
                        .getDefaultTaskDisplayArea().forAllTasks(this::addVisibleTaskToUnlocked);
            } else {
                mKeyguardDone = false;
                if (mLockBehavior == LOCK_BEHAVIOR_TIMEOUT && mLastFocusedAppKey != null) {
                    scheduleTimeoutLock(mLastFocusedAppKey);
                }
                if (mLockBehavior == LOCK_BEHAVIOR_ON_SCREEN_OFF) {
                    lockAllSessionsAndNotify();
                }
            }
        } catch (Exception e) {
            Slog.w(TAG, "setKeyguardDoneLocked failed", e);
            mKeyguardDone = done;
        }
    }

    @Override
    public void onAppFocusChanged(ActivityRecord newFocus, Task newTask) {
        if (!hasLockedPackages()) {
            mLastFocusedAppKey = null;
            return;
        }
        String newKey = newFocus != null ? sessionKey(newFocus) : null;
        if (mLastFocusedAppKey != null && !mLastFocusedAppKey.equals(newKey)) {
            scheduleTimeoutLock(mLastFocusedAppKey);
            if (mLockBehavior == LOCK_BEHAVIOR_ON_LEAVE
                    && mUnlockedApps.contains(mLastFocusedAppKey)) {
                relockFromSessionKey(mLastFocusedAppKey);
            }
        }
        if (newKey != null) {
            cancelTimeoutLock(newKey);
            mUnlockTimestamps.put(newKey, SystemClock.elapsedRealtime());
        }
        mLastFocusedAppKey = newKey;
        lockTopApp(newTask, "AppLock.onAppFocusChanged");
    }

    @Override
    public void onWindowingModeChanged(Task task, int prevWindowingMode) {
        if (task == null || mLockBehavior != LOCK_BEHAVIOR_ON_LEAVE) return;

        int currMode = task.getWindowingMode();
        if (!WindowConfiguration.isFloating(prevWindowingMode)
                && WindowConfiguration.isFloating(currMode) && task.isVisible()) {
            ActivityRecord r = task.topRunningActivityLocked();
            if (isAppLocked(r)) {
                markSessionUnlocked(r.packageName, r.mUserId);
            }
            return;
        }

        if (mUnlockedApps.isEmpty()) return;
        if ((!WindowConfiguration.inMultiWindowMode(prevWindowingMode)
                && !WindowConfiguration.isFloating(prevWindowingMode))
                || WindowConfiguration.inMultiWindowMode(currMode)
                || WindowConfiguration.isFloating(currMode)) {
            return;
        }

        ActivityRecord r = task.topRunningActivityLocked();
        if (task.isVisible()) {
            if (currMode == WindowConfiguration.WINDOWING_MODE_FULLSCREEN) {
                if (r != null) clearUnlockedApp(r);
                else clearUnlockedApp();
            }
        } else {
            if (r != null) markSessionLocked(r.packageName, r.mUserId);
            ActivityRecord lastPaused = task.mLastPausedActivity;
            if (lastPaused != null) {
                markSessionLocked(lastPaused.packageName, lastPaused.mUserId);
            }
            if (task.realActivity != null) {
                markSessionLocked(task.realActivity.getPackageName(), task.effectiveUid);
            }
        }
    }

    @Override
    public void clearUnlockedApp() {
        if (mLockBehavior != LOCK_BEHAVIOR_ON_LEAVE || mUnlockedApps.isEmpty()) return;
        lockAllSessionsAndNotify();
        lockVisibleMultiWindowApps(mAtms.mWindowManager.getDefaultDisplayContentLocked());
    }

    @Override
    public void clearUnlockedApp(ActivityRecord r) {
        if (r == null || mLockBehavior != LOCK_BEHAVIOR_ON_LEAVE) return;
        if (r.occludesParent() || r.isActivityTypeHomeOrRecents()) {
            if (r.isActivityTypeHomeOrRecents() && r.mTransitionController.isTransientLaunch(r)) {
                return;
            }
            boolean wasUnlocked = mUnlockedApps.contains(sessionKey(r));
            clearUnlockedApp();
            if (wasUnlocked) {
                markSessionUnlocked(r.packageName, r.mUserId);
            } else {
                markSessionLocked(r.packageName, r.mUserId);
            }
            if (WindowConfiguration.isFloating(r.getWindowingMode())) {
                lockVisibleFullscreenApps(mAtms.mWindowManager.getDefaultDisplayContentLocked());
            }
        }
    }

    @Override
    public void removeTask(Task task, String reason) {
        if (task == null || !"remove-task".equals(reason)
                || mLockBehavior != LOCK_BEHAVIOR_ON_LEAVE || mUnlockedApps.isEmpty()) {
            return;
        }
        if (!WindowConfiguration.inMultiWindowMode(task.getWindowingMode())
                && !WindowConfiguration.isFloating(task.getWindowingMode())) {
            return;
        }
        ActivityRecord r = task.topRunningActivityLocked();
        if (r != null) markSessionLocked(r.packageName, r.mUserId);
        if (task.mLastPausedActivity != null) {
            markSessionLocked(task.mLastPausedActivity.packageName, task.mLastPausedActivity.mUserId);
        }
        if (task.realActivity != null) {
            markSessionLocked(task.realActivity.getPackageName(), task.effectiveUid);
        }
    }

    @Override
    public void onAppDied(String packageName, int userId) {
        if (AUTH_PACKAGE.equals(packageName)) {
            synchronized (mPendingUnlocks) {
                mPendingUnlocks.clear();
            }
            return;
        }
        if (mLockBehavior == LOCK_BEHAVIOR_ON_KILL) {
            markSessionLocked(packageName, userId);
        }
    }

    // --- internals ---

    private AppLockState computeAppLockState(String packageName) {
        if (mController == null || !mController.isEnabled()) return NONE;
        if (PROTECTED_PACKAGES.contains(packageName) || !mController.isAppLocked(packageName)) {
            return NONE;
        }
        if (!mKeyguardDone) return LOCKED;

        int userId = UserHandle.getUserId(Binder.getCallingUid());
        String key = sessionKey(userId, packageName);
        boolean sessionUnlocked = mUnlockedApps.contains(key);
        if (sessionUnlocked && mLockBehavior == LOCK_BEHAVIOR_TIMEOUT) {
            Long lastUsed = mUnlockTimestamps.get(key);
            if (lastUsed != null
                    && (SystemClock.elapsedRealtime() - lastUsed) > (mLockTimeout * 1000L)) {
                sessionUnlocked = false;
            }
        }
        return sessionUnlocked ? UNLOCKED : LOCKED;
    }

    private boolean hasLockedPackages() {
        return mController != null && mController.isEnabled() && mController.hasLockedPackages();
    }

    private boolean startAuthPrompt(ActivityRecord target, String reason) {
        if (target == null || mAtms == null) return false;

        String pendingKey = sessionKey(target);
        if (mUnlockedApps.contains(pendingKey)) return true;

        synchronized (mPendingUnlocks) {
            if (!mPendingUnlocks.add(pendingKey)) return true;
        }

        try {
            Intent intent = new Intent(getConfirmIntent());
            intent.putExtra(EXTRA_LOCKED_UID, target.getUid());
            intent.putExtra(EXTRA_LOCKED_PACKAGE, target.packageName);
            intent.putExtra(EXTRA_LOCKED_COMPONENT,
                    target.intent.getComponent() != null
                            ? target.intent.getComponent().flattenToString() : "");
            intent.putExtra(EXTRA_APP_LABEL, resolveAppLabel(target.packageName, target.mUserId));

            WindowProcessController wpc = target.app;
            if (wpc == null) {
                mAtms.getActivityStartController()
                        .obtainStarter(intent, reason)
                        .setCallingUid(0)
                        .setResultTo(target.token)
                        .setRequestCode(mRequestCode)
                        .setActivityInfo(mAuthResolveInfo != null
                                ? mAuthResolveInfo.activityInfo : null)
                        .execute();
            } else {
                startActivityAsCaller(wpc.getThread(), target.packageName, intent,
                        "", target.token, target.resultWho, mRequestCode);
            }
            abortAnimation(target);
            return true;
        } catch (Exception e) {
            Slog.w(TAG, "startAuthPrompt failed for " + target.packageName, e);
            synchronized (mPendingUnlocks) {
                mPendingUnlocks.remove(pendingKey);
            }
            return false;
        }
    }

    private void refreshAuthResolveInfo(int userId) {
        List<ResolveInfo> list = mContext.getPackageManager()
                .queryIntentActivitiesAsUser(mConfirmIntent, PackageManager.MATCH_SYSTEM_ONLY, userId);
        for (int i = 0; list != null && i < list.size(); i++) {
            ResolveInfo ri = list.get(i);
            if ((ri.activityInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                mAuthResolveInfo = ri;
                int newUserId = UserHandle.getUserId(ri.activityInfo.applicationInfo.uid);
                if (mCurrentUserId != newUserId) {
                    mCurrentUserId = newUserId;
                }
                break;
            }
        }
    }

    private static String sessionKey(int userId, String packageName) {
        return userId + ":" + packageName;
    }

    private static String sessionKey(ActivityRecord r) {
        return sessionKey(r.mUserId, r.packageName);
    }

    private void relockFromSessionKey(String key) {
        int colon = key.indexOf(':');
        if (colon <= 0 || colon >= key.length() - 1) return;
        try {
            int userId = Integer.parseInt(key.substring(0, colon));
            String pkg = key.substring(colon + 1);
            markSessionLocked(pkg, userId);
        } catch (NumberFormatException ignored) {
        }
    }

    private void markSessionUnlocked(String packageName, int userId) {
        String key = sessionKey(userId, packageName);
        if (mUnlockedApps.add(key)) {
            mUnlockTimestamps.put(key, SystemClock.elapsedRealtime());
            notifyAppUnlocked(packageName, userId);
        }
    }

    private void markSessionLocked(String packageName, int userId) {
        String key = sessionKey(userId, packageName);
        if (mUnlockedApps.remove(key)) {
            mUnlockTimestamps.remove(key);
            cancelTimeoutLock(key);
            notifyAppLocked(packageName, userId);
        }
    }

    private void lockAllSessionsAndNotify() {
        if (mUnlockedApps.isEmpty()) return;
        String[] keys = mUnlockedApps.toArray(new String[0]);
        mUnlockedApps.clear();
        mUnlockTimestamps.clear();
        clearAllTimeouts();
        for (String key : keys) {
            relockFromSessionKey(key);
        }
    }

    private void scheduleTimeoutLock(String key) {
        if (mLockBehavior != LOCK_BEHAVIOR_TIMEOUT || !mUnlockedApps.contains(key)) return;
        cancelTimeoutLock(key);
        Runnable r = () -> {
            synchronized (mAtms.mGlobalLock) {
                ActivityRecord top = mAtms.mRootWindowContainer.getTopResumedActivity();
                String topKey = top != null ? sessionKey(top) : null;
                if (!key.equals(topKey)) {
                    relockFromSessionKey(key);
                }
                mTimeoutRunnables.remove(key);
            }
        };
        mTimeoutRunnables.put(key, r);
        mAtms.mH.postDelayed(r, mLockTimeout * 1000L);
    }

    private void cancelTimeoutLock(String key) {
        Runnable r = mTimeoutRunnables.remove(key);
        if (r != null) mAtms.mH.removeCallbacks(r);
    }

    private void clearAllTimeouts() {
        for (Runnable r : mTimeoutRunnables.values()) {
            mAtms.mH.removeCallbacks(r);
        }
        mTimeoutRunnables.clear();
    }

    private void notifyAppLockStateChanged(String packageName, boolean locked) {
        int count = mAppLockStateListeners.beginBroadcast();
        for (int i = 0; i < count; i++) {
            try {
                mAppLockStateListeners.getBroadcastItem(i).onAppLockStateChanged(packageName, locked);
            } catch (RemoteException e) {
                Slog.w(TAG, "app lock state listener failed", e);
            }
        }
        mAppLockStateListeners.finishBroadcast();
    }

    private void notifyAppUnlocked(String packageName, int userId) {
        int count = mAppSessionListeners.beginBroadcast();
        for (int i = 0; i < count; i++) {
            try {
                mAppSessionListeners.getBroadcastItem(i).onAppUnlocked(packageName, userId);
            } catch (RemoteException e) {
                Slog.w(TAG, "session listener (unlock) failed", e);
            }
        }
        mAppSessionListeners.finishBroadcast();
    }

    private void notifyAppLocked(String packageName, int userId) {
        int count = mAppSessionListeners.beginBroadcast();
        for (int i = 0; i < count; i++) {
            try {
                mAppSessionListeners.getBroadcastItem(i).onAppLocked(packageName, userId);
            } catch (RemoteException e) {
                Slog.w(TAG, "session listener (lock) failed", e);
            }
        }
        mAppSessionListeners.finishBroadcast();
    }

    private void addVisibleTaskToUnlocked(Task task) {
        if (task.isLeafTask() && task.isVisible()) {
            ActivityRecord r = task.topRunningActivityLocked();
            if (isAppLocked(r)) {
                lockTopApp(task, "AppLock.setKeyguardDone");
            }
        }
    }

    private void lockVisibleMultiWindowApps(DisplayContent dc) {
        if (dc == null) {
            dc = mAtms.mWindowManager.getDefaultDisplayContentLocked();
        }
        dc.getDefaultTaskDisplayArea().forAllTasks(task -> {
            if (task.isLeafTask()
                    && (WindowConfiguration.inMultiWindowMode(task.getWindowingMode())
                    || WindowConfiguration.isFloating(task.getWindowingMode()))
                    && task.isVisible()) {
                ActivityRecord r = task.topRunningActivityLocked();
                if (isAppLocked(r)) {
                    markSessionUnlocked(r.packageName, r.mUserId);
                }
            }
        });
    }

    private void lockVisibleFullscreenApps(DisplayContent dc) {
        if (dc == null) {
            dc = mAtms.mWindowManager.getDefaultDisplayContentLocked();
        }
        dc.getDefaultTaskDisplayArea().forAllTasks(task -> {
            if (task.isLeafTask()
                    && task.getWindowingMode() == WindowConfiguration.WINDOWING_MODE_FULLSCREEN
                    && task.isVisible()) {
                ActivityRecord r = task.topRunningActivityLocked();
                if (isAppLocked(r)) {
                    markSessionUnlocked(r.packageName, r.mUserId);
                }
            }
        });
    }

    private void abortAnimation(ActivityRecord r) {
        if (r == null) return;
        try {
            if (r.getOptions() != null && r.getOptions().getRemoteAnimationAdapter() != null) {
                r.getOptions().getRemoteAnimationAdapter().getRunner().onAnimationCancelled();
            }
        } catch (Exception e) {
            Slog.w(TAG, "abortAnimation failed", e);
        }
        r.abortAndClearOptionsAnimation();
    }

    private int startActivityAsCaller(IApplicationThread caller, String callingPackage,
            Intent intent, String resolvedType, IBinder resultTo, String resultWho,
            int requestCode) {
        return mAtms.getActivityStartController()
                .obtainStarter(intent, "AppLock.startActivityAsCaller")
                .setCaller(caller)
                .setCallingPackage(callingPackage)
                .setResolvedType(resolvedType)
                .setResultTo(resultTo)
                .setResultWho(resultWho)
                .setRequestCode(requestCode)
                .execute();
    }

    private String resolveAppLabel(String packageName, int userId) {
        try {
            PackageManager pm = mContext.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfoAsUser(packageName, 0, userId);
            CharSequence label = pm.getApplicationLabel(ai);
            return label != null ? label.toString() : packageName;
        } catch (Exception e) {
            return packageName;
        }
    }

    private int getPackageUid(String packageName) {
        try {
            return mContext.getPackageManager().getApplicationInfo(packageName, 0).uid;
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    private void enforceSettingsManager() {
        final int uid = Binder.getCallingUid();
        if (uid == Process.SYSTEM_UID || uid == Process.SHELL_UID) {
            return;
        }
        final String pkg = mContext.getPackageManager().getNameForUid(uid);
        if ("com.android.applock".equals(pkg)) {
            return;
        }
        throw new SecurityException("UID " + uid + " (" + pkg + ") cannot manage App Lock settings");
    }

    private void putSecureIntSetting(String key, int value) {
        final long token = Binder.clearCallingIdentity();
        try {
            Settings.Secure.putIntForUser(mContext.getContentResolver(), key, value,
                    UserHandle.USER_SYSTEM);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }
}
