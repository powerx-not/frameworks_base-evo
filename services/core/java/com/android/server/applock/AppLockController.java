/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.applock;

import android.app.AppLockManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.UserHandle;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Slog;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Persists locked-app list for system App Lock. */
public class AppLockController {
    private static final String TAG = "AppLockController";

    private static final String KEY_LOCKED_PKGS = "locked_pkgs";

    private final Context mContext;
    private final ContentResolver mContentResolver;
    private final LauncherApps mLauncherApps;
    private final Set<String> mBlacklistedPackages;
    private final Handler mHandler;

    private final Set<String> mLockedPackages = new HashSet<>();
    private boolean mEnabled;

    private ContentObserver mConfigObserver;
    private ContentObserver mEnabledObserver;

    public AppLockController(Context context, Set<String> blacklistedPackages) {
        mContext = context;
        mContentResolver = context.getContentResolver();
        mLauncherApps = context.getSystemService(LauncherApps.class);
        mBlacklistedPackages = blacklistedPackages;
        mHandler = new Handler(Looper.getMainLooper());
    }

    public void init() {
        registerSettingsObservers();
        loadFromSettings();
    }

    private void registerSettingsObservers() {
        mConfigObserver = new ContentObserver(mHandler) {
            @Override
            public void onChange(boolean selfChange) {
                loadLockedPackages();
            }
        };
        mContentResolver.registerContentObserver(
                Settings.Secure.getUriFor(AppLockManager.SETTING_CONFIG),
                false, mConfigObserver, UserHandle.USER_ALL);

        mEnabledObserver = new ContentObserver(mHandler) {
            @Override
            public void onChange(boolean selfChange) {
                loadEnabled();
            }
        };
        mContentResolver.registerContentObserver(
                Settings.Secure.getUriFor(AppLockManager.SETTING_ENABLED),
                false, mEnabledObserver, UserHandle.USER_ALL);
    }

    private void loadFromSettings() {
        loadEnabled();
        loadLockedPackages();
    }

    private void loadEnabled() {
        mEnabled = Settings.Secure.getIntForUser(mContentResolver, AppLockManager.SETTING_ENABLED,
                0, UserHandle.USER_SYSTEM) != 0;
        Slog.d(TAG, "App lock enabled=" + mEnabled);
    }

    private void loadLockedPackages() {
        String jsonStr = Settings.Secure.getString(mContentResolver, AppLockManager.SETTING_CONFIG);
        synchronized (this) {
            mLockedPackages.clear();
            if (!TextUtils.isEmpty(jsonStr)) {
                try {
                    JSONObject config = new JSONObject(jsonStr);
                    JSONArray arr = config.optJSONArray(KEY_LOCKED_PKGS);
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            String pkg = arr.optString(i);
                            if (!TextUtils.isEmpty(pkg) && !mBlacklistedPackages.contains(pkg)) {
                                mLockedPackages.add(pkg);
                            }
                        }
                    }
                } catch (JSONException e) {
                    Slog.e(TAG, "Failed to parse applock_config JSON", e);
                }
            }
        }
        Slog.i(TAG, "Loaded locked packages: " + mLockedPackages.size());
    }

    public boolean isEnabled() {
        return mEnabled;
    }

    public void setEnabled(boolean enabled) {
        Settings.Secure.putIntForUser(mContentResolver, AppLockManager.SETTING_ENABLED,
                enabled ? 1 : 0, UserHandle.USER_SYSTEM);
        mEnabled = enabled;
    }

    public boolean isAppLocked(String packageName) {
        if (!mEnabled || TextUtils.isEmpty(packageName)) return false;
        if (mBlacklistedPackages.contains(packageName)) return false;
        synchronized (this) {
            return mLockedPackages.contains(packageName);
        }
    }

    public boolean hasLockedPackages() {
        if (!mEnabled) return false;
        synchronized (this) {
            return !mLockedPackages.isEmpty();
        }
    }

    public void addLockedApp(String packageName) {
        if (TextUtils.isEmpty(packageName)) return;
        if (!isPackageLockable(packageName)) {
            Slog.w(TAG, "Cannot lock package - not lockable: " + packageName);
            return;
        }
        int uid = getPackageUid(packageName);
        synchronized (this) {
            if (mLockedPackages.add(packageName)) {
                saveConfigToSettings();
                if (uid >= 0) {
                    broadcastPackageChange(packageName, uid);
                }
            }
        }
    }

    public void removeLockedApp(String packageName) {
        if (TextUtils.isEmpty(packageName)) return;
        int uid = getPackageUid(packageName);
        synchronized (this) {
            if (mLockedPackages.remove(packageName)) {
                saveConfigToSettings();
                if (uid >= 0) {
                    broadcastPackageChange(packageName, uid);
                }
            }
        }
    }

    public List<String> getLockedPackages() {
        synchronized (this) {
            return new ArrayList<>(mLockedPackages);
        }
    }

    public boolean isPackageLockable(String packageName) {
        if (TextUtils.isEmpty(packageName)) return false;
        if (mBlacklistedPackages.contains(packageName)) return false;
        if (mLauncherApps == null) return false;
        try {
            List<LauncherActivityInfo> activities = mLauncherApps.getActivityList(
                    packageName, UserHandle.of(UserHandle.USER_SYSTEM));
            return activities != null && !activities.isEmpty();
        } catch (Exception e) {
            Slog.w(TAG, "Failed to check if package is lockable: " + packageName, e);
            return false;
        }
    }

    public List<String> getLockablePackages() {
        List<String> result = new ArrayList<>();
        if (mLauncherApps != null) {
            try {
                List<LauncherActivityInfo> activities = mLauncherApps.getActivityList(
                        null, UserHandle.of(UserHandle.USER_SYSTEM));
                Set<String> seen = new HashSet<>();
                for (LauncherActivityInfo info : activities) {
                    String pkgName = info.getApplicationInfo().packageName;
                    if (!mBlacklistedPackages.contains(pkgName) && !seen.contains(pkgName)) {
                        result.add(pkgName);
                        seen.add(pkgName);
                    }
                }
            } catch (Exception e) {
                Slog.e(TAG, "Failed to get lockable packages from LauncherApps", e);
            }
        }
        if (result.isEmpty()) {
            try {
                PackageManager pm = mContext.getPackageManager();
                List<ApplicationInfo> apps = pm.getInstalledApplications(0);
                for (ApplicationInfo appInfo : apps) {
                    if (mBlacklistedPackages.contains(appInfo.packageName)) continue;
                    if (isSystemUid(appInfo.uid)) continue;
                    if (pm.getLaunchIntentForPackage(appInfo.packageName) != null) {
                        result.add(appInfo.packageName);
                    }
                }
            } catch (Exception e) {
                Slog.e(TAG, "Failed to get lockable packages from PackageManager", e);
            }
        }
        return result;
    }

    public void cleanupPackage(String packageName) {
        synchronized (this) {
            if (mLockedPackages.remove(packageName)) {
                saveConfigToSettings();
            }
        }
    }

    private void saveConfigToSettings() {
        try {
            JSONObject config = new JSONObject();
            synchronized (this) {
                config.put(KEY_LOCKED_PKGS, new JSONArray(mLockedPackages));
            }
            Settings.Secure.putString(mContentResolver, AppLockManager.SETTING_CONFIG, config.toString());
        } catch (JSONException e) {
            Slog.e(TAG, "Failed to save applock_config JSON", e);
        }
    }

    private void broadcastPackageChange(String packageName, int uid) {
        try {
            Intent intent = new Intent(Intent.ACTION_PACKAGE_CHANGED);
            intent.setData(Uri.fromParts("package", packageName, null));
            intent.putExtra(Intent.EXTRA_UID, uid);
            intent.putExtra(Intent.EXTRA_USER_HANDLE, UserHandle.getUserId(uid));
            intent.putExtra(Intent.EXTRA_CHANGED_COMPONENT_NAME_LIST, new String[]{packageName});
            intent.putExtra(Intent.EXTRA_DONT_KILL_APP, true);
            mContext.sendBroadcastAsUser(intent, UserHandle.of(UserHandle.getUserId(uid)));
        } catch (Exception e) {
            Slog.w(TAG, "Failed to broadcast package change for " + packageName, e);
        }
    }

    private int getPackageUid(String packageName) {
        try {
            return mContext.getPackageManager().getApplicationInfo(packageName, 0).uid;
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    private static boolean isSystemUid(int uid) {
        int appId = UserHandle.getAppId(uid);
        return appId == android.os.Process.ROOT_UID || appId == android.os.Process.SYSTEM_UID;
    }
}
