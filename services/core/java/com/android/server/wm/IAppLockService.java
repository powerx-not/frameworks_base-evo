/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.wm;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Intent;

/**
 * Internal WM hooks for system App Lock.
 *
 * @hide
 */
public interface IAppLockService {

    IAppLockService DEFAULT = new IAppLockService() {};

    default void systemReadyInternal() {
    }

    default void setKeyguardDoneLocked(boolean done) {
    }

    default void onAppFocusChanged(ActivityRecord newFocus, Task newTask) {
    }

    default void onWindowingModeChanged(Task task, int prevWindowingMode) {
    }

    default boolean isAppLocked(String packageName, int uid, ComponentName componentName) {
        return false;
    }

    default boolean isAppLocked(ActivityRecord r) {
        return false;
    }

    default void lockTopApp(Task task, String reason) {
    }

    default boolean isAuthActivity(ComponentName componentName) {
        return false;
    }

    default boolean checkLockApp(ActivityRecord prev, ActivityRecord next) {
        return false;
    }

    default boolean checkUnlockApp(ActivityRecord r, int resultCode, Intent resultData) {
        return false;
    }

    default boolean isTopAppLocked(ActivityManager.RecentTaskInfo rti, int topUserId) {
        return false;
    }

    default void getRecentTasksCheck(int callingUid, int userId) {
    }

    default void clearUnlockedApp() {
    }

    default void clearUnlockedApp(ActivityRecord r) {
    }

    default void removeTask(Task task, String reason) {
    }

    default void onAppDied(String packageName, int userId) {
    }

    default boolean hasAppLock(String packageName) {
        return false;
    }
}
