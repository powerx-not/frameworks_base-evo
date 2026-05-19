/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.systemui.applock

import android.app.AppLockManager
import android.app.AppLockManager.AppLockState
import android.content.Context
import android.os.IBinder
import android.os.RemoteException
import android.os.ServiceManager
import android.os.SystemClock
import android.util.Log
import com.android.internal.app.IAppLockManager
import com.android.internal.app.IAppLockStateListener
import com.android.internal.app.IAppSessionListener
import com.android.systemui.CoreStartable
import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.dagger.qualifiers.Main
import com.android.systemui.shade.QuickSettingsControllerImpl
import com.android.systemui.shade.ShadeController
import com.android.systemui.statusbar.policy.KeyguardStateController
import dagger.Lazy
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject

/** SystemUI client for {@link Context#APP_LOCK_SERVICE} (Evolution App Lock). */
@SysUISingleton
class AppLockHelper @Inject constructor(
    private val qsController: Lazy<QuickSettingsControllerImpl>,
    private val shadeController: Lazy<ShadeController>,
    private val keyguardStateController: KeyguardStateController,
    @Main private val mainExecutor: Executor,
) : CoreStartable {

    companion object {
        private const val TAG = "AppLockHelper"
        private const val PENDING_EXPIRY_MS = 15_000L
        private fun sessionKey(userId: Int, pkg: String): String = "$userId:$pkg"
    }

    private val serviceRef = AtomicReference<IAppLockManager?>()
    @Volatile private var listenersRegistered = false
    private val hasLockCache = ConcurrentHashMap<String, Boolean>()
    private val sessionAuthCache = ConcurrentHashMap<String, Boolean>()
    private val refreshListeners = CopyOnWriteArrayList<Runnable>()
    private val notifUnlocks =
        Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
    private val pendingNotifOnly = ConcurrentHashMap<String, Long>()

    private val keyguardCallback = object : KeyguardStateController.Callback {
        override fun onKeyguardShowingChanged() {
            if (keyguardStateController.isShowing) {
                notifUnlocks.clear()
                pendingNotifOnly.clear()
                sessionAuthCache.clear()
                mainExecutor.execute { refreshState() }
            }
        }
    }

    private val lockStateListener = object : IAppLockStateListener.Stub() {
        override fun onAppLockStateChanged(packageName: String, locked: Boolean) {
            if (packageName.isBlank()) return
            hasLockCache[packageName] = locked
            clearSessionCacheFor(packageName)
            if (!locked) {
                notifUnlocks.removeAll { it.endsWith(":$packageName") }
                pendingNotifOnly.keys.removeAll { it.endsWith(":$packageName") }
            }
            mainExecutor.execute {
                qsController.get().onAppLockerUpdated(packageName)
                refreshState()
            }
        }
    }

    private val sessionListener = object : IAppSessionListener.Stub() {
        override fun onAppUnlocked(packageName: String, userId: Int) {
            if (packageName.isBlank()) return
            val key = sessionKey(userId, packageName)
            sessionAuthCache[key] = false
            val pendingTs = pendingNotifOnly.remove(key)
            val now = SystemClock.elapsedRealtime()
            val notifOnly = pendingTs != null && (now - pendingTs) < PENDING_EXPIRY_MS
            if (notifOnly) notifUnlocks.add(key)
            mainExecutor.execute {
                if (notifOnly) {
                    shadeController.get().animateExpandShade()
                }
                qsController.get().onAppLockerUpdated(packageName)
                refreshState()
            }
        }

        override fun onAppLocked(packageName: String, userId: Int) {
            if (packageName.isBlank()) return
            sessionKey(userId, packageName).let { k ->
                if (notifUnlocks.contains(k)) return@let
                sessionAuthCache[k]?.let { if (!it) return@onAppLocked }
                sessionAuthCache[k] = true
            }
            mainExecutor.execute {
                qsController.get().onAppLockerUpdated(packageName)
                refreshState()
            }
        }
    }

    private val deathRecipient = IBinder.DeathRecipient {
        serviceRef.set(null)
        listenersRegistered = false
        hasLockCache.clear()
        sessionAuthCache.clear()
        notifUnlocks.clear()
        pendingNotifOnly.clear()
    }

    fun addRefreshListener(l: Runnable) {
        refreshListeners.addIfAbsent(l)
    }

    fun removeRefreshListener(l: Runnable) {
        refreshListeners.remove(l)
    }

    private fun refreshState() {
        refreshListeners.forEach { it.run() }
    }

    private fun getService(): IAppLockManager? {
        var manager = serviceRef.get()
        if (manager == null) {
            val binder = ServiceManager.getService(Context.APP_LOCK_SERVICE) ?: return null
            try {
                binder.linkToDeath(deathRecipient, 0)
                manager = IAppLockManager.Stub.asInterface(binder)
                serviceRef.set(manager)
                registerListeners(manager)
            } catch (e: RemoteException) {
                Log.w(TAG, "Failed to link/register", e)
            }
        }
        return manager
    }

    private fun registerListeners(manager: IAppLockManager) {
        if (listenersRegistered) return
        try {
            manager.registerAppLockStateListener(lockStateListener)
            manager.registerAppSessionListener(sessionListener)
            listenersRegistered = true
        } catch (e: RemoteException) {
            Log.w(TAG, "Failed to register listeners", e)
        }
    }

    private fun clearSessionCacheFor(packageName: String) {
        sessionAuthCache.keys.removeAll { it.endsWith(":$packageName") }
    }

    override fun start() {
        keyguardStateController.addCallback(keyguardCallback)
        getService()
    }

    fun getState(packageName: String): AppLockState {
        if (packageName.isBlank()) return AppLockState.NONE
        val manager = getService() ?: return AppLockState.NONE
        return try {
            AppLockState.fromOrdinal(manager.getAppLockState(packageName))
        } catch (e: RemoteException) {
            Log.w(TAG, "getState failed", e)
            AppLockState.NONE
        }
    }

    fun hasAppLock(packageName: String): Boolean {
        if (packageName.isBlank()) return false
        hasLockCache[packageName]?.let { return it }
        val hasLock = getState(packageName).hasAppLock()
        hasLockCache[packageName] = hasLock
        return hasLock
    }

    fun needsAuth(packageName: String, userId: Int): Boolean {
        if (packageName.isBlank()) return false
        if (!hasAppLock(packageName)) return false
        val key = sessionKey(userId, packageName)
        if (notifUnlocks.contains(key)) return false
        sessionAuthCache[key]?.let { return it }
        val authoritative = getState(packageName).needsAuth()
        sessionAuthCache[key] = authoritative
        return authoritative
    }

    fun promptUnlock(packageName: String, userId: Int) {
        pendingNotifOnly[sessionKey(userId, packageName)] = SystemClock.elapsedRealtime()
        shadeController.get().collapseShade()
        val manager = getService() ?: return
        try {
            manager.promptUnlock(packageName, userId)
        } catch (e: RemoteException) {
            Log.e(TAG, "promptUnlock failed", e)
        }
    }
}
