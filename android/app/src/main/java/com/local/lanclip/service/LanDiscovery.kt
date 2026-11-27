package com.local.lanclip.service

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import com.local.lanclip.core.DiscoveredDevice
import com.local.lanclip.core.LanClipCrypto
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

class LanDiscovery(private val context: Context) {
    private val nsdManager: NsdManager by lazy {
        context.getSystemService(Context.NSD_SERVICE) as NsdManager
    }
    private val resolveExecutor = Executors.newSingleThreadExecutor()

    private var regListener: NsdManager.RegistrationListener? = null
    private var discListener: NsdManager.DiscoveryListener? = null
    private var registeredKey: String = ""
    private val discovered = ConcurrentHashMap<String, DiscoveredDevice>()

    var onDevicesChanged: ((List<DiscoveredDevice>) -> Unit)? = null

    @Synchronized
    fun updateAdvertise(active: Boolean, port: Int, pairing: Boolean, deviceID: String, displayName: String) {
        val nextKey = if (active && port > 0) "$port|$pairing|$deviceID|$displayName" else ""
        if (nextKey == registeredKey) return

        regListener?.let {
            try { nsdManager.unregisterService(it) } catch (_: Exception) {}
        }
        regListener = null
        registeredKey = ""

        if (nextKey.isEmpty()) return

        val info = NsdServiceInfo().apply {
            serviceName = "$displayName-${deviceID.take(4)}"
            serviceType = LanClipCrypto.SERVICE_TYPE
            setPort(port)
            setAttribute("id", deviceID)
            setAttribute("name", displayName)
            setAttribute("pairing", if (pairing) "1" else "0")
            setAttribute("port", port.toString())
        }

        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {}
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {}
            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
        }
        regListener = listener
        registeredKey = nextKey
        try {
            nsdManager.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (_: Exception) {
            regListener = null
            registeredKey = ""
        }
    }

    @Synchronized
    fun startDiscovery() {
        stopDiscovery()
        discovered.clear()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (!serviceInfo.serviceType.contains("_lanclip")) return
                resolveExecutor.submit {
                    try {
                        @Suppress("DEPRECATION")
                        nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(si: NsdServiceInfo, errorCode: Int) {}
                            override fun onServiceResolved(si: NsdServiceInfo) {
                                val attrs = si.attributes
                                val id = attrs["id"]?.toString(Charsets.UTF_8) ?: return
                                val name = attrs["name"]?.toString(Charsets.UTF_8)?.ifBlank { si.serviceName } ?: si.serviceName
                                val pairing = attrs["pairing"]?.toString(Charsets.UTF_8) == "1"
                                val port = attrs["port"]?.toString(Charsets.UTF_8)?.toIntOrNull() ?: si.port
                                val host = si.host?.hostAddress ?: return
                                if (!LanClipCrypto.isAllowedAddress(si.host)) return
                                discovered[id] = DiscoveredDevice(id, name, pairing, host, port)
                                notifyChanged()
                            }
                        })
                    } catch (_: Exception) {}
                }
            }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                val lostName = serviceInfo.serviceName ?: return
                discovered.entries.removeIf { it.value.displayName == lostName }
                notifyChanged()
            }
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
        }
        discListener = listener
        try {
            nsdManager.discoverServices(LanClipCrypto.SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (_: Exception) {
            discListener = null
        }
    }

    @Synchronized
    fun stopDiscovery() {
        discListener?.let {
            try { nsdManager.stopServiceDiscovery(it) } catch (_: Exception) {}
        }
        discListener = null
    }

    fun snapshot(): List<DiscoveredDevice> {
        return discovered.values.sortedWith(
            compareByDescending<DiscoveredDevice> { it.isPairing }.thenBy { it.displayName }
        )
    }

    private fun notifyChanged() {
        onDevicesChanged?.invoke(snapshot())
    }
}
