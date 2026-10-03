package co.algorand.passkeyautofill.utils

import android.content.Context
import co.algorand.passkeyautofill.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Supplies the FIDO/GPM privileged-browser allowlist (Google's
 * `gpm-passkeys-privileged-apps` list) to
 * [co.algorand.passkeyautofill.credentials.CredentialRepository.getPrivilegedOrigin].
 *
 * The allowlist is the set of callers this provider is willing to treat as real
 * browsers: only for a caller on this list will a request-supplied web origin
 * and `clientDataHash` be trusted. Every other caller is bound to its own
 * `android:apk-key-hash:` origin.
 *
 * ### Sourcing strategy
 * The list is not static: Google adds/removes browsers over time (and an app
 * that turns malicious can be rotated *out* of it). Bundling only a snapshot
 * means such changes never reach an installed provider until it ships again, so
 * this loader keeps a current copy at runtime while degrading safely:
 *
 *  1. a fresh cached download (younger than [TTL_MS]);
 *  2. the last good download, even if stale;
 *  3. the bundled `res/raw` snapshot as the guaranteed offline floor.
 *
 * [json] is on the latency-sensitive credential path, so it NEVER touches the
 * network; it only reads cache/disk/bundle. [refreshIfStale] performs the
 * actual download on a background scope and is meant to be called from the
 * credential-provider callbacks; it validates the payload before replacing the
 * cache and leaves the previous copy untouched on any failure.
 *
 * Staleness cuts both ways. A browser *added* after our copy was fetched just
 * falls back to app-binding (safe). But a browser *removed* from Google's list
 * (e.g. rotated out because it turned malicious) keeps being trusted until the
 * cache refreshes, so [TTL_MS] is the revocation window and is kept short. A
 * missing/unreadable list makes every caller non-privileged (safe default).
 */
object PrivilegedBrowserAllowlist {
    private const val TAG = "PrivilegedAllowlist"

    /**
     * Google's published GPM privileged-apps allowlist. This is the same file
     * bundled as `res/raw/gpm_privileged_browser_allowlist.json`, kept current
     * here. `CallingAppInfo.getOrigin` consumes the raw JSON string, so a fresh
     * download can be handed to it as-is.
     */
    private const val REMOTE_URL = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"

    /** Filename of the cached download inside the app's private `filesDir`. */
    private const val CACHE_FILE_NAME = "gpm_privileged_browser_allowlist.json"

    /**
     * How long a downloaded copy is considered fresh (24 hours). This bounds how
     * long a browser Google has removed from the list can still be trusted; the
     * payload is ~30 KB, so refreshing daily is cheap.
     */
    private const val TTL_MS = 24L * 60 * 60 * 1000

    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 10_000

    /** Guards against a runaway download producing an oversized in-memory string. */
    private const val MAX_DOWNLOAD_BYTES = 1L * 1024 * 1024 // 1 MiB

    /**
     * Process-lifetime scope for refreshes. Deliberately not tied to the
     * short-lived provider service, whose scope is cancelled in `onDestroy` and
     * would otherwise abort a download mid-flight.
     */
    private val refreshScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var memoryCache: String? = null

    @Volatile
    private var refreshInProgress = false

    /**
     * The allowlist JSON to hand to `CallingAppInfo.getOrigin`, chosen in
     * priority order: an already-resolved in-memory copy → a valid cached
     * download → the bundled raw snapshot. Returns `null` only if every source
     * fails, which makes every caller non-privileged (the safe, app-bound
     * default).
     *
     * This never performs network I/O and is safe to call on the credential
     * path.
     */
    fun json(context: Context): String? {
        memoryCache?.let { return it }
        return synchronized(this) {
            memoryCache ?: run {
                val resolved = readCacheFile(context) ?: readBundled(context)
                memoryCache = resolved
                resolved
            }
        }
    }

    /**
     * Kicks off a background refresh when the cached download is missing or older
     * than [TTL_MS]. Returns immediately and never blocks the credential flow;
     * the download runs on a process-lifetime background scope. The result
     * replaces the cache (and the in-memory copy) only if it
     * validates, so a truncated/garbage response can never clobber a good copy
     * (which would otherwise silently make every browser non-privileged).
     *
     * Intended to be called opportunistically from the credential-provider
     * callbacks so the list stays current without a dedicated update job.
     */
    fun refreshIfStale(context: Context) {
        if (!isCacheStale(context)) return
        synchronized(this) {
            if (refreshInProgress) return
            refreshInProgress = true
        }
        val appContext = context.applicationContext
        refreshScope.launch {
            try {
                val downloaded = download()
                if (downloaded == null || !isValidAllowlist(downloaded)) {
                    PasskeyLog.w(TAG, "Downloaded privileged allowlist missing or invalid; keeping previous copy")
                    return@launch
                }
                writeCacheFile(appContext, downloaded)
                memoryCache = downloaded
                PasskeyLog.d(TAG, "Refreshed privileged browser allowlist from remote source")
            } catch (e: Exception) {
                PasskeyLog.w(TAG, "Failed to refresh privileged browser allowlist; keeping previous copy", e)
            } finally {
                synchronized(this@PrivilegedBrowserAllowlist) { refreshInProgress = false }
            }
        }
    }

    private fun cacheFile(context: Context) = File(context.filesDir, CACHE_FILE_NAME)

    private fun isCacheStale(context: Context): Boolean {
        val f = cacheFile(context)
        if (!f.exists() || f.length() == 0L) return true
        return (System.currentTimeMillis() - f.lastModified()) > TTL_MS
    }

    private fun readCacheFile(context: Context): String? {
        return try {
            val f = cacheFile(context)
            if (!f.exists() || f.length() == 0L) return null
            val text = f.readText()
            if (isValidAllowlist(text)) {
                text
            } else {
                PasskeyLog.w(TAG, "Cached privileged allowlist is invalid; falling back to bundled copy")
                null
            }
        } catch (e: Exception) {
            PasskeyLog.w(TAG, "Failed to read cached privileged allowlist; falling back to bundled copy", e)
            null
        }
    }

    private fun writeCacheFile(context: Context, text: String) {
        val dst = cacheFile(context)
        val tmp = File(context.filesDir, "$CACHE_FILE_NAME.tmp")
        try {
            tmp.writeText(text)
            if (!tmp.renameTo(dst)) {
                // Atomic rename failed (e.g. dst exists on some FS): overwrite.
                dst.writeText(text)
            }
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private fun readBundled(context: Context): String? {
        return try {
            context.resources
                .openRawResource(R.raw.gpm_privileged_browser_allowlist)
                .bufferedReader()
                .use { it.readText() }
        } catch (e: Exception) {
            PasskeyLog.w(TAG, "Failed to load bundled privileged browser allowlist; all callers will be treated as non-privileged", e)
            null
        }
    }

    private fun download(): String? {
        val conn = (URL(REMOTE_URL).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
        }
        return try {
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                PasskeyLog.w(TAG, "Privileged allowlist download returned HTTP $code")
                return null
            }
            val bytes = conn.inputStream.buffered().use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_DOWNLOAD_BYTES) {
                        PasskeyLog.w(TAG, "Privileged allowlist download exceeded size limit; discarding")
                        return null
                    }
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
            String(bytes, Charsets.UTF_8)
        } finally {
            conn.disconnect()
        }
    }

    /** A well-formed allowlist parses as JSON with a non-empty `apps` array. */
    private fun isValidAllowlist(text: String): Boolean {
        return try {
            val apps = JSONObject(text).optJSONArray("apps")
            apps != null && apps.length() > 0
        } catch (e: Exception) {
            false
        }
    }
}
