package co.algorand.passkeyautofill.utils

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * The passkey activities trust every extra they are started with (credential id, request JSON,
 * calling app info, the biometric-result flag). Only the provider service's own PendingIntent may
 * start them, so they must not be exported; the service stays exported behind the system-only
 * bind permission.
 */
class ManifestExportPolicyTest {
    private val androidNs = "http://schemas.android.com/apk/res/android"

    /** `src/main/AndroidManifest.xml` of this module, whatever directory Gradle runs the tests from. */
    private fun moduleManifest(): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "src/main/AndroidManifest.xml")
            if (candidate.isFile && File(dir, "src/main/java/co/algorand/passkeyautofill").isDirectory) {
                return candidate
            }
            dir = dir.parentFile
        }
        throw AssertionError("Could not locate the module's AndroidManifest.xml from ${File("").absolutePath}")
    }

    private fun elements(tag: String): List<Element> {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val nodes = factory.newDocumentBuilder().parse(moduleManifest()).getElementsByTagName(tag)
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    @Test
    fun everyActivityIsExplicitlyNotExported() {
        val activities = elements("activity")
        assertTrue("Expected the passkey activities in the manifest", activities.size >= 2)
        val exported = activities
            .filter { it.getAttributeNS(androidNs, "exported") != "false" }
            .map { it.getAttributeNS(androidNs, "name") }
        assertEquals("Activities must declare android:exported=\"false\"", emptyList<String>(), exported)
    }

    @Test
    fun theProviderServiceIsGuardedByTheSystemBindPermission() {
        val service = elements("service").single()
        assertEquals(
            "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE",
            service.getAttributeNS(androidNs, "permission"),
        )
    }
}
