package si.ark0.wallet

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // Route popup requests to WebChromeClient.onCreateWindow, whose default denies them. Without this,
    // Android treats target="_blank" and window.open as navigations of the current web view instead.
    webView.settings.setSupportMultipleWindows(true)
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    // The interface is dark: light status and navigation bar icons on it.
    enableEdgeToEdge(
      statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
      navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
    )
    super.onCreate(savedInstanceState)
    // The web view does not draw under the system bars, a display cutout or the keyboard: the content view
    // is padded by them, and its background, the interface's own, shows behind the bars.
    val content = findViewById<View>(android.R.id.content)
    content.setBackgroundColor(Color.rgb(9, 12, 16))
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime()
      )
      view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }
  }
}
