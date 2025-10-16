package com.example.myapplication

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import android.annotation.SuppressLint
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.platform.LocalContext
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebChromeClient
import android.webkit.ConsoleMessage
import android.webkit.WebSettings
import android.webkit.GeolocationPermissions
import android.webkit.PermissionRequest
import android.view.ViewGroup
import android.util.Log
import android.os.Message
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions
import android.Manifest
import android.content.pm.PackageManager
import androidx.compose.runtime.DisposableEffect
import com.example.myapplication.ui.theme.MyApplicationTheme
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

class MainActivity : ComponentActivity() {
    private lateinit var permissionLauncher: ActivityResultLauncher<Array<String>>
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Immersive fullscreen: hide status/navigation bars
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val controller = WindowInsetsControllerCompat(window, window.decorView)
        controller.hide(WindowInsetsCompat.Type.statusBars() or WindowInsetsCompat.Type.navigationBars())
        controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        // Register runtime permission launcher before starting composition
        permissionLauncher = registerForActivityResult(RequestMultiplePermissions()) { _ -> }

        setContent {
            MyApplicationTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    WebPortalScreen(
                        url = "http://192.168.1.238:3000",
                        modifier = Modifier.padding(innerPadding),
                        permissionLauncher = permissionLauncher
                    )
                }
            }
        }
    }
}

@Composable
@SuppressLint("SetJavaScriptEnabled")
fun WebPortalScreen(
    url: String,
    modifier: Modifier = Modifier,
    permissionLauncher: ActivityResultLauncher<Array<String>>
) {
    var canGoBack by remember { mutableStateOf(false) }
    var webViewRef by remember { mutableStateOf<WebView?>(null) }
    // launcher is provided by Activity and registered before composition
    var isLoading by remember { mutableStateOf(true) }
    var hasError by remember { mutableStateOf(false) }

    Box(modifier = modifier.fillMaxSize().background(Color(0xFF0B1020))) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                WebView(context).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.setSupportMultipleWindows(true)
                settings.javaScriptCanOpenWindowsAutomatically = true
                settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
                settings.loadWithOverviewMode = true
                settings.useWideViewPort = true
                settings.mediaPlaybackRequiresUserGesture = false
                settings.databaseEnabled = true
                settings.setGeolocationEnabled(true)
                
                // Additional settings for better WebSocket and network support
                settings.cacheMode = WebSettings.LOAD_DEFAULT
                settings.allowFileAccess = true
                settings.allowContentAccess = true
                settings.allowFileAccessFromFileURLs = true
                settings.allowUniversalAccessFromFileURLs = true

                // Allow cookies for authentication/session if needed
                android.webkit.CookieManager.getInstance().setAcceptCookie(true)
                android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)

                // Add JavaScript interface for debugging
                addJavascriptInterface(object {
                    @android.webkit.JavascriptInterface
                    fun log(message: String) {
                        Log.d("WebApp", message)
                    }
                    
                    @android.webkit.JavascriptInterface
                    fun onWebSocketError(error: String) {
                        Log.e("WebApp", "WebSocket Error: $error")
                    }
                    
                    @android.webkit.JavascriptInterface
                    fun onGameStateChange(state: String) {
                        Log.d("WebApp", "Game State: $state")
                    }
                }, "AndroidApp")

                webChromeClient = object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
                        Log.d("WebViewConsole", "${'$'}{consoleMessage.message()} [${'$'}{consoleMessage.sourceId()}:${'$'}{consoleMessage.lineNumber()}]")
                        return super.onConsoleMessage(consoleMessage)
                    }

                    override fun onCreateWindow(view: WebView?, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message?): Boolean {
                        val transport = resultMsg?.obj as? WebView.WebViewTransport ?: return false
                        // Open new window requests in the same WebView
                        transport.webView = view
                        resultMsg.sendToTarget()
                        return true
                    }

                    override fun onPermissionRequest(request: PermissionRequest) {
                        // Grant camera/mic if runtime permissions granted
                        val resources = request.resources
                        request.grant(resources)
                    }

                    override fun onGeolocationPermissionsShowPrompt(origin: String?, callback: GeolocationPermissions.Callback?) {
                        callback?.invoke(origin, true, false)
                    }
                }

                webViewClient = object : WebViewClient() {
                    override fun onPageFinished(view: WebView?, url: String?) {
                        canGoBack = view?.canGoBack() == true
                        isLoading = false
                        hasError = false
                        Log.d("WebView", "Page finished loading: $url")
                    }

                    override fun shouldOverrideUrlLoading(view: WebView?, request: android.webkit.WebResourceRequest?): Boolean {
                        val targetUrl = request?.url?.toString() ?: return false
                        Log.d("WebView", "Loading URL: $targetUrl")
                        view?.loadUrl(targetUrl)
                        return true
                    }

                    override fun onReceivedError(view: WebView?, request: android.webkit.WebResourceRequest?, error: android.webkit.WebResourceError?) {
                        hasError = true
                        isLoading = false
                        Log.e("WebView", "Error loading page: ${error?.description}")
                    }

                    override fun onReceivedHttpError(view: WebView?, request: android.webkit.WebResourceRequest?, errorResponse: android.webkit.WebResourceResponse?) {
                        Log.e("WebView", "HTTP Error: ${errorResponse?.statusCode} - ${errorResponse?.reasonPhrase}")
                    }
                }
                webViewRef = this
                loadUrl(url)
            }
        },
        update = { webView ->
            if (webView.url != url) webView.loadUrl(url)
            canGoBack = webView.canGoBack()
            webViewRef = webView
        }
        )

        if (isLoading) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(color = Color(0xFF6AD3FF))
            }
        }

        if (hasError) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color(0xAA0B1020)),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Connection problem", color = Color.White)
                Button(onClick = {
                    isLoading = true
                    hasError = false
                    webViewRef?.reload()
                }) {
                    Text("Retry")
                }
            }
        }
    }

    BackHandler(enabled = canGoBack) {
        webViewRef?.goBack()
    }

    // Request runtime permissions on first composition
    LaunchedEffect(Unit) {
        val toRequest = mutableListOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS
        )
        // Android 13+ notifications
        try {
            val post = Manifest.permission::class.java.getField("POST_NOTIFICATIONS").get(null) as? String
            if (post != null) toRequest += post
        } catch (_: Throwable) {}
        permissionLauncher.launch(toRequest.toTypedArray())
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    MyApplicationTheme {
        Text("Web preview placeholder")
    }
}