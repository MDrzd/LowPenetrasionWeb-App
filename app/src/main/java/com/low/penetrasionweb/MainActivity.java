package com.low.penetrasionweb;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.Toast;

import com.low.penetrasionweb.databinding.ActivityMainBinding;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.buttonStart.setOnClickListener(v -> {
            String target = binding.editTextTarget.getText().toString().trim();

            if (target.isEmpty()) {
                Toast.makeText(this, "URL/IP tidak boleh kosong", Toast.LENGTH_SHORT).show();
                return;
            }

            if (!target.startsWith("http")) {
                target = "http://" + target;
            }

            String finalTarget = target;
            new Thread(() -> {
                StringBuilder result = new StringBuilder();

                // 1. Header Security Check
                if (binding.checkboxHeaders.isChecked()) {
                    result.append("== Cek Header Keamanan ==\n");
                    try {
                        URL url = new URL(finalTarget);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("GET");
                        conn.connect();

                        String[] headers = {
                                "X-Frame-Options", "X-XSS-Protection",
                                "Strict-Transport-Security", "Content-Security-Policy"
                        };
                        for (String header : headers) {
                            String val = conn.getHeaderField(header);
                            result.append(header).append(": ").append(val != null ? val : "TIDAK ADA").append("\n");
                        }
                    } catch (Exception e) {
                        result.append("Gagal cek header: ").append(e.getMessage()).append("\n");
                    }
                    result.append("\n");
                }

                // 2. Scan Port
                if (binding.checkboxPort.isChecked()) {
                    result.append("== Scan Port ==\n");
                    int[] ports = {21, 22, 23, 80, 443, 3306, 8080};
                    for (int port : ports) {
                        try (Socket socket = new Socket()) {
                            socket.connect(new InetSocketAddress(finalTarget.replace("http://", "").replace("https://", ""), port), 1000);
                            result.append("Port ").append(port).append(": TERBUKA\n");
                        } catch (Exception e) {
                            result.append("Port ").append(port).append(": tertutup\n");
                        }
                    }
                    result.append("\n");
                }

                // 3. User-Agent Googlebot (opsional)
                if (binding.checkboxUserAgent != null && binding.checkboxUserAgent.isChecked()) {
                    result.append("== Uji User-Agent Googlebot ==\n");
                    try {
                        URL url = new URL(finalTarget);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestProperty("User-Agent", "Googlebot/2.1 (+http://www.google.com/bot.html)");
                        conn.connect();
                        int code = conn.getResponseCode();
                        result.append("Respon Googlebot: HTTP ").append(code).append("\n");
                    } catch (Exception e) {
                        result.append("Gagal uji User-Agent: ").append(e.getMessage()).append("\n");
                    }
                    result.append("\n");
                }

                // 4. Dummy POST Login
                if (binding.checkboxPost != null && binding.checkboxPost.isChecked()) {
                    result.append("== Dummy POST Login ==\n");
                    try {
                        URL url = new URL(finalTarget + "/login");
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("POST");
                        conn.setDoOutput(true);
                        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                        String postData = "username=admin&password=admin123";

                        OutputStream os = conn.getOutputStream();
                        os.write(postData.getBytes());
                        os.flush();
                        os.close();

                        int code = conn.getResponseCode();
                        result.append("Respon login dummy: HTTP ").append(code).append("\n");
                    } catch (Exception e) {
                        result.append("Gagal POST login: ").append(e.getMessage()).append("\n");
                    }
                    result.append("\n");
                }

                // 5. Brute-force Direktori
                if (binding.checkboxFuzz.isChecked()) {
                    String[] paths = {"/admin", "/login", "/dashboard", "/panel", "/cpanel"};
                    result.append("== Brute-force Direktori ==\n");
                    for (String path : paths) {
                        try {
                            URL url = new URL(finalTarget + path);
                            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                            conn.setRequestMethod("GET");
                            conn.connect();
                            int code = conn.getResponseCode();
                            result.append(path).append(" → HTTP ").append(code).append("\n");
                        } catch (Exception e) {
                            result.append(path).append(" → Gagal\n");
                        }
                    }
                    result.append("\n");
                }

                // 6. Cek API Key
                if (binding.checkboxApiKey != null && binding.checkboxApiKey.isChecked()) {
                    result.append("== Cek API Key Tersembunyi ==\n");
                    try {
                        URL url = new URL(finalTarget);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setRequestMethod("GET");
                        conn.setConnectTimeout(3000);
                        conn.setReadTimeout(3000);

                        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        StringBuilder html = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            html.append(line).append("\n");
                        }
                        reader.close();

                        String[] patterns = {
                                "AIza[0-9A-Za-z\\-_]{35}",               // Google API key
                                "sk_live_[0-9a-zA-Z]{24}",               // Stripe key
                                "Bearer [a-zA-Z0-9\\-\\._~\\+\\/]+=*",   // Bearer token
                                "api[_-]?key[\"'=:\\s]+[a-zA-Z0-9]{16,}" // Generic api_key
                        };

                        boolean found = false;
                        for (String pattern : patterns) {
                            Pattern p = Pattern.compile(pattern);
                            Matcher m = p.matcher(html.toString());
                            while (m.find()) {
                                result.append("🔑 Ditemukan kemungkinan API Key: ").append(m.group()).append("\n");
                                found = true;
                            }
                        }

                        if (!found) {
                            result.append("Tidak ditemukan pola API key yang umum.\n");
                        }
                    } catch (Exception e) {
                        result.append("Gagal cek API key: ").append(e.getMessage()).append("\n");
                    }
                    result.append("\n");
                }
                
                if (binding.checkboxRobots != null && binding.checkboxRobots.isChecked()) {
    result.append("== Cek robots.txt ==\n");
    try {
        URL url = new URL(finalTarget + "/robots.txt");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.connect();
        int code = conn.getResponseCode();
        result.append("/robots.txt → HTTP ").append(code).append("\n");
        if (code == 200) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\n");
            }
            reader.close();
        }
    } catch (Exception e) {
        result.append("Gagal cek robots.txt: ").append(e.getMessage()).append("\n");
    }
    result.append("\n");
}

                // Tampilkan hasil ke UI
                String finalResult = result.toString();
                runOnUiThread(() -> binding.textViewResult.setText(finalResult));
            }).start();
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        this.binding = null;
    }
}