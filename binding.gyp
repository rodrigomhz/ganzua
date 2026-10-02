{
  "targets": [
    {
      "target_name": "zipcrypto_attack",
      "sources": ["native/zipcrypto_attack.cc"],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
      "cflags_cc": ["-O3", "-std=c++17"],
      "cflags_cc!": ["-fno-exceptions"],
      "defines": ["NAPI_CPP_EXCEPTIONS"],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "OTHER_CFLAGS": ["-O3", "-std=c++17"]
      },
      "msvs_settings": {
        "VCCLCompilerTool": {"ExceptionHandling": 1}
      }
    }
  ]
}
