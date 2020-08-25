ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=./libfuzzer_bin/ gdb --args  ./libfuzzer_bin/tester
