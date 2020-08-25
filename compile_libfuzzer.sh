
mkdir -p libfuzzer_bin/
clang -DLIBFUZZER -fPIC -g -fsanitize=address,fuzzer -O3 -shared src/cfg.c src/disassembler.c src/tnt_cache.c src/decoder.c src/libxdc.c src/mmh3.c src/trace_cache.c -o libfuzzer_bin/libxdc.so -l:libcapstone.so.4  

clang -DLIBFUZZER -fPIC -g -fsanitize=address,fuzzer -O3 test/tester.c test/page_cache.c test/helper.c -o libfuzzer_bin/tester -Itest/ -I./ -Llibfuzzer_bin/ -lxdc 

