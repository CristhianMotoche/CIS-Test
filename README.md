# CIS Benchmark CentOS Linux v2.1.0

Scripts:
- *cis-audit.sh* - to compare the benchmarks from the CIS Benchmark
- *cis-remeditaion.sh* - to run the recomendations from the CIS Benchmark

Run:
- Clone: git clone https://github.com/CristhianMotoche/CIS-Test
- cd CIS-Test/
- Execute the following commands from the CIS-Test/ directory

```
./cis-audit.sh 2>/dev/null | grep "OK"  | wc | awk '{print "Tiene "$1 " visto(s) bueno(s)"}'
./cis-audit.sh 2>/dev/null | wc | awk '{print "De "$1 " revisiones"}'
```
