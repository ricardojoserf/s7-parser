# Work in progress! 

# s7-parser
S7 protocol (S7comm) extractor using Libpcap

## Compilation

```
gcc s7.c -o s7 -lpcap
```

## Usage

```
./s7 $input_file $output_file
```

Example:
```
./s7 s7_test/password.pcapng result_test.pcap
```

Result:

[[images/image1.jpg]]
