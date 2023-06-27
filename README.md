Clone:
git clone https://github.com/taodd/cephtrace
git submodule update --init --recursive

Build:
1. cd cephtrace
2. make

Start to trace your osd op's life cycle latency:
./osdtrace -m avg -d 1
