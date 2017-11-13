lwip bug finder
====

Finds bugs with symbolic execution!


Requirements
----
* Python2
* angr 7
    * `sudo -H pip install angr`
* scapy
    * `sudo -H pip install scapy`
* graphviz
    * To generate state history graph. Used by `emoviz.py`.


Installation
----
### git clone
```bash
git clone  --recursive https://github.com/ertlnagoya/lwip-bug-finder.git
```

### build simhost with each versions of lwip (NOT WORKING)
`build-full-version-simhost.sh` builds simhosts to `./bin`.

I git added my `simhost-STABLE-1_3_0`.


Usage
----
### to find [bug #24596](http://savannah.nongnu.org/bugs/?24596)
(runtime: < 30 sec)

Running `lwip-solve.py` will generates attack packet and saves result to `result.py`.

Run `sudo ./simhost-STABLE-XXX -d` and run `sudo python result.py 0` to attack simhost. Version of lwip must be 1.x.


Tips
----
### about `./trace` directory
angr's state history is visualized in this directory (saved as {dot,png} file). Let's check!

### `./preprocess.py`
This is helper script. Running this script is required by `lwip-solve.py`. Don't worry, `lwip-solve.py` mentions how to run. Follow his instructions.

### `lwip-solve-test.py`
This is obsoleted prototype. (runtime: < 15 sec)

To run `lwip-solve-test.py`, you must execute following steps beforehand:

```bash
### this script is not checked. will work
prev_dir=`pwd`
cd lwip
git checkout STABLE-1_3_1
patch -p1 < ../patch/lwip-STABLE-1_3_1-test.patch
cd ../lwip-contrib
git checkout STABLE-1_3_1
cd ports/unix/proj/unixsim
make clean
make -j4
mv simhost $prev_dir/bin/simhost-STABLE-1_3_1-test
```
