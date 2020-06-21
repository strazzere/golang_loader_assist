# golang_loader_assist.py
This is the `golang_loader_assist.py` code to accompany the blog I wrote, [Reversing GO binaries like a pro (in IDA Pro)](http://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/). There is also the `hello-go` directory which contains the simple hello world code I used as an example.

## Important notes
If you're using IDA Pro 7.3 or below, you likely will need to take a look at the older release tagged [IDA-7.3-and-Below](https://github.com/strazzere/golang_loader_assist/releases/tag/IDA-7.3-and-Below). This is due to changes in the IDA Python libraries which where introduced in 7.4 which do not look to be backwards compatible.

## TODO
- [X] Support IDA Pro 7.5 w/ Python3 (tested with a go1.13.6 and go1.14.4 binary on IDA 7.5.200519 Linux x86_64)
- [X] Support IDA Pro 7.4
- [X] Retain IDA Pro 7.3 support via old release taggin
- [X] Convert all code to Python3 syntax
- [ ] Get all code style into the same format
- [ ] Clean up imports due to IDA Python changes
