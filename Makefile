
test: cryptoCPP.h test.cpp crypto_DES.cpp constants_DES.h
	g++ test.cpp crypto_DES.cpp -o test --std=c++11


clean:
	rm test

