
test: cryptoCPP.h test.cpp crypto_DES.cpp constants_DES.h
	g++ test.cpp crypto_DES.cpp -o test --std=c++11
	g++ enc.cpp crypto_DES.cpp -o enc_command_line --std=c++11
	g++ dec.cpp crypto_DES.cpp -o dec_command_line --std=c++11
    
clean:
	rm test enc_command_line dec_command_line

