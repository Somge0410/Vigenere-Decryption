#include <iostream>
#include "Test_strings.h"
#include <algorithm>
#include <vector>
#include "Alphabeth.h"
#include "vigenere_analyzer.h"



int main() {

	std::string ciphertext = test_string1;
	if (ciphertext.size() == 0) {
		std::cout << "Empty ciphertext. Try again another ciphertext." << std::endl;
			return 0;
	}
	// Set the language of the plaintext. This matters because different languages
	//have different letter frequencies.
	std::string language = "English";
	std::cout << language << " expected as plaintext language" << std::endl;
	//Delete all spaces and punctuation from the ciphertext
	std::string altered_cipher = transform_ciphertext(ciphertext);
	// Start Kasiski examination. Find repeated substrings and their distances and
	// all the divisors of all the distances. The most frequent divisor is the most likely
	//Key length
	std::vector<std::pair<int, int>> divisor_frequency = get_divisor_frequency(altered_cipher);
	// Now we try the 5 most likely key lengths
	// The most frequent divisor is not always the correct key length so we try several	
	// to find the best decryption
	for(int i =0; i < std::min(5, static_cast<int>(divisor_frequency.size())); ++i) {
		int likely_key_length = divisor_frequency[i].first;
		std::cout << i+1<<"-th most likely key length: " << likely_key_length << std::endl;
		// Here we assume the Length of the key is = likely_key_length. Then we split the altered_cipher
		// into likely_key_length many substrings, each substring containing every likely_key_length-th character
		std::vector<std::string> column_substrings = get_column_substrings(altered_cipher, likely_key_length);
		// Now we analyze each substring as if it were encrypted with a Caesar cipher.
		// A Frequency analysis is done to find the most likely shift for each substring.
		// The collection of all the shifts is the most likely key
		std::vector<int> key_shifts = initialize_key_shifts(column_substrings,language);
		// Now we reverse the caesar decryption with the key_shifts we found above
		std::vector<std::string> decrypted_columns = caesar_decrypt_columns(column_substrings, key_shifts);
		//Now we reassamble it into a plaintext. That means inserting spaces and punctuation just as in
		// the original ciphertext
		std::string plain_text = reassemble_plaintext(decrypted_columns, ciphertext);
		// Finally we create the key string from the key shifts
		std::string key = create_key(key_shifts);
		// print the results
		std::cout << "Most Likely Key " << key << ":\n" << "Decrypted plaintext:\n"<< plain_text <<"\n" << std::endl;
	}
	return 0;
}
