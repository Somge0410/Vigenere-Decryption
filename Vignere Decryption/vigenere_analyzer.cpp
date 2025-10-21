#include "vignere_analyzer.h" 
#include "Alphabeth.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <cctype> 

//Internal helper functions
std::string get_every_nth_char(const std::string& input, size_t n, size_t offset) {
	std::string result;
	for (size_t i = offset; i < input.size(); i += n) {
		result += input[i];
	}
	return result;
}
char get_most_frequent_char(const std::string& input) {
	std::vector<size_t> freq(256, 0);
	for (char c : input) {
		freq[static_cast<unsigned char>(c)]++;
	}
	size_t max_freq = 0;
	char most_frequent_char = '\0';
	for (size_t i = 0; i < freq.size(); ++i) {
		if (freq[i] > max_freq) {
			max_freq = freq[i];
			most_frequent_char = static_cast<char>(i);
		}
	}
	return most_frequent_char;
}
double quadratic_distance(const std::vector<double>& freq1, const std::vector<double>& freq2) {
	double distance = 0.0;
	for (size_t i = 0; i < freq1.size(); ++i) {
		double diff = freq1[i] - freq2[i];
		distance += diff * diff;
	}
	return distance;
}
std::vector<double> shift_frequencies(const std::vector<double>& freq, int shift) {
	std::vector<double> result(freq.size(), 0.0);
	size_t n = freq.size();
	for (size_t i = 0; i < n; ++i) {
		size_t new_index = (i + shift + n) % n;
		result[new_index] = freq[i];
	}
	return result;
}
int find_best_caesar_shift(const std::string& text, std::string& language) {
	std::vector<double> expected_frequencies;
	if (language == "English") {
		expected_frequencies = english_letter_frequencies;
	}
	else if (language == "German") {
		expected_frequencies = german_letter_frequencies;
	}
	else {
		std::cerr << "Unsupported language for frequency analysis." << std::endl;
		return -1;
	}
	std::vector<double> observed_frequencies(alphabet.size(), 0);
	size_t total_chars = text.size();
	for (char c : text) {
		observed_frequencies[static_cast<unsigned char>(c) - static_cast<unsigned char>('a')] += 1.0 / total_chars;
	}
	/*std::cout << "Frequencies: ";
	for (size_t i = 0; i < freq.size(); ++i) {
		std::cout << alphabet[i] << ": " << freq[i] << ", ";
	}*/
	int best_shift = 0;
	double best_distance = std::numeric_limits<double>::max();
	for (size_t shift = 0; shift < alphabet.size(); ++shift) {
		std::vector<double> shifted_freq = shift_frequencies(expected_frequencies, shift);
		double distance = quadratic_distance(shifted_freq, observed_frequencies);
		if (distance < best_distance) {
			best_distance = distance;
			best_shift = shift;
		}
	}
	return best_shift;




}
std::string restore_punctuation(const std::string& cipher_text, std::string& decyphered_text) {
	std::string result;
	size_t content_index = 0;
	for (char c : cipher_text) {
		if (alphabet.find(std::tolower(c)) != std::string::npos) {
			if (isupper(c))
				result += std::toupper(decyphered_text[content_index++]);
			else {
				result += decyphered_text[content_index++];
			}
		}
		else {
			result += c;
		}
	}
	return result;
}
std::vector<int> get_divisors(int n) {
	std::vector<int> divisors;
	for (int i = 4; i <= n; ++i) {
		if (n % i == 0) {
			divisors.push_back(i);
		}
	}
	return divisors;
}
void tally_divisors(std::vector<std::pair<int, int>>& divisor_frequency, int repeat_distance) {
	std::vector<int> divisors = get_divisors(repeat_distance);
	for (int d : divisors) {
		auto it = std::find_if(divisor_frequency.begin(), divisor_frequency.end(),
			[d](const std::pair<int, int>& p) { return p.first == d; });
		if (it != divisor_frequency.end()) {
			it->second += 1;
		}
		else {
			divisor_frequency.push_back(std::make_pair(d, 1));
		}
	}

}
void sort_divisor_frequency(std::vector<std::pair<int, int>>& divisor_frequency) {
	std::sort(divisor_frequency.begin(), divisor_frequency.end(),
		[](const std::pair<int, int>& a, const std::pair<int, int>& b) {
			return a.second > b.second;
		});
}

//Implementation of the functions from the header file
std::string transform_ciphertext(const std::string& ciphertext) {
	std::string altered_cipher = ciphertext;
	std::transform(altered_cipher.begin(), altered_cipher.end(), altered_cipher.begin(), std::tolower);
	altered_cipher.erase(std::remove_if(
		altered_cipher.begin(),
		altered_cipher.end(),
		[](char c) {
			return alphabet.find(c) == std::string::npos;
		}), altered_cipher.end());
	return altered_cipher;
}
std::vector<std::pair<int, int>> get_divisor_frequency(const std::string& ciphertext) {
	std::vector<std::pair<int, int>> divisor_frequency;
	for (size_t repeat_length = 10; repeat_length >= 3; --repeat_length) {
		for (size_t start = 0; start + 2 * repeat_length <= ciphertext.size(); ++start) {
			std::string cipher_substr = ciphertext.substr(start, repeat_length);
			size_t next_pos = ciphertext.find(cipher_substr, start + repeat_length);
			if (next_pos != std::string::npos) {
				//std::cout << cipher_substr << " with length " << repeat_length << " " << " with distance " << next_pos - start << std::endl;
				tally_divisors(divisor_frequency, next_pos - start);
			}
		}
	}
	sort_divisor_frequency(divisor_frequency);
	return divisor_frequency;
}
std::vector<std::string> get_column_substrings(const std::string& input, size_t n) {
	std::vector<std::string> result(n);
	for (size_t offset = 0; offset < n; ++offset) {
		result[offset] = get_every_nth_char(input, n, offset);
	}
	return result;
}
std::vector<int> initialize_key_shifts(std::vector<std::string> column_substrings, std::string language) {
	std::vector<int> key_shifts(column_substrings.size(), 0);
	for (size_t i = 0; i < column_substrings.size(); ++i) {
		key_shifts[i] = find_best_caesar_shift(column_substrings[i], language);
	}
	return key_shifts;
}
std::vector<std::string> caesar_decrypt_columns(const std::vector<std::string>& column_substrings, const std::vector<int>& key_shifts) {
	std::vector<std::string> decrypted_columns(column_substrings.size());
	for (size_t i = 0; i < column_substrings.size(); ++i) {
		std::string decrypted_column;
		for (char c : column_substrings[i]) {
			size_t char_index = alphabet.find(c);
			size_t decrypted_index = (char_index - key_shifts[i] + alphabet.size()) % alphabet.size();
			decrypted_column += alphabet[decrypted_index];
		}
		decrypted_columns[i] = decrypted_column;
	}
	return decrypted_columns;
}
std::string reassemble_plaintext(const std::vector<std::string>& decrypted_columns, const std::string original_cipher_text) {
	std::string decrypted_content;
	for (size_t i = 0; i < decrypted_columns[0].size(); ++i) {
		for (size_t j = 0; j < decrypted_columns.size(); ++j) {
			if (i < decrypted_columns[j].size()) {
				decrypted_content += decrypted_columns[j][i];
			}
		}
	}
	decrypted_content = restore_punctuation(original_cipher_text, decrypted_content);
	return decrypted_content;
}
std::string create_key(const std::vector<int>& key_shifts) {
	std::string key;
	for (int shift : key_shifts) {
		key += toupper(alphabet[shift]);
	}
	return key;
}