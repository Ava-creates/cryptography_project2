
#include <iostream>
#include <string>
#include <vector>
#include <stack>



//Converts an input string to an array of int16_t in the same order as the string
std::vector<int16_t> string_to_bitarray(const std::string& s) {
	int n = s.size();
	std::vector<int16_t> binarystr;
	std::stack<int16_t> reverse;
	for (int i = n - 1; i >= 0; i--) {
		if ((n - i) % 2 == 1) {
			reverse.push((int16_t)s[i]);	//Every other character, push onto the stack
		}
		else {
			int16_t temp = reverse.top();
			std::cout << ((int16_t)s[i] << 8) << " ";
			reverse.pop();                              //Every other character, add the character shifted 1 char size (8bits)
			reverse.push(((int16_t)s[i] << 8) + (int16_t)temp);    //left to the existing value on the stack
		}

	}
	while (!reverse.empty()) {
		binarystr.push_back(reverse.top());	//Reverse the order
		reverse.pop();
	}
	return binarystr;
}


int main() {

	std::vector<int16_t> v = string_to_bitarray("abcd");
	for (int i = 0; i < v.size(); i++) {
		std::cout << v[i] << " ";
	}
	return 1;
}
