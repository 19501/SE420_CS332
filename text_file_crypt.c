// Magnus Bergman
// SE420 SQA
// Exercise 1, part 3
// Custom encryption program using substitution, transposition, and a random hash

// NOTE: The substitution-cypher part of this code is a slightly-modified version
// of the example found online at:
// https://www.programmingalgorithms.com/algorithm/simple-substitution-cipher?lang=C

// NOTE: The transposition-cypher part of this code is a slightly-modified version
// of the example found online at:
// https://www.programmingalgorithms.com/algorithm/transposition-cipher

// The hash function is from http://www.cse.yorku.ca/~oz/hash.html
// The hashEncrypt and hashDecrypt functions are my own, however.

#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<stdbool.h>
#include<math.h>
#include<stdio.h>

typedef struct {
	int Key;
	char Value;
} KeyValuePair;

int compare(const void* first, const void* second) {
	return ((KeyValuePair*)first)->Value - ((KeyValuePair*)second)->Value;
}

char** Create2DArray(int rowCount, int colCount) {
	char** rArray = (char**)malloc(sizeof(char*) * rowCount);

    int i;
	for (i = 0; i < rowCount; i++) {
		rArray[i] = (char*)malloc(sizeof(char) * colCount);
	}

	return rArray;
}

char* PadRight(char* str, int max, char padChar) {
	int strLen = strlen(str);
	char* output = (char*)malloc(sizeof(char*) * max);

	if (strLen < max) {
		//int padLen = max - strLen;
		int i;
		for (i = 0; i < max; ++i)
			output[i] = i < strLen ? str[i] : padChar;
	}

	output[max] = '\0';
	return output;
}

int* GetShiftIndexes(char* key)
{
	int keyLength = strlen(key);
	int* indexes = (int*)malloc(sizeof(int) * keyLength);
	KeyValuePair* sortedKey = (KeyValuePair*)malloc(sizeof(KeyValuePair) * keyLength);
	int i;

	for (i = 0; i < keyLength; ++i)
    {
        //sortedKey[i] = {i, key[i]};
        sortedKey[i].Key = i;
        sortedKey[i].Value = key[i];
    }

	qsort(sortedKey, keyLength, sizeof(KeyValuePair), compare);
	for (i = 0; i < keyLength; ++i)
		indexes[sortedKey[i].Key] = i;

	return indexes;
}

char* EncipherTrans(char* input, char* key, char padChar)
{
	int totalChars = strlen(input);
	int keyLength = strlen(key);
	input = (totalChars % keyLength == 0) ? input : PadRight(input, totalChars - (totalChars % keyLength) + keyLength, padChar);
	totalChars = strlen(input);
	char* output = (char*)malloc(sizeof(char) * totalChars);
	int totalColumns = keyLength;
	int totalRows = (int)ceil((double)totalChars / totalColumns);
	char** rowChars = Create2DArray(totalRows, totalColumns);
	char** colChars = Create2DArray(totalColumns, totalRows);
	char** sortedColChars = Create2DArray(totalColumns, totalRows);
	int currentRow, currentColumn, i, j;
	int* shiftIndexes = GetShiftIndexes(key);

	for (i = 0; i < totalChars; ++i)
	{
		currentRow = i / totalColumns;
		currentColumn = i % totalColumns;
		rowChars[currentRow][currentColumn] = input[i];
	}

	for (i = 0; i < totalRows; ++i)
		for (j = 0; j < totalColumns; ++j)
			colChars[j][i] = rowChars[i][j];

	for (i = 0; i < totalColumns; ++i)
		for (j = 0; j < totalRows; ++j)
			sortedColChars[shiftIndexes[i]][j] = colChars[i][j];

	for (i = 0; i < totalChars; ++i)
	{
		currentRow = i / totalRows;
		currentColumn = i % totalRows;
		output[i] = sortedColChars[currentRow][currentColumn];
	}

	output[totalChars] = '\0';
	return output;
}

char* DecipherTrans(char* input, char* key)
{
	int keyLength = strlen(key);
	int totalChars = strlen(input);
	char* output = (char*)malloc(sizeof(char*) * totalChars);
	int totalColumns = (int)ceil((double)totalChars / keyLength);
	int totalRows = keyLength;
	char** rowChars = Create2DArray(totalRows, totalColumns);
	char** colChars = Create2DArray(totalColumns, totalRows);
	char** unsortedColChars = Create2DArray(totalColumns, totalRows);
	int currentRow, currentColumn, i, j;
	int* shiftIndexes = GetShiftIndexes(key);

	for (i = 0; i < totalChars; ++i)
	{
		currentRow = i / totalColumns;
		currentColumn = i % totalColumns;
		rowChars[currentRow][currentColumn] = input[i];
	}

	for (i = 0; i < totalRows; ++i)
		for (j = 0; j < totalColumns; ++j)
			colChars[j][i] = rowChars[i][j];

	for (i = 0; i < totalColumns; ++i)
		for (j = 0; j < totalRows; ++j)
			unsortedColChars[i][j] = colChars[i][shiftIndexes[j]];

	for (i = 0; i < totalChars; ++i)
	{
		currentRow = i / totalRows;
		currentColumn = i % totalRows;
		output[i] = unsortedColChars[currentRow][currentColumn];
	}

	output[totalChars] = '\0';
	return output;
}

bool CipherSub(char* input, char* oldAlphabet, char* newAlphabet, char* output)
{
	int inputLen = strlen(input);

	if (strlen(oldAlphabet) != strlen(newAlphabet))
		return false;

    int i;
	for (i = 0; i < inputLen; ++i)
	{
		const char* ptr = strchr(oldAlphabet, tolower(input[i]));
		int oldCharIndex = ptr - oldAlphabet;

		if (ptr && oldCharIndex >= 0)
			output[i] = isupper(input[i]) ? toupper(newAlphabet[oldCharIndex]) : newAlphabet[oldCharIndex];
		else
			output[i] = input[i];
	}

	output[inputLen] = '\0';
	return true;
}

bool EncipherSub(char* input, char* cipherAlphabet, char* output)
{
	char* plainAlphabet = "abcdefghijklmnopqrstuvwxyz";
	return CipherSub(input, plainAlphabet, cipherAlphabet, output);
}

bool DecipherSub(char* input, char* cipherAlphabet, char* output)
{
	char* plainAlphabet = "abcdefghijklmnopqrstuvwxyz";
	return CipherSub(input, cipherAlphabet, plainAlphabet, output);
}

// Hash generation from string
// Copied from http://www.cse.yorku.ca/~oz/hash.html
unsigned long hash(char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = (*str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

// A very simple "take the ASCII code of the input character and add the hashkey value
void hashEncrypt(char* input, unsigned long hashKey, char* output)
{
    int iterator;
    int stringLength = strlen(input);
    for(iterator = 0; iterator < stringLength; iterator++)
    {
        output[iterator] = input[iterator] + hashKey;
    }
}

// A very simple "take the ASCII code of the input character and subtract the hashkey value
void hashDecrypt(char* input, unsigned long hashKey, char* output)
{
    int iterator;
    int stringLength = strlen(input);
    for(iterator = 0; iterator < stringLength; iterator++)
    {
        output[iterator] = input[iterator] - hashKey;
    }
}

// Put running all of the en/de-cryption in a method to simplify the main() function
// I know that using the same variable name in the arguments as in the main()
// function is a bad idea generally, but it saves time re-writing the variable names
void runThroughAll(char* inputText, char* outputText, bool disp)
{
    if(disp)
    {
        printf("------------------------------------------");
        printf("\nThis is the input string:");
        printf("\n%s", inputText);
    }

    // Take the input text and cipher it with a substitution cypher
    char* cipherAlphabet = "yhkqgvxfoluapwmtzecjdbsnri";
    char* subText = (char*)malloc(strlen(inputText));

    // set the key for the transposition cypher
    char* key = "transpose";

    // Set the hash for the hash-substitution cypher
    unsigned long testHash;
    testHash = hash("testPhrase");
    if(disp)
        printf("\n\nTest Hash: %lu", testHash);

    // substitution-cypher
    // input: inputText
    // output: subText
    EncipherSub(inputText, cipherAlphabet, subText);
    if(disp)
        printf("\n\nAfter substitution:\n%s", subText);

    // Transposition-cypher
    // input: subText
    // output: transText
    char* transText = EncipherTrans(subText, key, '-');
    if(disp)
        printf("\n\nAfter transposition:\n%s", transText);

    // Hash-Substitution cypher
    // input: transText
    // output: hashSubText

    char* hashSubText = (char*)malloc(strlen(transText));
    hashEncrypt(transText, testHash, hashSubText);
    if(disp)
        printf("\n\nAfter hash:\n%s", hashSubText);

    // un-hash-Sub-cypher
    // input: hashSubText
    // output: unHashSubText

    char* unHashSubText = (char*)malloc(strlen(hashSubText));
    hashDecrypt(hashSubText, testHash, unHashSubText);
    if(disp)
        printf("\n\nAfter un-hash:\n%s", unHashSubText);

    // un-Transposition-cypher
    // input: unHashSubText
    // output: unTransText
    char* unTransText = DecipherTrans(unHashSubText, key);
    if(disp)
        printf("\n\nAfter un-transposition:\n%s", unTransText);

    // Un-substitution-cypher
    // input: unTransText
    // output: outputText
    DecipherSub(unTransText, cipherAlphabet, outputText);

    if (disp)
    {
        printf("\n\nOutput over input:");
        printf("\n%s\n%s\n", outputText, inputText);
    }
}

//  Takes the input text, encrypts it with all 3 levels, and then
//  saves it to the output text given.
void encrypt3(char* inputText, char* outputText)
{
    // Take the input text and cipher it with a substitution cypher
    char* cipherAlphabet = "yhkqgvxfoluapwmtzecjdbsnri";
    char* subText = (char*)malloc(strlen(inputText));

    // set the key for the transposition cypher
    char* key = "transpose";

    // Set the hash for the hash-substitution cypher
    unsigned long testHash;
    testHash = hash("testPhrase");

    // substitution-cypher
    // input: inputText
    // output: subText
    EncipherSub(inputText, cipherAlphabet, subText);

    // Transposition-cypher
    // input: subText
    // output: transText
    char* transText = EncipherTrans(subText, key, '-');

    // Hash-Substitution cypher
    // input: transText
    // output: outputText

    hashEncrypt(transText, testHash, outputText);
}

void decrypt3(char* inputText, char* outputText)
{
    unsigned long testHash;
    testHash = hash("testPhrase");
    char* unHashSubText = (char*)malloc(strlen(inputText));
    char* cipherAlphabet = "yhkqgvxfoluapwmtzecjdbsnri";

    // set the key for the transposition cypher
    char* key = "transpose";

    hashDecrypt(inputText, testHash, unHashSubText);

    // un-Transposition-cypher
    // input: unHashSubText
    // output: unTransText
    char* unTransText = DecipherTrans(unHashSubText, key);

    // Un-substitution-cypher
    // input: unTransText
    // output: outputText
    DecipherSub(unTransText, cipherAlphabet, outputText);
}

int main()
{
    //  Define the input file name
    FILE *inputFilePTR, *cipheredFilePTR, *newFilePTR;

    // Initialize the buffers
    char inputBuffer[1000];
    char outputBuffer[1000];

    inputFilePTR = fopen("input.txt", "r");
    cipheredFilePTR = fopen("cipheredText.txt", "w");

    if (inputFilePTR == NULL)
    {
        printf("Input file couldn't be opened.");
        return 1;
    }

    // Oddly, *this* line works perfectly well.
    fgets(inputBuffer, 1000, inputFilePTR) != NULL;

    //  But *this* one generates a run-time error.
    while(fgets(inputBuffer, 1000, inputFilePTR) != NULL)
    {
        encrypt3(inputBuffer, outputBuffer);
        fprintf(cipheredFilePTR, "%s", outputBuffer);
    }

    // Close the middle file
    fclose(cipheredFilePTR);

    // Open the middle file for read-only
    cipheredFilePTR = fopen("cipheredText.txt", "r");

    // Open the new file to write the original text to
    newFilePTR = fopen("deCipheredText.txt", "w");

    // Loop through the ciphered text, de-ciphering each line
    while(fgets(inputBuffer, 1000, cipheredFilePTR) != NULL)
    {
        decrypt3(inputBuffer, outputBuffer);
        fprintf(newFilePTR, "%s", outputBuffer);
    }

    // Close the files.
    fclose(inputFilePTR);
    fclose(newFilePTR);

    return 0;
}
