
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <valgrind/memcheck.h>
#include <ftw.h>

#define __STDC_FORMAT_MACROS

#define START_MAX 128
#define BUFF_SIZE 128
#define KEY_SIZE 65536
#define DECIPHER 1
#define META_DESCRIPTOR 0
#define MAX_BLOCK_LENGTH 30
#define MIN_BLOCK_LENGTH 10
#define MAGIC_NUM (KEY_SIZE - ((offset + block_length) % KEY_SIZE) + 93) % KEY_SIZE
#define MAX_PATH 256
#define PROGRESS_STEP 5

enum {FIL, DIR};

typedef struct crypt_tag{
	FILE *plain;
	FILE *cipher;
	FILE *meta;
	char *cPath;
	char *cwd;
	uint16_t *key;
	uint16_t *rev_key;
	uint64_t meta_size;
	uint64_t meta_byte;
	int op;
	unsigned int curr_file;
	uint16_t block_length;
	int curr_block;
}crypt_t;

typedef struct file_tag{
	char fPath[MAX_PATH];			//file name limited to 255 characters, must be null terminated
	uint16_t level;					//Indicates the level in the file tree that the file resides the root directory is level 0
	uint16_t type;					//Indicates wether the entry is a file or directory
}file_t;

void key_gen(FILE *);
void key_poly(uint16_t *, uint16_t*, uint16_t);
void file_crypt(crypt_t *cInfo);
int fs_decipher(crypt_t *cInfo);
void progress_print(unsigned long int, unsigned long int, int);
int pre_crypt(const char *, const struct stat *, int, struct FTW *);
int fs_crypt(const char *, const struct stat *, int, struct FTW *);
int post_crypt(const char *, const struct stat *, int, struct FTW *);
int decrypt(const char *, const struct stat *, int, struct FTW *);

unsigned long int bytes = 0;
unsigned long int file_count = 0;
unsigned long int curr_byte = 0;
crypt_t *cGlobal = NULL;
char path[1024];

int main(int argc, char* argv[])
{
	long int seed = time(NULL);
	//long int seed = 1467209495;
#ifdef DEBUG
	printf("Seed: %ld\n", seed);
#endif
	srand(seed);
	if(argc < 4)
	{
		exit(1);
	}
	char *plain = argv[1];
	char *cipher = argv[2];
	int op = atoi(argv[3]);	
	char *key_name;
	FILE *keyf;
	if(argc < 5)
	{
		char key_string[16] = "tmpKey\0";
		key_name = key_string;
		keyf = fopen(key_name, "wb");
		key_gen(keyf);
		fclose(keyf);
		printf("Created Key: tmpKey\n");
		return 0;
	}
	key_name = argv[4];
	keyf = fopen(key_name, "r");
	uint16_t key[KEY_SIZE];
	uint16_t rev_key[KEY_SIZE];
	uint64_t sz = 500;
	uint16_t block_length, block_lengthw;
	uint16_t offset, offsetw;
	int count;
	int i = 0;
	uint16_t magic_num;
	char *inputdir;
	char cwd[MAX_PATH];
	char cPath[MAX_PATH];

	cGlobal = (crypt_t *)malloc(sizeof(crypt_t));
	cGlobal->cPath = cPath;
	cGlobal->cwd = cwd;


	//Build Key
	count = fread(key, sizeof(uint16_t), KEY_SIZE, keyf);
	assert(count == KEY_SIZE);
	cGlobal->key = key;
	cGlobal->op = op;
	//Build reverse Lookup key
	if(op == DECIPHER)
	{
		for(i = 0; i <KEY_SIZE; i++)
		{
			rev_key[key[i]] = i;
		}
		cGlobal->rev_key = rev_key;
		//Pick an input directory from the 2 provided
		inputdir = cipher;
	}
	else
	{	
		cGlobal->rev_key = NULL;
		//Pick input directory as the plain text directory
		inputdir = plain;
	}
	//fclose(plain);
	//fclose(cipher);
	nftw(inputdir, pre_crypt, 20, FTW_PHYS);
	printf("%lu items totalling %lu bytes\n", file_count, bytes);
	if(cGlobal->op == DECIPHER)
	{
		//Do deciphering prep
		//mkdir(plain, S_IRWXU);			//Probably not needed because absolute paths are used right now... look into changing this
		realpath(cipher, &(cGlobal->cPath[0]));
		sprintf(path, "%s/%d", cGlobal->cPath, META_DESCRIPTOR);
		cGlobal->meta = fopen(path, "r");
		printf("Deciphering:\n");
		progress_print(curr_byte, bytes, PROGRESS_STEP);
		curr_byte += sizeof(uint64_t)*fread(&sz, sizeof(uint64_t), 1, cGlobal->meta);
		curr_byte += sizeof(uint16_t)*fread(&block_length, sizeof(uint16_t), 1, cGlobal->meta);
		curr_byte += sizeof(uint16_t)*fread(&offset, sizeof(uint16_t), 1, cGlobal->meta);
		curr_byte += sizeof(uint16_t)*fread(&magic_num, sizeof(uint16_t), 1, cGlobal->meta);
		block_length = cGlobal->rev_key[block_length];
		cGlobal->block_length = block_length;
		cGlobal->curr_block = 0;
		offset = cGlobal->rev_key[offset];
		magic_num = cGlobal->rev_key[magic_num];
		//printf("Magic Num: %"PRIu16"\n", magic_num);
		assert(magic_num == MAGIC_NUM);
		if(magic_num != MAGIC_NUM)
		{
			printf("You have the wrong key\n");
			exit(2);
		}
		uint16_t *sz_array = (uint16_t *)(&sz);
		for(i = 0; i < sizeof(uint64_t)/sizeof(uint16_t); i++)
			sz_array[i] = cGlobal->rev_key[sz_array[i]];
		cGlobal->meta_size = sz;
		cGlobal->meta_byte = 0;
		cGlobal->curr_file = 1;
		key_poly(cGlobal->key, cGlobal->rev_key, offset);
		int cont;
		do{
			cont = fs_decipher(cGlobal);
		}while(cont != 0);
		printf("\n");
		fclose(cGlobal->meta);
		fflush(stdout);
		printf("Cleaning up files...\t");
		nftw(inputdir, post_crypt, 20, FTW_PHYS|FTW_DEPTH);
		printf("Done!\n");
	}
	else
	{
		mkdir(cipher, S_IRWXU);
		realpath(cipher, &(cGlobal->cPath[0]));
		realpath(cipher, cGlobal->cwd);
		sprintf(path, "%s/%d", cGlobal->cPath, META_DESCRIPTOR);
		cGlobal->meta = fopen(path, "w");
		sz = file_count*sizeof(file_t);
		uint16_t *sz_array = (uint16_t *)(&sz);
		//Treat as an array of uint16_t and encrypt
		for(i = 0; i < sizeof(uint64_t)/sizeof(uint16_t); i++)
			sz_array[i] = cGlobal->key[sz_array[i]];
		fwrite(&sz, sizeof(uint64_t), 1, cGlobal->meta);
		cGlobal->curr_block = 0;
		cGlobal->block_length = rand() % (MAX_BLOCK_LENGTH - MIN_BLOCK_LENGTH) + MIN_BLOCK_LENGTH;
		block_length = cGlobal->block_length;
		offset = rand() % (KEY_SIZE - 1) + 1;
		magic_num = MAGIC_NUM;				//This will be used in deciphering as a crude way to check that the key is valid
		block_lengthw = cGlobal->key[block_length];
		offsetw = cGlobal->key[offset];
		magic_num = cGlobal->key[magic_num];
		fwrite(&block_lengthw, sizeof(uint16_t), 1, cGlobal->meta);
		fwrite(&offsetw, sizeof(uint16_t), 1, cGlobal->meta);
		fwrite(&magic_num, sizeof(uint16_t), 1, cGlobal->meta);
		key_poly(cGlobal->key, NULL, offset);
		cGlobal->curr_file = 1;
		printf("Encrypting:\n");
		progress_print(curr_byte, bytes, PROGRESS_STEP);
		nftw(inputdir, fs_crypt, 20, FTW_PHYS);
		printf("\n");
		fclose(cGlobal->meta);
		printf("Cleaning up files...\t");
		fflush(stdout);
		nftw(inputdir, post_crypt, 20, FTW_PHYS|FTW_DEPTH);
		printf("Done!\n");
	}
	fclose(keyf);
	free(cGlobal);
	return 0;
}

int pre_crypt(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	if(tflag == FTW_F)
	{
		printf("%s: F %d\n", fpath, (int)sb->st_size);
		bytes += sb->st_size + sizeof(file_t);
		file_count++;
	}
	else if(tflag == FTW_D)
	{
		printf("%s: D\n", fpath);
		bytes += sizeof(file_t);
		file_count++;
	}
	if(cGlobal->op == DECIPHER)
	{
		bytes -= sizeof(file_t);
	}
	return 0;
}

int fs_crypt(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	int i;
	file_t fInfo;
	//strncpy(fInfo.fPath, fpath, MAX_PATH);
	realpath(fpath, fInfo.fPath);
	//int half_length;
	int length = strlen(fInfo.fPath) + 1;	//Add 1 because we want to keep the NULL character
#ifdef DEBUG
	printf("\n%s\t%d\n", fInfo.fPath, length);
#endif	
	uint16_t *process_in = (uint16_t *)(fInfo.fPath);
	
	//Check if its time to start a new block
	if(cGlobal->curr_block >= cGlobal->block_length)
	{
#ifdef DEBUG
		printf("Need to do key change\n");
#endif
		uint16_t offset, offsetw, block_length, block_lengthw;
		cGlobal->curr_block = 0;
		cGlobal->block_length = rand() % (MAX_BLOCK_LENGTH - MIN_BLOCK_LENGTH) + MIN_BLOCK_LENGTH;
		block_length = cGlobal->block_length;
		offset = rand() % (KEY_SIZE - 1) + 1;
		//printf("BL: %"PRIu16" Offset: %"PRIu16"\n", block_length, offset);
		block_lengthw = cGlobal->key[block_length];
		offsetw = cGlobal->key[offset];
		fwrite(&block_lengthw, sizeof(uint16_t), 1, cGlobal->meta);
		fwrite(&offsetw, sizeof(uint16_t), 1, cGlobal->meta);
		key_poly(cGlobal->key, NULL, offset);		
	}
	
	fInfo.level = 0;					//Might not need this field but keep it for now	
	if(tflag == FTW_F)
	{
		cGlobal->plain = fopen(fInfo.fPath, "r");
		sprintf(path, "%s/%d", cGlobal->cPath, cGlobal->curr_file);
		cGlobal->cipher = fopen(path, "w");
		fInfo.type = FIL;
		cGlobal->curr_file++;
	}
	else
	{
		assert(tflag == FTW_D);
		fInfo.type = DIR;
	}
	
	//Randomize data after the end of the block to avoid having a bunch of repeated elements
	for(i = length; i < MAX_PATH; i++)
	{
		fInfo.fPath[i] = (char)(rand() % 256);
	}
	length % 2 == 0 ? 0 : length++;
	fInfo.fPath[length+1] = 'a';
	for(i = 0; i<length/2; i++)
	{
#ifdef DEBUG
		if(VALGRIND_CHECK_MEM_IS_DEFINED(&(fInfo.fPath[2*i]), sizeof(uint8_t)))
		{
			printf("Path string check: %d\n", 2*i);
		}
		if(VALGRIND_CHECK_MEM_IS_DEFINED(&(fInfo.fPath[2*i+1]), sizeof(uint8_t)))
		{
			printf("Path string check: %d\n", 2*i+1);
		}
		//fflush(stdout);
		//VALGRIND_CHECK_VALUE_IS_DEFINED(process_in[i]);
#endif
		process_in[i] = cGlobal->key[process_in[i]];
	}
	/*
	for(i = 0; i < length; i+=2)
	{
		pptr[0] = fInfo.fPath[i];
		pptr[1] = fInfo.fPath[i+1];
		process = cGlobal->key[process];
		fInfo.fPath[i] = pptr[0];
		fInfo.fPath[i+1] = pptr[1];
	}*/
	fInfo.level = cGlobal->key[fInfo.level];
	fInfo.type = cGlobal->key[fInfo.type];
	fwrite(fInfo.fPath, sizeof(char), MAX_PATH, cGlobal->meta);
	fwrite(&(fInfo.level), sizeof(uint16_t), 1, cGlobal->meta);
	fwrite(&(fInfo.type), sizeof(uint16_t), 1, cGlobal->meta);
	curr_byte += sizeof(file_t);
	cGlobal->curr_block+=2;										//Not exact but roughly
	
	//Encrypt the file
	if(tflag == FTW_F)
	{
		file_crypt(cGlobal);
		fclose(cGlobal->plain);
		fclose(cGlobal->cipher);
	}
	
	progress_print(curr_byte, bytes, PROGRESS_STEP);
	return 0;
}

int fs_decipher(crypt_t *cInfo)
{
	uint16_t offset, block_length;	
	int i;
	file_t fInfo;
	uint16_t process;
	char *pptr = (char *)(&process);
	if(cInfo->meta_byte >= cInfo->meta_size)
	{
		return 0;
	}
	
	if(cInfo->curr_block >= cInfo->block_length)
	{	//Check Here
#ifdef DEBUG
		printf("\nNeed to do key change\n");
#endif
		curr_byte += sizeof(uint16_t)*fread(&block_length, sizeof(uint16_t), 1, cInfo->meta);
		curr_byte += sizeof(uint16_t)*fread(&offset, sizeof(uint16_t), 1, cInfo->meta);
		block_length = cInfo->rev_key[block_length];
		offset = cInfo->rev_key[offset];
		//printf("BL: %"PRIu16" Offset: %"PRIu16"\n", block_length, offset);
		key_poly(cInfo->key, cInfo->rev_key, offset);
		cInfo->curr_block = 0;
		cInfo->block_length = block_length;
	}
	
	//Read and Decipher Meta block;
	fread(fInfo.fPath, sizeof(uint8_t), MAX_PATH, cInfo->meta);
	fread(&(fInfo.level), sizeof(uint16_t), 1, cInfo->meta);
	fread(&(fInfo.type), sizeof(uint16_t), 1, cInfo->meta);
	curr_byte+= sizeof(file_t);
	cInfo->meta_byte+=sizeof(file_t);
	cInfo->curr_block+=2;
	
	for(i = 0; i < MAX_PATH; i+=2)
	{
		pptr[0] = fInfo.fPath[i];
		pptr[1] = fInfo.fPath[i+1];
		process = cInfo->rev_key[process];
		fInfo.fPath[i] = pptr[0];
		fInfo.fPath[i+1] = pptr[1];
		if(fInfo.fPath[i] == '\0' || fInfo.fPath[i+1] == '\0')
		{
			break;
		}
	}
#ifdef DEBUG
	printf("\n%s\n", fInfo.fPath);
#endif
	fInfo.level = cInfo->rev_key[fInfo.level];
	fInfo.type = cInfo->rev_key[fInfo.type];
	if(fInfo.type == DIR)
	{
		mkdir(fInfo.fPath, S_IRWXU);
	}
	else
	{
		assert(fInfo.type == FIL);
		cInfo->plain = fopen(fInfo.fPath, "w");
		sprintf(path, "%s/%d", cInfo->cPath, cInfo->curr_file);
		cInfo->cipher = fopen(path, "r");
		file_crypt(cInfo);
		fclose(cInfo->plain);
		fclose(cInfo->cipher);
		cInfo->curr_file++;
	}
	progress_print(curr_byte, bytes, PROGRESS_STEP);
	return 1;
}

int post_crypt(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	file_t fInfo;
	realpath(fpath, fInfo.fPath);
	
	if(tflag == FTW_F)
	{
		unlink(fInfo.fPath);
	}
	else
	{
		remove(fInfo.fPath);
	}
	return 0;
}

void file_crypt(crypt_t *cInfo)
{
	uint8_t in[BUFF_SIZE+1];
	uint16_t *process_in = (uint16_t *)in;
	long int file_size = 0;
	uint64_t sz = 500;
	uint16_t block_length, block_lengthw;
	uint16_t offset, offsetw;
	//char *plainstring = (char *)in;
	int count;
	int half_count;
	uint64_t total_count = 0;
	int i = 0;
	uint16_t magic_num;
	int curr_block = 0;
	FILE *inputfp;
	
	//Check to ensure key does not need to be updated
	if(cInfo->curr_block >= cInfo->block_length)
	{
		if(cInfo->op == DECIPHER)
		{
			//Change block using decipher procedure
			curr_byte += sizeof(uint16_t)*fread(&block_length, sizeof(uint16_t), 1, cInfo->meta);
			curr_byte += sizeof(uint16_t)*fread(&offset, sizeof(uint16_t), 1, cInfo->meta);
#ifdef DEBUG
			printf("Block_length up at start of file\n");
			if(VALGRIND_CHECK_MEM_IS_DEFINED(&block_length, sizeof(uint16_t)))
			{
				printf("Failed to read block_length\n");
			}
			if(VALGRIND_CHECK_MEM_IS_DEFINED(&offset, sizeof(uint16_t)))
			{
				printf("Failed to read offset\n");
			}
#endif
			block_length = cInfo->rev_key[block_length];
			offset = cInfo->rev_key[offset];
			//printf("BL: %"PRIu16" Offset: %"PRIu16"\n", block_length, offset);
			key_poly(cInfo->key, cInfo->rev_key, offset);
			cInfo->curr_block = 0;
			cInfo->block_length = block_length;
		}
		else
		{
#ifdef DEBUG
			printf("Block_length up at start of file\n");
#endif
			block_length = rand() % (MAX_BLOCK_LENGTH - MIN_BLOCK_LENGTH) + MIN_BLOCK_LENGTH;
			offset = rand() % (KEY_SIZE - 1) + 1;
			//printf("BL: %"PRIu16" Offset: %"PRIu16"\n", block_length, offset);
			block_lengthw = cInfo->key[block_length];
			offsetw = cInfo->key[offset];
			fwrite(&block_lengthw, sizeof(uint16_t), 1, cInfo->meta);
			fwrite(&offsetw, sizeof(uint16_t), 1, cInfo->meta);
			key_poly(cInfo->key, NULL, offset);
			curr_block = 0;
		}
	}
	
	
	
	if(cInfo->op == DECIPHER)
	{
		inputfp = cInfo->cipher;
		//Decipher original file size and starting block length
		curr_byte += sizeof(uint64_t)*fread(&sz, sizeof(uint64_t), 1, cInfo->cipher);
		curr_byte += sizeof(uint16_t)*fread(&block_length, sizeof(uint16_t), 1, cInfo->cipher);
		curr_byte += sizeof(uint16_t)*fread(&offset, sizeof(uint16_t), 1, cInfo->cipher);
		curr_byte += sizeof(uint16_t)*fread(&magic_num, sizeof(uint16_t), 1, cInfo->cipher);
		block_length = cInfo->rev_key[block_length];
		offset = cInfo->rev_key[offset];
		magic_num = cInfo->rev_key[magic_num];
		//printf("Magic Num: %"PRIu16"\n", magic_num);
		assert(magic_num == MAGIC_NUM);
		if(magic_num != MAGIC_NUM)
		{
			printf("You have the wrong key\n");
			exit(2);
		}
		uint16_t *sz_array = (uint16_t *)(&sz);
		for(i = 0; i < sizeof(uint64_t)/sizeof(uint16_t); i++)
			sz_array[i] = cInfo->rev_key[sz_array[i]];
#ifdef DEBUG
		printf("Plain Text Size: %"PRIu64"\n", sz);
#endif
		key_poly(cInfo->key, cInfo->rev_key, offset);
	}
	else
	{
		inputfp = cInfo->plain;
		//Find plainTxt file size
		fseek(cInfo->plain, 0, SEEK_END);
		file_size = ftell(cInfo->plain);
		rewind(cInfo->plain);		//Go back to beginning
		sz = file_size;		//Store size in block of data of known length;
		uint16_t *sz_array = (uint16_t *)(&sz);
		//Treat as an array of uint16_t and encrypt
		for(i = 0; i < sizeof(uint64_t)/sizeof(uint16_t); i++)
			sz_array[i] = cInfo->key[sz_array[i]];
		fwrite(&sz, sizeof(uint64_t), 1, cInfo->cipher);	//Write as first bytes in cipher file
		block_length = rand() % (MAX_BLOCK_LENGTH - MIN_BLOCK_LENGTH) + MIN_BLOCK_LENGTH;
		offset = rand() % (KEY_SIZE - 1) + 1;
		magic_num = MAGIC_NUM;				//This will be used in deciphering as a crude way to check that the key is valid
		block_lengthw = cInfo->key[block_length];
		offsetw = cInfo->key[offset];
		magic_num = cInfo->key[magic_num];
		fwrite(&block_lengthw, sizeof(uint16_t), 1, cInfo->cipher);
		fwrite(&offsetw, sizeof(uint16_t), 1, cInfo->cipher);
		fwrite(&magic_num, sizeof(uint16_t), 1, cInfo->cipher);
		key_poly(cInfo->key, NULL, offset);
	}
	
	//Do encryption
	do
	{
		if(cInfo->op == DECIPHER)
		{
			count = fread(in, sizeof(uint8_t), BUFF_SIZE, cInfo->cipher);
			curr_byte += count;
			total_count += count;
			assert(count <= BUFF_SIZE);
			count % 2 == 0 ? 0 : count++;		//Count will only be odd if this is the last read and there are an odd number bytes
			half_count = count/2;
			for(i = 0; i < half_count; i++)
			{
				process_in[i] = cInfo->rev_key[process_in[i]];
			}
			assert(total_count <= sz + 1);
			total_count > sz ? count-- : 0;		//If total_count > sz then there was an odd # of bytes in plain text and last cipher symbol only represents 1 byte
			fwrite(in, sizeof(uint8_t), count, cInfo->plain);
			curr_block++;
			if(curr_block == block_length && total_count < sz)
			{
				curr_byte += sizeof(uint16_t)*fread(&block_length, sizeof(uint16_t), 1, cInfo->cipher);
				curr_byte += sizeof(uint16_t)*fread(&offset, sizeof(uint16_t), 1, cInfo->cipher);
				block_length = cInfo->rev_key[block_length];
				offset = cInfo->rev_key[offset];
				key_poly(cInfo->key, cInfo->rev_key, offset);
				curr_block = 0;
				progress_print(curr_byte, bytes, PROGRESS_STEP);
			}
#ifdef DEBUG
			else if(curr_block == block_length && total_count >= sz)
			{
				printf("\nDo not change key at end of file\n");
			}
#endif
		}
		else
		{	
			
			count = fread(in, sizeof(uint8_t), BUFF_SIZE, cInfo->plain);
			curr_byte+=count;
			assert(count <= BUFF_SIZE);
			in[count] = '\0';
			count % 2 == 0 ? 0 : count++;
			half_count = count/2;
			for(i = 0; i<half_count; i++)
			{
				process_in[i] = cInfo->key[process_in[i]];
			}
			total_count += count;
			fwrite(in, sizeof(uint8_t), count, cInfo->cipher);
			curr_block++;
			if(curr_block == block_length && total_count < file_size)
			{
				block_length = rand() % (MAX_BLOCK_LENGTH - MIN_BLOCK_LENGTH) + MIN_BLOCK_LENGTH;
				offset = rand() % (KEY_SIZE - 1) + 1;
				block_lengthw = cInfo->key[block_length];
				offsetw = cInfo->key[offset];
				fwrite(&block_lengthw, sizeof(uint16_t), 1, cInfo->cipher);
				fwrite(&offsetw, sizeof(uint16_t), 1, cInfo->cipher);
				key_poly(cInfo->key, NULL, offset);
				curr_block = 0;
				progress_print(curr_byte, bytes, PROGRESS_STEP);
			}
#ifdef DEBUG
			else if(curr_block == block_length && total_count >=file_size)
			{
				printf("\nDo not change key at end of file\n");
			}
#endif
		}
	}while(count == BUFF_SIZE && !feof(inputfp) && total_count < sz);	
	cInfo->curr_block = curr_block;
	cInfo->block_length = block_length;
}

void key_gen(FILE *key)
{
	int i;
	uint16_t key_array[KEY_SIZE];
	int index1, index2;
	int offset;
	uint16_t hold;


	//Populate Key Array
	for(i = 0; i <KEY_SIZE; i++)
	{
		key_array[i] = i;
	}
	
	//Randomly Shuffle Key Array
	for(i = 0; i <4*KEY_SIZE; i++)
	{
		index1 = rand() % KEY_SIZE;
		offset = (rand() % (KEY_SIZE - 1)) + 1;
		index2 = (index1 + offset) % KEY_SIZE;
		hold = key_array[index1];
		key_array[index1] = key_array[index2];
		key_array[index2] = hold;
	}

	//Write to key file
	fwrite(key_array, sizeof(uint16_t), KEY_SIZE, key);
	return;
}
void key_poly(uint16_t *key, uint16_t *rev_key, uint16_t offset)
{
	uint16_t *hold_block;
	int i;
	
	hold_block = (uint16_t*)malloc(KEY_SIZE*sizeof(uint16_t));
	memcpy(hold_block, &(key[offset]), (KEY_SIZE - offset)*sizeof(uint16_t));
	memcpy(&(hold_block[KEY_SIZE - offset]), key, offset*sizeof(uint16_t));
	memcpy(key, hold_block, KEY_SIZE*sizeof(uint16_t));
	free(hold_block);
	if(rev_key == NULL)
	{
		return;
	}
	for(i = 0; i < KEY_SIZE; i++)
	{
		rev_key[key[i]] = i;
	}
}

void progress_print(unsigned long int current, unsigned long int total, int step)
{
	printf("\r[");
	int i;
	for(i = 0; i < 100; i+=step)
	{
		if(i < 100*current/total)
			printf("#");
		else
			printf(" ");
	}
	printf("]\t%lu/%lu bytes\t%lu%%",curr_byte, bytes, current*100/total);
	fflush(stdout);
}
