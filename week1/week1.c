#include <assert.h>
#include <ctype.h>
#include <iso646.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * how to convert hex to binary:
 * echo "obase=2; ibase=16; 234C" | bc
 */

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static int LINES_COUNT = 11;

void
convert_bytes(const char* bytes_string, unsigned char* bytes);

typedef struct char_weight
{
  unsigned char ch;
  int cnt;
} char_weight;

typedef struct encoded_string
{
  unsigned char* bytes;
  int len;
  char_weight* chars;
} encoded_string;

void
print_encoded_string(encoded_string* str)
{
  for (int i = 0; i < str->len; i++) {
    /* printf("%X ", str->bytes[i]); */
  }
  printf("\n");

  for (int i = 0; i < str->len; i++) {
    char_weight* cw = &(str->chars[i]);
    if (cw->cnt == -1) {
      printf("%c", cw->ch);
    } else if (cw->cnt > 0) {
      printf("%c", cw->ch);
    } else if (cw->ch == ' ') {
      printf("_");
    } else {
      printf("?");
    }
  }
  printf("\n");
}

encoded_string*
create_encoded_string(const char* hexstr)
{
  encoded_string* estr = malloc(sizeof(encoded_string));
  estr->len = strlen(hexstr) / 2 + 1;

  // init encoded bytes
  estr->bytes = malloc(estr->len * sizeof(char));
  convert_bytes(hexstr, estr->bytes);

  // init probabilities
  estr->chars = malloc(estr->len * sizeof(char_weight));
  for (int i = 0; i < estr->len; i++) {
    estr->chars[i] = (struct char_weight){ .ch = '\0', .cnt = 0 };
  }
  return estr;
}

void
dispose_encoded_string(encoded_string* estr)
{
  free(estr->bytes);
  free(estr->chars);
  free(estr);
}

/**
 * bytes_string - string of hex bytes
 * bytes - resulting array
 */
void
convert_bytes(const char* bytes_string, unsigned char* bytes)
{
  char* byte_tmp = malloc(sizeof(char) * 3); // 2 chars + '\0'
  int i;
  for (i = 0; i < strlen(bytes_string) / 2; i++) {
    strncpy(byte_tmp, bytes_string + (i * 2), 2);

    *(bytes + i) = (unsigned char)strtol(byte_tmp, NULL, 16);
  }
  bytes[i] = '\0';
  free(byte_tmp);
}

void
update_prob(char_weight* prob, const unsigned char ch)
{
  /* printf( */
  /*   "old: '%c', new: '%c' | '%d' | '%X'\n", prob->ch, ch, (int)ch, (int)ch);
   */

  // count hits
  prob->cnt += 1;

  if (prob->ch == ' ')
    return;
  else if (prob->ch == '\0')
    prob->ch = ch;
  else if (prob->ch != ch)
    prob->ch = ' ';
}

int
main(int argc, char** argv)
{
  const char* fciphers = "./cyphers.txt";
  const char* fguesses = "./guesses.txt";

  encoded_string** encoded_strings =
    malloc(LINES_COUNT * sizeof(encoded_string*));
  char** guessed_strings = malloc(LINES_COUNT * sizeof(char*));

  FILE* fp;
  size_t line_len = 0;
  ssize_t read;

  fp = fopen(fciphers, "r");

  // read cypher texts
  char* line = NULL;
  for (int i = 0; i < LINES_COUNT; i++) {
    read = getline(&line, &line_len, fp);
    encoded_strings[i] = create_encoded_string(line);
  }
  fclose(fp);
  if (line)
    free(line);

  // read guesses about encoded strings.
  // constructed from previous run
  fp = fopen(fguesses, "r");
  for (int i = 0; i < LINES_COUNT; i++) {
    guessed_strings[i] = NULL;
    read = getline((guessed_strings + i), &line_len, fp);
  }
  fclose(fp);

  // init with guesses
  for (int i = 0; i < LINES_COUNT; i++) {
    char* gstring = guessed_strings[i];
    for (int j = 0; j < strlen(gstring); j++) {
      unsigned char guess = gstring[j];
      if (guess != '?') {
        /* printf("!!! %c\n", guess); */
        encoded_strings[i]->chars[j].ch = guess;
        encoded_strings[i]->chars[j].cnt = -1;
      }
    }
  }

  // probability attack
  unsigned char* first_str;
  unsigned char* second_str;
  for (int i = 0; i < LINES_COUNT; i++) {
    first_str = encoded_strings[i]->bytes;

    for (int j = i + 1; j < LINES_COUNT; j++) {
      printf("%d vs %d.\n", i, j);
      second_str = encoded_strings[j]->bytes;

      int count2xor = MIN(encoded_strings[i]->len, encoded_strings[j]->len);

      for (int z = 0; z < count2xor; z++) {
        unsigned char xored = first_str[z] xor second_str[z] xor ' ';
        if (isalpha(xored)) {
          printf("%d (%X | %X): probably %c\n",
                 z,
                 first_str[z],
                 second_str[z],
                 xored);

          // process guesses
          encoded_string* istring = encoded_strings[i];
          encoded_string* jstring = encoded_strings[j];

          if (istring->chars[z].cnt == -1) {
            if (jstring->chars[z].cnt != -1) {
              xored = istring->chars[z].ch ^ first_str[z] ^ second_str[z];
              jstring->chars[z].ch = xored;
              jstring->chars[z].cnt = -1;
            }
          } else if (jstring->chars[z].cnt == -1) {
            if (istring->chars[z].cnt != -1) {
              xored = istring->chars[z].ch ^ first_str[z] ^ second_str[z];
              xored = jstring->chars[z].ch ^ first_str[z] ^ second_str[z];
              istring->chars[z].ch = xored;
              istring->chars[z].cnt = -1;
            }
          } else {
            update_prob(&(encoded_strings[i]->chars[z]), xored);
            update_prob(&(encoded_strings[j]->chars[z]), xored);
          }
        }
      }
    }
  }

  for (int i = 0; i < LINES_COUNT; i++) {
    print_encoded_string(encoded_strings[i]);
  }

  for (int i = 0; i < LINES_COUNT; i++) {
    dispose_encoded_string(encoded_strings[i]);
  }
  free(encoded_strings);

  for (int i = 0; i < LINES_COUNT; i++)
    free(guessed_strings[i]);
  free(guessed_strings);
}
