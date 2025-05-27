import sys


if len(sys.argv) < 2:
    print("Usage: python script_name.py <N>")
    sys.exit(1)

try:
    N = int(sys.argv[1])
    if N <= 0:
        raise ValueError
except ValueError:
    print("Error: N must be a positive integer.")
    sys.exit(1)


with open("test1.txt", 'w') as file:
    file.write("Hello world Pleasure to meet you world BYE!")


with open("test1.txt", 'r') as file:
    content2 = file.read().split()


word_count = {}
for word in content2:
    word_count[word] = word_count.get(word, 0) + 1


sorted_word_count = sorted(word_count.items(), key=lambda x: x[1], reverse=True)


print(f"The top {N} words are:")
for word, count in sorted_word_count[:N]:
    print(f"{word}: {count}")